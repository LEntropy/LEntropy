use anyhow::{bail, Result};
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

use crate::{AuthError, UserIdentity};

pub struct LdapClient {
    url: String,
    bind_dn: String,
    bind_pw: String,
    user_base: String,
    user_filter: String,
}

impl LdapClient {
    /// `user_filter`에는 `{}` 플레이스홀더 사용 (username으로 치환됨)
    pub fn new(
        url: impl Into<String>,
        bind_dn: impl Into<String>,
        bind_pw: impl Into<String>,
        user_base: impl Into<String>,
        user_filter: impl Into<String>,
    ) -> Self {
        Self {
            url: url.into(),
            bind_dn: bind_dn.into(),
            bind_pw: bind_pw.into(),
            user_base: user_base.into(),
            user_filter: user_filter.into(),
        }
    }

    /// 사용자 인증 + 그룹 조회
    ///
    /// 1. service account로 bind
    /// 2. username으로 user DN 검색
    /// 3. user DN + password로 bind (인증)
    /// 4. memberOf 속성에서 그룹 추출
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<UserIdentity> {
        if password.is_empty() {
            bail!(AuthError::InvalidCredentials);
        }

        let settings = LdapConnSettings::new();
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.url)
            .await
            .map_err(|e| anyhow::anyhow!(AuthError::Ldap(format!("connect failed: {e}"))))?;

        // Drive the connection in the background
        ldap3::drive!(conn);

        // 1. Service account bind
        ldap.simple_bind(&self.bind_dn, &self.bind_pw)
            .await
            .map_err(|e| anyhow::anyhow!(AuthError::Ldap(format!("service bind failed: {e}"))))?
            .success()
            .map_err(|e| anyhow::anyhow!(AuthError::Ldap(format!("service bind error: {e}"))))?;

        // 2. Search for user DN
        let filter = self.user_filter.replace("{}", username);
        let attrs = vec!["dn", "cn", "displayName", "mail", "memberOf"];
        let (entries, _res) = ldap
            .search(&self.user_base, Scope::Subtree, &filter, attrs)
            .await
            .map_err(|e| anyhow::anyhow!(AuthError::Ldap(format!("search failed: {e}"))))?
            .success()
            .map_err(|_| anyhow::anyhow!(AuthError::UserNotFound(username.to_string())))?;

        let entry = entries
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!(AuthError::UserNotFound(username.to_string())))?;

        let search_entry = SearchEntry::construct(entry);
        let user_dn = search_entry.dn.clone();

        // 3. Re-bind as the user to verify password
        ldap.simple_bind(&user_dn, password)
            .await
            .map_err(|e| anyhow::anyhow!(AuthError::Ldap(format!("user bind failed: {e}"))))?
            .success()
            .map_err(|_| anyhow::anyhow!(AuthError::InvalidCredentials))?;

        // 4. Extract attributes
        let display_name = search_entry
            .attrs
            .get("displayName")
            .and_then(|v| v.first())
            .cloned()
            .or_else(|| {
                search_entry
                    .attrs
                    .get("cn")
                    .and_then(|v| v.first())
                    .cloned()
            });

        let email = search_entry
            .attrs
            .get("mail")
            .and_then(|v| v.first())
            .cloned();

        let groups = search_entry
            .attrs
            .get("memberOf")
            .map(|dns| dns.iter().map(|dn| Self::extract_cn_from_dn(dn)).collect())
            .unwrap_or_default();

        ldap.unbind().await.ok();

        Ok(UserIdentity {
            username: username.to_string(),
            display_name,
            email,
            groups,
        })
    }

    /// "CN=group1,OU=Groups,DC=corp,DC=local" → "group1"
    fn extract_cn_from_dn(dn: &str) -> String {
        dn.split(',')
            .next()
            .and_then(|part| {
                let part = part.trim();
                if part.to_uppercase().starts_with("CN=") {
                    Some(part[3..].to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| dn.to_string())
    }
}
