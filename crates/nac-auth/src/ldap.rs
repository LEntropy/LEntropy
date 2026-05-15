use anyhow::Result;

pub struct LdapClient {
    url: String,
    bind_dn: String,
    bind_pw: String,
}

impl LdapClient {
    pub fn new(url: impl Into<String>, bind_dn: impl Into<String>, bind_pw: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            bind_dn: bind_dn.into(),
            bind_pw: bind_pw.into(),
        }
    }

    pub async fn authenticate(&self, username: &str, password: &str) -> Result<bool> {
        let _ = (username, password, &self.url, &self.bind_dn, &self.bind_pw);
        Ok(false)
    }
}
