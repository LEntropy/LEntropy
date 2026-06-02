use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub database_url: String,
    pub redis_url: String,
    pub nats_url: String,
    pub listen_addr: String,

    // LDAP (Phase 3)
    pub ldap_url: Option<String>,
    pub ldap_bind_dn: Option<String>,
    pub ldap_bind_pw: Option<String>,
    pub ldap_user_base: Option<String>,
    pub ldap_user_filter: Option<String>,

    // JWT
    pub jwt_secret: Option<String>,

    // Captive Portal
    pub captive_portal_addr: Option<String>,

    // RADIUS
    pub radius_secret: Option<String>,
    pub radius_auth_addr: Option<String>,
    pub radius_acct_addr: Option<String>,

    // Management access: comma-separated IPs allowed to SSH into the Pi.
    // If unset, SSH is open to all (dev mode). Example: "192.168.0.100,1.2.3.4"
    pub management_ips: Option<String>,
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let cfg = config::Config::builder()
            .add_source(config::Environment::default().separator("__"))
            .build()?;
        Ok(cfg.try_deserialize()?)
    }
}
