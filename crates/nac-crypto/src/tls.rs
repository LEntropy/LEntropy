use anyhow::Result;
use rustls::{ClientConfig, ServerConfig};
use std::sync::Arc;

pub fn build_server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<ServerConfig>> {
    let _ = (cert_pem, key_pem);
    anyhow::bail!("TLS server config not yet implemented")
}

pub fn build_client_config(ca_pem: &[u8]) -> Result<Arc<ClientConfig>> {
    let _ = ca_pem;
    anyhow::bail!("TLS client config not yet implemented")
}
