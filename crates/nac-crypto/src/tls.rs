use anyhow::Result;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, ServerConfig};
use std::sync::Arc;

pub fn build_server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<ServerConfig>> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem))?
        .ok_or_else(|| anyhow::anyhow!("no private key found"))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(config))
}

pub fn build_client_config(ca_pem: &[u8]) -> Result<Arc<ClientConfig>> {
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(ca_pem)) {
        root_store.add(cert?)?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}
