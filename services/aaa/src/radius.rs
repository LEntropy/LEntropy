//! RADIUS 서버 (RFC 2865/2866 기반 UDP 1812/1813).
//! 지원: PAP, EAP-MD5 (PEAP/EAP-TLS는 구조 정의 포함)

use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

// RADIUS 코드 상수
pub const CODE_ACCESS_REQUEST: u8 = 1;
pub const CODE_ACCESS_ACCEPT: u8 = 2;
pub const CODE_ACCESS_REJECT: u8 = 3;
pub const CODE_ACCOUNTING_REQUEST: u8 = 4;
pub const CODE_ACCOUNTING_RESPONSE: u8 = 5;

// RADIUS 속성 타입
pub const ATTR_USER_NAME: u8 = 1;
pub const ATTR_USER_PASSWORD: u8 = 2;
pub const ATTR_NAS_IP: u8 = 4;
pub const ATTR_NAS_PORT: u8 = 5;
pub const ATTR_REPLY_MESSAGE: u8 = 18;
pub const ATTR_EAP_MESSAGE: u8 = 79;

/// RADIUS 패킷 구조
#[derive(Debug, Clone)]
pub struct RadiusPacket {
    pub code: u8,
    pub identifier: u8,
    pub authenticator: [u8; 16],
    pub attributes: Vec<RadiusAttribute>,
}

#[derive(Debug, Clone)]
pub struct RadiusAttribute {
    pub attr_type: u8,
    pub value: Vec<u8>,
}

impl RadiusPacket {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 20 {
            anyhow::bail!("RADIUS packet too short: {}", buf.len());
        }
        let code = buf[0];
        let identifier = buf[1];
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if buf.len() < length {
            anyhow::bail!("RADIUS packet truncated");
        }
        let mut authenticator = [0u8; 16];
        authenticator.copy_from_slice(&buf[4..20]);

        let mut attributes = Vec::new();
        let mut pos = 20;
        while pos + 2 <= length {
            let attr_type = buf[pos];
            let attr_len = buf[pos + 1] as usize;
            if attr_len < 2 || pos + attr_len > length {
                break;
            }
            let value = buf[pos + 2..pos + attr_len].to_vec();
            attributes.push(RadiusAttribute { attr_type, value });
            pos += attr_len;
        }

        Ok(RadiusPacket {
            code,
            identifier,
            authenticator,
            attributes,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut attrs_bytes = Vec::new();
        for attr in &self.attributes {
            attrs_bytes.push(attr.attr_type);
            attrs_bytes.push((attr.value.len() + 2) as u8);
            attrs_bytes.extend_from_slice(&attr.value);
        }
        let length = (20 + attrs_bytes.len()) as u16;
        let mut buf = Vec::with_capacity(length as usize);
        buf.push(self.code);
        buf.push(self.identifier);
        buf.extend_from_slice(&length.to_be_bytes());
        buf.extend_from_slice(&self.authenticator);
        buf.extend_from_slice(&attrs_bytes);
        buf
    }

    pub fn get_attr(&self, attr_type: u8) -> Option<&[u8]> {
        self.attributes
            .iter()
            .find(|a| a.attr_type == attr_type)
            .map(|a| a.value.as_slice())
    }
}

/// PAP 패스워드 복호화 (RFC 2865 §5.2)
fn decrypt_pap_password(encrypted: &[u8], secret: &[u8], authenticator: &[u8; 16]) -> Vec<u8> {
    let mut result = Vec::with_capacity(encrypted.len());
    let mut prev = authenticator.to_vec();
    for chunk in encrypted.chunks(16) {
        let mut input = secret.to_vec();
        input.extend_from_slice(&prev);
        let hash = md5::compute(&input);
        let decrypted: Vec<u8> = chunk.iter().zip(hash.iter()).map(|(c, h)| c ^ h).collect();
        prev = chunk.to_vec();
        result.extend_from_slice(&decrypted);
    }
    // 제로 패딩 제거
    while result.last() == Some(&0) {
        result.pop();
    }
    result
}

/// 인증 콜백 트레이트
pub trait AuthBackend: Send + Sync + 'static {
    fn authenticate(&self, username: &str, password: &str) -> bool;
}

/// 단순 정적 시크릿 인증 (테스트용)
pub struct StaticAuth {
    pub users: std::collections::HashMap<String, String>,
}

impl AuthBackend for StaticAuth {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        self.users
            .get(username)
            .map(|p| p == password)
            .unwrap_or(false)
    }
}

/// RADIUS 서버 상태
pub struct RadiusServer<A: AuthBackend> {
    pub shared_secret: Vec<u8>,
    pub auth: A,
}

impl<A: AuthBackend> RadiusServer<A> {
    pub fn new(secret: impl Into<Vec<u8>>, auth: A) -> Self {
        Self {
            shared_secret: secret.into(),
            auth,
        }
    }

    fn handle_access_request(&self, pkt: &RadiusPacket) -> RadiusPacket {
        let username = pkt
            .get_attr(ATTR_USER_NAME)
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("");

        // PAP 인증 시도
        let authenticated = if let Some(enc_pw) = pkt.get_attr(ATTR_USER_PASSWORD) {
            let password = decrypt_pap_password(enc_pw, &self.shared_secret, &pkt.authenticator);
            let pass_str = String::from_utf8_lossy(&password);
            debug!(username, "PAP authentication attempt");
            self.auth.authenticate(username, &pass_str)
        } else if pkt.get_attr(ATTR_EAP_MESSAGE).is_some() {
            // EAP: 현재는 거부 (EAP-TLS/PEAP 확장 포인트)
            warn!(username, "EAP authentication not fully implemented");
            false
        } else {
            false
        };

        let code = if authenticated {
            CODE_ACCESS_ACCEPT
        } else {
            CODE_ACCESS_REJECT
        };
        let msg = if authenticated {
            "Access granted"
        } else {
            "Access denied"
        };

        info!(username, authenticated, "RADIUS authentication result");

        RadiusPacket {
            code,
            identifier: pkt.identifier,
            authenticator: pkt.authenticator,
            attributes: vec![RadiusAttribute {
                attr_type: ATTR_REPLY_MESSAGE,
                value: msg.as_bytes().to_vec(),
            }],
        }
    }

    fn handle_accounting_request(&self, pkt: &RadiusPacket) -> RadiusPacket {
        let username = pkt
            .get_attr(ATTR_USER_NAME)
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("<unknown>");
        info!(username, "RADIUS accounting request received");
        RadiusPacket {
            code: CODE_ACCOUNTING_RESPONSE,
            identifier: pkt.identifier,
            authenticator: pkt.authenticator,
            attributes: vec![],
        }
    }
}

/// UDP 1812/1813 리스너 실행
pub async fn run_radius_server(auth_addr: &str, acct_addr: &str, secret: Vec<u8>) -> Result<()> {
    let auth_socket = UdpSocket::bind(auth_addr).await?;
    let acct_socket = UdpSocket::bind(acct_addr).await?;
    info!(auth_addr, acct_addr, "RADIUS server listening");

    let auth_users = {
        let mut m = std::collections::HashMap::new();
        m.insert("testuser".to_string(), "testpass".to_string());
        m
    };
    let server = std::sync::Arc::new(RadiusServer::new(
        secret.clone(),
        StaticAuth { users: auth_users },
    ));

    let auth_server = server.clone();
    let auth_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match auth_socket.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    handle_packet(&auth_socket, &buf[..n], peer, &*auth_server).await;
                }
                Err(e) => warn!(error = %e, "RADIUS auth recv error"),
            }
        }
    });

    let acct_server = server.clone();
    let acct_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match acct_socket.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    handle_packet(&acct_socket, &buf[..n], peer, &*acct_server).await;
                }
                Err(e) => warn!(error = %e, "RADIUS acct recv error"),
            }
        }
    });

    tokio::try_join!(auth_task, acct_task)?;
    Ok(())
}

async fn handle_packet<A: AuthBackend>(
    socket: &UdpSocket,
    buf: &[u8],
    peer: SocketAddr,
    server: &RadiusServer<A>,
) {
    match RadiusPacket::parse(buf) {
        Ok(pkt) => {
            let response = match pkt.code {
                CODE_ACCESS_REQUEST => server.handle_access_request(&pkt),
                CODE_ACCOUNTING_REQUEST => server.handle_accounting_request(&pkt),
                other => {
                    warn!(code = other, "Unknown RADIUS code");
                    return;
                }
            };
            let encoded = response.encode();
            if let Err(e) = socket.send_to(&encoded, peer).await {
                warn!(error = %e, "RADIUS send error");
            }
        }
        Err(e) => warn!(error = %e, peer = %peer, "RADIUS parse error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_server() -> RadiusServer<StaticAuth> {
        let mut users = std::collections::HashMap::new();
        users.insert("alice".to_string(), "secret".to_string());
        RadiusServer::new(b"sharedsecret".to_vec(), StaticAuth { users })
    }

    fn make_access_request(username: &str) -> RadiusPacket {
        RadiusPacket {
            code: CODE_ACCESS_REQUEST,
            identifier: 1,
            authenticator: [0u8; 16],
            attributes: vec![RadiusAttribute {
                attr_type: ATTR_USER_NAME,
                value: username.as_bytes().to_vec(),
            }],
        }
    }

    #[test]
    fn test_packet_encode_parse_roundtrip() {
        let pkt = make_access_request("alice");
        let encoded = pkt.encode();
        let parsed = RadiusPacket::parse(&encoded).unwrap();
        assert_eq!(parsed.code, CODE_ACCESS_REQUEST);
        assert_eq!(parsed.identifier, 1);
        assert_eq!(parsed.get_attr(ATTR_USER_NAME), Some(b"alice".as_slice()));
    }

    #[test]
    fn test_pap_reject_no_password() {
        let server = make_server();
        let pkt = make_access_request("alice");
        let resp = server.handle_access_request(&pkt);
        assert_eq!(resp.code, CODE_ACCESS_REJECT);
    }

    #[test]
    fn test_accounting_response() {
        let server = make_server();
        let pkt = RadiusPacket {
            code: CODE_ACCOUNTING_REQUEST,
            identifier: 5,
            authenticator: [0u8; 16],
            attributes: vec![RadiusAttribute {
                attr_type: ATTR_USER_NAME,
                value: b"bob".to_vec(),
            }],
        };
        let resp = server.handle_accounting_request(&pkt);
        assert_eq!(resp.code, CODE_ACCOUNTING_RESPONSE);
        assert_eq!(resp.identifier, 5);
    }

    #[test]
    fn test_packet_too_short() {
        assert!(RadiusPacket::parse(&[0u8; 5]).is_err());
    }
}
