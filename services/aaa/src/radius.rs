//! RADIUS 서버 (RFC 2865/2866 기반 UDP 1812/1813).
//! NAC 연동: MAC 주소 기반 인증(MAB) + VLAN 할당 응답

use anyhow::Result;
use nac_store::{audit::AuditRepo, endpoint::EndpointRepo};
use sqlx::PgPool;
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
pub const ATTR_CALLING_STATION_ID: u8 = 31; // MAC 주소 (스위치가 전달)
pub const ATTR_EAP_MESSAGE: u8 = 79;
// VLAN 할당용 Tunnel 속성 (RFC 2868)
pub const ATTR_TUNNEL_TYPE: u8 = 64; // 13 = VLAN
pub const ATTR_TUNNEL_MEDIUM_TYPE: u8 = 65; // 6 = 802
pub const ATTR_TUNNEL_PRIVATE_GROUP_ID: u8 = 81; // VLAN ID 문자열

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

    /// RFC 2865 §3: Response Authenticator 계산
    /// MD5(Code + ID + Length + RequestAuth + Attributes + Secret)
    pub fn encode_with_response_auth(&self, request_auth: &[u8; 16], secret: &[u8]) -> Vec<u8> {
        let mut buf = self.encode();
        // 응답 패킷의 authenticator 자리를 임시로 request_auth로 채운 상태에서 MD5 계산
        buf[4..20].copy_from_slice(request_auth);
        let mut input = buf.clone();
        input.extend_from_slice(secret);
        let hash = md5::compute(&input);
        buf[4..20].copy_from_slice(&hash.0);
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
    while result.last() == Some(&0) {
        result.pop();
    }
    result
}

/// MAC 주소 정규화: 구분자를 모두 제거하고 소문자로 변환 후 xx:xx:xx:xx:xx:xx 형식으로
fn normalize_mac(raw: &str) -> Option<String> {
    let hex: String = raw
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_lowercase();
    if hex.len() == 12 {
        Some(format!(
            "{}:{}:{}:{}:{}:{}",
            &hex[0..2],
            &hex[2..4],
            &hex[4..6],
            &hex[6..8],
            &hex[8..10],
            &hex[10..12]
        ))
    } else {
        None
    }
}

/// VLAN Tunnel 속성 생성 (RFC 2868)
fn vlan_attributes(vlan_id: u16) -> Vec<RadiusAttribute> {
    // Tunnel-Type = 13 (VLAN), Tag=0x00
    let mut tunnel_type = vec![0x00u8]; // tag
    tunnel_type.extend_from_slice(&13u32.to_be_bytes());

    // Tunnel-Medium-Type = 6 (802), Tag=0x00
    let mut medium_type = vec![0x00u8];
    medium_type.extend_from_slice(&6u32.to_be_bytes());

    // Tunnel-Private-Group-ID = VLAN ID as string, Tag=0x00
    let mut group_id = vec![0x00u8];
    group_id.extend_from_slice(vlan_id.to_string().as_bytes());

    vec![
        RadiusAttribute {
            attr_type: ATTR_TUNNEL_TYPE,
            value: tunnel_type,
        },
        RadiusAttribute {
            attr_type: ATTR_TUNNEL_MEDIUM_TYPE,
            value: medium_type,
        },
        RadiusAttribute {
            attr_type: ATTR_TUNNEL_PRIVATE_GROUP_ID,
            value: group_id,
        },
    ]
}

/// RADIUS 인증 처리: DB에서 MAC 조회 후 정책 결정
async fn handle_access_request(
    pkt: &RadiusPacket,
    secret: &[u8],
    pool: &PgPool,
    nats: &async_nats::Client,
) -> RadiusPacket {
    let repo = EndpointRepo::new(pool);
    let audit = AuditRepo::new(pool);

    // 1. MAC 추출: Calling-Station-Id 우선, 없으면 User-Name (MAB)
    let mac_raw = pkt
        .get_attr(ATTR_CALLING_STATION_ID)
        .and_then(|b| std::str::from_utf8(b).ok())
        .or_else(|| {
            pkt.get_attr(ATTR_USER_NAME)
                .and_then(|b| std::str::from_utf8(b).ok())
        })
        .unwrap_or("");

    let mac = match normalize_mac(mac_raw) {
        Some(m) => m,
        None => {
            // PAP 사용자명/비밀번호 인증 (관리 계정용 폴백)
            let username = pkt
                .get_attr(ATTR_USER_NAME)
                .and_then(|b| std::str::from_utf8(b).ok())
                .unwrap_or("");
            let authenticated = if let Some(enc_pw) = pkt.get_attr(ATTR_USER_PASSWORD) {
                let pw = decrypt_pap_password(enc_pw, secret, &pkt.authenticator);
                let admin_pass =
                    std::env::var("RADIUS_ADMIN_PASS").unwrap_or_else(|_| "changeme".into());
                let admin_user =
                    std::env::var("RADIUS_ADMIN_USER").unwrap_or_else(|_| "admin".into());
                let pw_str = String::from_utf8_lossy(&pw);
                username == admin_user && pw_str == admin_pass
            } else {
                false
            };
            warn!(username, mac_raw, "non-MAC RADIUS request — PAP fallback");
            return build_response(pkt, authenticated, None, "PAP authentication");
        }
    };

    // 2. DB에서 단말 조회
    let endpoint = match repo.find_by_mac(&mac).await {
        Ok(Some(ep)) => ep,
        Ok(None) => {
            // 미등록 단말: 거부 (격리 VLAN으로 보낼 수도 있음)
            let quarantine_vlan: Option<u16> = std::env::var("RADIUS_UNKNOWN_VLAN")
                .ok()
                .and_then(|v| v.parse().ok());
            info!(mac, "unknown endpoint — rejecting");
            let _ = audit
                .log(
                    "radius_unknown_endpoint",
                    None,
                    "radius",
                    serde_json::json!({ "mac": mac }),
                )
                .await;
            return build_response(pkt, false, quarantine_vlan, "Unknown endpoint");
        }
        Err(e) => {
            warn!(error = %e, mac, "DB error looking up endpoint");
            return build_response(pkt, false, None, "Internal error");
        }
    };

    // 3. 상태 기반 결정
    let (accept, vlan, msg) = match endpoint.status.as_str() {
        "allowed" => {
            // 허용 VLAN (기본값 없음 = 스위치의 기본 VLAN 사용)
            let vlan: Option<u16> = std::env::var("RADIUS_ALLOW_VLAN")
                .ok()
                .and_then(|v| v.parse().ok());
            (true, vlan, "Access granted")
        }
        "quarantined" => {
            // 격리 VLAN으로 수용
            let vlan: u16 = std::env::var("RADIUS_QUARANTINE_VLAN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(99);
            (true, Some(vlan), "Quarantine VLAN assigned")
        }
        _ => (false, None, "Access denied"),
    };

    info!(
        mac,
        status = endpoint.status,
        accept,
        vlan,
        "RADIUS authentication result"
    );

    // 4. 감사 로그
    let _ = audit
        .log(
            if accept {
                "radius_auth_success"
            } else {
                "radius_auth_failure"
            },
            Some(endpoint.id),
            "radius",
            serde_json::json!({
                "mac": mac,
                "status": endpoint.status,
                "vlan": vlan,
                "accept": accept,
            }),
        )
        .await;

    // 5. NATS 이벤트 발행
    let event = serde_json::json!({
        "mac_address": mac,
        "endpoint_id": endpoint.id,
        "success": accept,
        "vlan": vlan,
    });
    if let Ok(payload) = serde_json::to_vec(&event) {
        nats.publish("nac.events.radius.auth", payload.into())
            .await
            .ok();
    }

    build_response(pkt, accept, vlan, msg)
}

fn build_response(
    req: &RadiusPacket,
    accept: bool,
    vlan: Option<u16>,
    message: &str,
) -> RadiusPacket {
    let code = if accept {
        CODE_ACCESS_ACCEPT
    } else {
        CODE_ACCESS_REJECT
    };

    let mut attributes = vec![RadiusAttribute {
        attr_type: ATTR_REPLY_MESSAGE,
        value: message.as_bytes().to_vec(),
    }];

    if accept {
        if let Some(v) = vlan {
            attributes.extend(vlan_attributes(v));
        }
    }

    RadiusPacket {
        code,
        identifier: req.identifier,
        authenticator: req.authenticator,
        attributes,
    }
}

/// UDP 1812/1813 리스너 실행
pub async fn run_radius_server(
    auth_addr: &str,
    acct_addr: &str,
    secret: Vec<u8>,
    pool: PgPool,
    nats: async_nats::Client,
) -> Result<()> {
    let auth_socket = UdpSocket::bind(auth_addr).await?;
    let acct_socket = UdpSocket::bind(acct_addr).await?;
    info!(auth_addr, acct_addr, "RADIUS server listening");

    let secret = std::sync::Arc::new(secret);
    let pool = std::sync::Arc::new(pool);
    let nats = std::sync::Arc::new(nats);

    let auth_secret = secret.clone();
    let auth_pool = pool.clone();
    let auth_nats = nats.clone();
    let auth_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match auth_socket.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    handle_auth_packet(
                        &auth_socket,
                        &buf[..n],
                        peer,
                        &auth_secret,
                        &auth_pool,
                        &auth_nats,
                    )
                    .await;
                }
                Err(e) => warn!(error = %e, "RADIUS auth recv error"),
            }
        }
    });

    let acct_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match acct_socket.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    handle_acct_packet(&acct_socket, &buf[..n], peer).await;
                }
                Err(e) => warn!(error = %e, "RADIUS acct recv error"),
            }
        }
    });

    tokio::try_join!(auth_task, acct_task)?;
    Ok(())
}

async fn handle_auth_packet(
    socket: &UdpSocket,
    buf: &[u8],
    peer: SocketAddr,
    secret: &[u8],
    pool: &PgPool,
    nats: &async_nats::Client,
) {
    let pkt = match RadiusPacket::parse(buf) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, peer = %peer, "RADIUS parse error");
            return;
        }
    };

    debug!(peer = %peer, code = pkt.code, id = pkt.identifier, "RADIUS auth packet");

    if pkt.code != CODE_ACCESS_REQUEST {
        warn!(code = pkt.code, "unexpected RADIUS code on auth port");
        return;
    }

    let request_auth = pkt.authenticator;
    let response = handle_access_request(&pkt, secret, pool, nats).await;
    let encoded = response.encode_with_response_auth(&request_auth, secret);

    if let Err(e) = socket.send_to(&encoded, peer).await {
        warn!(error = %e, "RADIUS auth send error");
    }
}

async fn handle_acct_packet(socket: &UdpSocket, buf: &[u8], peer: SocketAddr) {
    let pkt = match RadiusPacket::parse(buf) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, peer = %peer, "RADIUS acct parse error");
            return;
        }
    };

    debug!(peer = %peer, code = pkt.code, id = pkt.identifier, "RADIUS acct packet");

    if pkt.code == CODE_ACCOUNTING_REQUEST {
        let username = pkt
            .get_attr(ATTR_USER_NAME)
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("<unknown>");
        info!(username, "RADIUS accounting request received");

        let response = RadiusPacket {
            code: CODE_ACCOUNTING_RESPONSE,
            identifier: pkt.identifier,
            authenticator: pkt.authenticator,
            attributes: vec![],
        };
        if let Err(e) = socket.send_to(&response.encode(), peer).await {
            warn!(error = %e, "RADIUS acct send error");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_normalize_mac() {
        assert_eq!(
            normalize_mac("AA-BB-CC-DD-EE-FF"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(
            normalize_mac("aabbccddeeff"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(
            normalize_mac("AA:BB:CC:DD:EE:FF"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(normalize_mac("invalid"), None);
    }

    #[test]
    fn test_vlan_attributes() {
        let attrs = vlan_attributes(100);
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0].attr_type, ATTR_TUNNEL_TYPE);
        assert_eq!(attrs[1].attr_type, ATTR_TUNNEL_MEDIUM_TYPE);
        assert_eq!(attrs[2].attr_type, ATTR_TUNNEL_PRIVATE_GROUP_ID);
    }

    #[test]
    fn test_packet_too_short() {
        assert!(RadiusPacket::parse(&[0u8; 5]).is_err());
    }

    #[test]
    fn test_response_auth_included() {
        let pkt = make_access_request("test");
        let secret = b"sharedsecret";
        let request_auth = [1u8; 16];
        let encoded = pkt.encode_with_response_auth(&request_auth, secret);
        // Response Authenticator (bytes 4..20) should not be all zeros
        let auth: &[u8] = &encoded[4..20];
        assert_ne!(auth, &[0u8; 16]);
    }
}
