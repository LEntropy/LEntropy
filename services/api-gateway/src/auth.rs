//! JWT 인증 미들웨어.

use anyhow::Result;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::AppState;

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: u64,
}

pub fn create_token(secret: &[u8], username: &str) -> Result<String> {
    let exp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 86400; // 24시간

    let header = base64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims_json = serde_json::to_vec(&Claims {
        sub: username.to_string(),
        exp,
    })?;
    let payload = base64url_encode(&claims_json);
    let message = format!("{header}.{payload}");

    let sig = hmac_sha256(secret, message.as_bytes());
    let signature = base64url_encode(&sig);

    Ok(format!("{message}.{signature}"))
}

pub fn verify_token(secret: &[u8], token: &str) -> Result<String> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        anyhow::bail!("invalid token format");
    }

    let message = format!("{}.{}", parts[0], parts[1]);
    let expected_sig = hmac_sha256(secret, message.as_bytes());
    let provided_sig = base64url_decode(parts[2])?;

    if expected_sig != provided_sig {
        anyhow::bail!("invalid token signature");
    }

    let claims_bytes = base64url_decode(parts[1])?;
    let claims: Claims = serde_json::from_slice(&claims_bytes)?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if claims.exp < now {
        anyhow::bail!("token expired");
    }

    Ok(claims.sub)
}

pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    verify_token(&state.jwt_secret, token).map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(next.run(req).await)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    // 단순 HMAC-SHA256 구현 (프로덕션에서는 ring/hmac 사용 권장)
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // 경고: 이 구현은 실제 HMAC-SHA256이 아닌 데모용입니다.
    // 프로덕션에서는 jsonwebtoken 크레이트를 사용하세요.
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    data.hash(&mut hasher);
    let h = hasher.finish();
    h.to_le_bytes().repeat(4)
}

fn base64url_encode(input: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let b64_chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        write!(s, "{}", b64_chars[((n >> 18) & 63) as usize] as char).unwrap();
        write!(s, "{}", b64_chars[((n >> 12) & 63) as usize] as char).unwrap();
        if chunk.len() > 1 {
            write!(s, "{}", b64_chars[((n >> 6) & 63) as usize] as char).unwrap();
        } else {
            s.push('=');
        }
        if chunk.len() > 2 {
            write!(s, "{}", b64_chars[(n & 63) as usize] as char).unwrap();
        } else {
            s.push('=');
        }
    }
    s.replace('+', "-").replace('/', "_").replace('=', "")
}

fn base64url_decode(input: &str) -> Result<Vec<u8>> {
    let padded = match input.len() % 4 {
        2 => format!("{input}=="),
        3 => format!("{input}="),
        _ => input.to_string(),
    };
    let standard = padded.replace('-', "+").replace('_', "/");
    // 간단한 base64 디코딩
    let mut result = Vec::new();
    let chars: Vec<u8> = standard.bytes().collect();
    for chunk in chars.chunks(4) {
        if chunk.len() < 4 {
            break;
        }
        let decode = |c: u8| -> u8 {
            match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => 0,
            }
        };
        let b0 = decode(chunk[0]);
        let b1 = decode(chunk[1]);
        let b2 = decode(chunk[2]);
        let b3 = decode(chunk[3]);
        result.push((b0 << 2) | (b1 >> 4));
        if chunk[2] != b'=' {
            result.push((b1 << 4) | (b2 >> 2));
        }
        if chunk[3] != b'=' {
            result.push((b2 << 6) | b3);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_roundtrip() {
        let secret = b"test-secret-key-min-32-characters";
        let token = create_token(secret, "admin").unwrap();
        let sub = verify_token(secret, &token).unwrap();
        assert_eq!(sub, "admin");
    }

    #[test]
    fn test_invalid_token_rejected() {
        let secret = b"test-secret-key-min-32-characters";
        assert!(verify_token(secret, "invalid.token.here").is_err());
    }

    #[test]
    fn test_wrong_secret_rejected() {
        let secret1 = b"secret-one-min-32-characters-xxx";
        let secret2 = b"secret-two-min-32-characters-xxx";
        let token = create_token(secret1, "admin").unwrap();
        assert!(verify_token(secret2, &token).is_err());
    }
}
