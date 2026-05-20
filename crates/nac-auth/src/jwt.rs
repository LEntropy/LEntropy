use anyhow::Result;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

use crate::NacClaims;

/// JWT 서명 (HS256)
pub fn sign_token(claims: &NacClaims, secret: &[u8]) -> Result<String> {
    let header = Header::new(Algorithm::HS256);
    let token = encode(&header, claims, &EncodingKey::from_secret(secret))?;
    Ok(token)
}

/// JWT 검증 및 클레임 추출
pub fn verify_token(token: &str, secret: &[u8]) -> Result<NacClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let data = decode::<NacClaims>(token, &DecodingKey::from_secret(secret), &validation)?;
    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NacClaims;

    fn make_claims(sub: &str, exp_offset: i64) -> NacClaims {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        NacClaims {
            sub: sub.to_string(),
            groups: vec!["corp-users".to_string()],
            exp: now + exp_offset,
            iat: now,
        }
    }

    #[test]
    fn test_sign_and_verify() {
        let secret = b"test-secret-key-32-chars-minimum!";
        let claims = make_claims("alice", 3600);
        let token = sign_token(&claims, secret).unwrap();
        assert!(!token.is_empty());
        let decoded = verify_token(&token, secret).unwrap();
        assert_eq!(decoded.sub, "alice");
        assert_eq!(decoded.groups, vec!["corp-users"]);
    }

    #[test]
    fn test_wrong_secret_fails() {
        let secret = b"correct-secret-key-32-chars-min!!";
        let wrong = b"wrong-secret-key-32-chars-minimum";
        let claims = make_claims("bob", 3600);
        let token = sign_token(&claims, secret).unwrap();
        assert!(verify_token(&token, wrong).is_err());
    }

    #[test]
    fn test_expired_token_fails() {
        let secret = b"test-secret-key-32-chars-minimum!";
        // jsonwebtoken v9 has a default leeway of 60s, so use -120s to be safe
        let claims = make_claims("charlie", -120); // expired 120s ago
        let token = sign_token(&claims, secret).unwrap();
        assert!(verify_token(&token, secret).is_err());
    }
}
