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
