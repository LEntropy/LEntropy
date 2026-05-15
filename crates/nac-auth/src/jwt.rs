use anyhow::Result;

pub fn sign_token(subject: &str, secret: &[u8]) -> Result<String> {
    let _ = (subject, secret);
    Ok(String::new())
}

pub fn verify_token(token: &str, secret: &[u8]) -> Result<String> {
    let _ = (token, secret);
    Ok(String::new())
}
