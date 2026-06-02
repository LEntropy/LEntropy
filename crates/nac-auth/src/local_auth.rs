//! Local DB-based user authentication (argon2 password hashing).

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use sqlx::PgPool;

use crate::{AuthError, UserIdentity};

pub struct LocalAuth {
    pool: PgPool,
}

impl LocalAuth {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<UserIdentity, AuthError> {
        let row = sqlx::query_as::<_, (String, String)>(
            "SELECT password_hash, role FROM nac_users \
             WHERE username = $1 AND enabled = true",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?
        .ok_or_else(|| AuthError::UserNotFound(username.to_string()))?;

        let (password_hash, role) = row;

        let hash =
            PasswordHash::new(&password_hash).map_err(|e| AuthError::Internal(e.to_string()))?;

        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .map_err(|_| AuthError::InvalidCredentials)?;

        Ok(UserIdentity {
            username: username.to_string(),
            display_name: None,
            email: None,
            groups: vec![role],
        })
    }
}

/// argon2 해시 생성 (관리자 API에서 유저 생성 시 사용)
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AuthError::Internal(e.to_string()))
}
