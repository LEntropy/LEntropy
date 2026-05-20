//! nac-auth: LDAP, JWT, and OIDC authentication helpers for the NAC platform.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod jwt;
pub mod ldap;

pub use ldap::LdapClient;

/// Authentication errors.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("user not found: {0}")]
    UserNotFound(String),
    #[error("token expired")]
    TokenExpired,
    #[error("token invalid: {0}")]
    TokenInvalid(String),
    #[error("ldap error: {0}")]
    Ldap(String),
    #[error("internal error: {0}")]
    Internal(String),
}

/// An authenticated user identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentity {
    /// Unique username / UPN.
    pub username: String,
    /// Display name from directory.
    pub display_name: Option<String>,
    /// Email address.
    pub email: Option<String>,
    /// Group memberships.
    pub groups: Vec<String>,
}

/// Claims embedded in a NAC JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NacClaims {
    pub sub: String,
    pub groups: Vec<String>,
    pub exp: i64,
    pub iat: i64,
}
