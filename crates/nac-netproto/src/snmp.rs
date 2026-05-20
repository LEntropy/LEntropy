//! Minimal SNMP v2c GET helper for switch port queries.

use crate::NetProtoError;

/// An SNMP community string and target address.
#[derive(Debug, Clone)]
pub struct SnmpTarget {
    pub address: std::net::SocketAddr,
    pub community: String,
}

/// A decoded SNMP VarBind value (simplified).
#[derive(Debug, Clone)]
pub enum SnmpValue {
    Integer(i64),
    OctetString(Vec<u8>),
    OidString(String),
    Null,
}

/// Encode a minimal SNMPv2c GET-REQUEST PDU.
///
/// Returns raw UDP payload bytes.
pub fn encode_get_request(
    community: &str,
    oid: &str,
    request_id: i32,
) -> Result<Vec<u8>, NetProtoError> {
    // Minimal BER-encoded SNMPv2c GET-REQUEST (no external ASN.1 dep)
    // This is a stub; replace with a full ASN.1/BER library for production.
    let _ = (community, oid, request_id);
    Err(NetProtoError::Parse(
        "SNMP encoding not yet implemented — use a full BER library".into(),
    ))
}
