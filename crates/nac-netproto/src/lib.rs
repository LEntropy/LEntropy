//! nac-netproto: pnet-based ARP, DHCP, SNMP, and ICMPv6 protocol helpers.

pub mod arp;
pub mod dhcp;
pub mod icmpv6;
pub mod snmp;

use thiserror::Error;

/// Errors produced by network protocol operations.
#[derive(Debug, Error)]
pub enum NetProtoError {
    #[error("packet parse error: {0}")]
    Parse(String),
    #[error("interface error: {0}")]
    Interface(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
