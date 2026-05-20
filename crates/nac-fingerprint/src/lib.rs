//! nac-fingerprint: OS and device identification from network observables.

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Confidence level of an identification result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// A device fingerprint result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fingerprint {
    pub os_family: Option<String>,
    pub os_version: Option<String>,
    pub device_type: Option<String>,
    pub vendor: Option<String>,
    pub confidence: Confidence,
}

/// Raw signals collected during device discovery.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FingerprintSignals {
    /// MAC OUI (first 3 bytes as hex, e.g. "001122")
    pub oui: Option<String>,
    /// DHCP option 55 parameter request list (raw bytes)
    pub dhcp_prl: Option<Vec<u8>>,
    /// HTTP User-Agent string if captured
    pub user_agent: Option<String>,
    /// TCP initial window size
    pub tcp_win_size: Option<u16>,
    /// TCP options fingerprint string (e.g. "MSS,NOP,WS,NOP,NOP,TS,SACK")
    pub tcp_options: Option<String>,
}

/// Identify a device from collected signals.
///
/// Returns a best-effort [`Fingerprint`] based on heuristics and OUI lookups.
pub fn identify(signals: &FingerprintSignals) -> Result<Fingerprint> {
    let mut fp = Fingerprint {
        os_family: None,
        os_version: None,
        device_type: None,
        vendor: None,
        confidence: Confidence::Low,
    };

    // OUI-based vendor detection
    if let Some(ref oui) = signals.oui {
        match oui.to_uppercase().as_str() {
            "ACDE48" | "A4C361" => {
                fp.vendor = Some("Apple".into());
                fp.os_family = Some("iOS/macOS".into());
                fp.confidence = Confidence::Medium;
            }
            "001A2B" => {
                fp.vendor = Some("Cisco".into());
                fp.device_type = Some("Network Equipment".into());
                fp.confidence = Confidence::Medium;
            }
            _ => {}
        }
    }

    // DHCP PRL heuristics
    if let Some(ref prl) = signals.dhcp_prl {
        // Windows typically requests options 1,3,6,15,31,33,43,44,46,47,119,121,249,252
        let windows_prl: Vec<u8> = vec![1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252];
        if prl == &windows_prl {
            fp.os_family = Some("Windows".into());
            fp.confidence = Confidence::High;
        }
        // Linux DHCP clients typically request 1,28,2,3,15,6,119,12,44,47,26,121,42
        let linux_prl: Vec<u8> = vec![1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42];
        if prl == &linux_prl {
            fp.os_family = Some("Linux".into());
            fp.confidence = Confidence::High;
        }
    }

    // User-Agent based detection
    if let Some(ref ua) = signals.user_agent {
        if ua.contains("Windows NT") {
            fp.os_family = Some("Windows".into());
            fp.confidence = Confidence::High;
        } else if ua.contains("iPhone") || ua.contains("iPad") {
            fp.os_family = Some("iOS".into());
            fp.device_type = Some("Mobile".into());
            fp.confidence = Confidence::High;
        } else if ua.contains("Android") {
            fp.os_family = Some("Android".into());
            fp.device_type = Some("Mobile".into());
            fp.confidence = Confidence::High;
        } else if ua.contains("Macintosh") {
            fp.os_family = Some("macOS".into());
            fp.confidence = Confidence::High;
        } else if ua.contains("Linux") {
            fp.os_family = Some("Linux".into());
            fp.confidence = Confidence::Medium;
        }
    }

    Ok(fp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_agent_windows() {
        let signals = FingerprintSignals {
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64)".into()),
            ..Default::default()
        };
        let fp = identify(&signals).unwrap();
        assert_eq!(fp.os_family.as_deref(), Some("Windows"));
        assert_eq!(fp.confidence, Confidence::High);
    }

    #[test]
    fn test_user_agent_ios() {
        let signals = FingerprintSignals {
            user_agent: Some("Mozilla/5.0 (iPhone; CPU iPhone OS 16_0)".into()),
            ..Default::default()
        };
        let fp = identify(&signals).unwrap();
        assert_eq!(fp.os_family.as_deref(), Some("iOS"));
        assert_eq!(fp.device_type.as_deref(), Some("Mobile"));
    }
}
