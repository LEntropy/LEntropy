//! TTL 기반 OS 추정.
//! 초기 TTL 값으로 OS 계열을 추론한다.

/// IP 헤더의 TTL 값으로 OS 계열 추정.
/// 라우터 홉 수를 보정하지 않으므로 실제 initial TTL을 기준으로 구분.
pub fn os_from_ttl(ttl: u8) -> Option<&'static str> {
    match ttl {
        // Windows: initial TTL 128
        113..=128 => Some("Windows"),
        // Linux/Android: initial TTL 64
        49..=64 => Some("Linux"),
        // macOS/iOS: initial TTL 64 (동일하지만 TCP options으로 구분)
        // Cisco IOS: initial TTL 255
        240..=255 => Some("Network Equipment"),
        // Solaris/AIX: initial TTL 254
        239 => Some("Unix"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_ttl() {
        assert_eq!(os_from_ttl(128), Some("Windows"));
        assert_eq!(os_from_ttl(120), Some("Windows")); // few hops
    }

    #[test]
    fn test_linux_ttl() {
        assert_eq!(os_from_ttl(64), Some("Linux"));
        assert_eq!(os_from_ttl(60), Some("Linux")); // 4 hops
    }

    #[test]
    fn test_cisco_ttl() {
        assert_eq!(os_from_ttl(255), Some("Network Equipment"));
        assert_eq!(os_from_ttl(250), Some("Network Equipment"));
    }

    #[test]
    fn test_unknown_ttl() {
        assert_eq!(os_from_ttl(1), None);
        assert_eq!(os_from_ttl(32), None);
    }
}
