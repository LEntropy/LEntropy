//! IP 주소 풀 — MAC→IP 할당 테이블 (인메모리).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct LeasePool {
    inner: Arc<Mutex<PoolInner>>,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
}

struct PoolInner {
    leases: HashMap<Vec<u8>, Ipv4Addr>,
    next: u32,
    start: u32,
    end: u32,
}

impl LeasePool {
    pub fn new(
        pool_start: Ipv4Addr,
        pool_end: Ipv4Addr,
        subnet_mask: Ipv4Addr,
        gateway: Ipv4Addr,
    ) -> Self {
        let start = u32::from(pool_start);
        let end = u32::from(pool_end);
        Self {
            inner: Arc::new(Mutex::new(PoolInner {
                leases: HashMap::new(),
                next: start,
                start,
                end,
            })),
            subnet_mask,
            gateway,
        }
    }

    pub fn get_or_allocate(&self, mac: &[u8]) -> Ipv4Addr {
        let mut pool = self.inner.lock().unwrap();
        let key = mac[..6.min(mac.len())].to_vec();
        if let Some(&ip) = pool.leases.get(&key) {
            return ip;
        }
        let ip = if pool.next <= pool.end {
            let ip = Ipv4Addr::from(pool.next);
            pool.next += 1;
            ip
        } else {
            Ipv4Addr::from(pool.start) // 풀 고갈 시 첫 번째 IP 재사용
        };
        pool.leases.insert(key, ip);
        ip
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pool() -> LeasePool {
        LeasePool::new(
            "192.168.1.100".parse().unwrap(),
            "192.168.1.200".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
        )
    }

    #[test]
    fn test_allocate_new_mac() {
        let pool = make_pool();
        let mac = &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let ip = pool.get_or_allocate(mac);
        assert_eq!(ip, "192.168.1.100".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_same_mac_same_ip() {
        let pool = make_pool();
        let mac = &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let ip1 = pool.get_or_allocate(mac);
        let ip2 = pool.get_or_allocate(mac);
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_different_macs_different_ips() {
        let pool = make_pool();
        let mac1 = &[0x01, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mac2 = &[0x01, 0x00, 0x00, 0x00, 0x00, 0x02];
        let ip1 = pool.get_or_allocate(mac1);
        let ip2 = pool.get_or_allocate(mac2);
        assert_ne!(ip1, ip2);
    }
}
