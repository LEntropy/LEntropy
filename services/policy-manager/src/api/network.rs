use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use tokio::process::Command;

use super::endpoints::AppError;

#[derive(Debug, Deserialize)]
pub struct ScanQuery {
    /// CIDR 표기 서브넷. 기본: 192.168.0.0/24
    #[serde(default = "default_subnet")]
    pub subnet: String,
}

fn default_subnet() -> String {
    "192.168.0.0/24".to_string()
}

#[derive(Debug, Serialize)]
pub struct HostEntry {
    pub ip: String,
    pub octet: u8,
    /// ARP 테이블에서 가져온 MAC 주소
    pub mac: Option<String>,
    /// ARP/DB에서 가져온 호스트명
    pub hostname: Option<String>,
    /// OS 정보 (endpoints DB)
    pub os_family: Option<String>,
    pub os_version: Option<String>,
    pub device_type: Option<String>,
    pub vendor: Option<String>,
    /// NAC 상태: allowed / denied / quarantined / pending / unregistered
    pub nac_status: String,
    /// endpoints DB ID
    pub endpoint_id: Option<String>,
    /// 마지막 인증 사용자 (endpoints.username)
    pub last_auth_user: Option<String>,
    /// ARP 테이블에 현재 있는지 여부
    pub arp_active: bool,
    pub last_seen: Option<String>,
}

/// ARP 테이블 항목
struct ArpEntry {
    ip: String,
    mac: String,
}

/// /proc/net/arp 파싱
async fn read_arp_table() -> Vec<ArpEntry> {
    let content = match tokio::fs::read_to_string("/proc/net/arp").await {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    content
        .lines()
        .skip(1) // 헤더 스킵
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 {
                return None;
            }
            let ip = cols[0].to_string();
            let flags = cols[2];
            let mac = cols[3].to_string();
            // flags 0x2 = 완료된 항목, 0x6 = proxy
            if flags == "0x0" || mac == "00:00:00:00:00:00" {
                return None;
            }
            Some(ArpEntry { ip, mac })
        })
        .collect()
}

/// `ip neigh show` 도 함께 읽어 ARP 보완
async fn read_ip_neigh() -> Vec<ArpEntry> {
    let output = Command::new("ip").args(["neigh", "show"]).output().await;

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return vec![],
    };

    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter_map(|line| {
            // 형식: "192.168.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                return None;
            }
            let ip = parts[0].to_string();
            // lladdr 다음이 MAC
            let lladdr_pos = parts.iter().position(|&s| s == "lladdr")?;
            let mac = parts.get(lladdr_pos + 1)?.to_string();
            Some(ArpEntry { ip, mac })
        })
        .collect()
}

/// CIDR에서 시작/끝 옥텟 추출 (단순 /24 지원)
fn subnet_range(cidr: &str) -> Option<(String, u8, u8)> {
    let (net, prefix_str) = cidr.split_once('/')?;
    let prefix: u8 = prefix_str.parse().ok()?;
    let parts: Vec<&str> = net.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let base = format!("{}.{}.{}.", parts[0], parts[1], parts[2]);
    let host_bits = 32 - prefix;
    let host_count = (1u32 << host_bits) - 2; // 네트워크/브로드캐스트 제외
    let start: u8 = 1;
    let end = (start as u32 + host_count - 1).min(254) as u8;
    Some((base, start, end))
}

/// DB에서 모든 endpoint를 가져와 IP → endpoint 매핑 반환
async fn load_db_endpoints(pool: &PgPool) -> Result<HashMap<String, DbEndpoint>, AppError> {
    let rows = sqlx::query_as::<
        _,
        (
            String,         // id
            Option<String>, // ip_address (INET → text)
            Option<String>, // mac_address
            Option<String>, // hostname
            Option<String>, // os_family
            Option<String>, // os_version
            Option<String>, // device_type
            Option<String>, // vendor
            String,         // status
            Option<String>, // username
            Option<String>, // last_seen (ISO text)
        ),
    >(
        "SELECT id::text, ip_address::text, mac_address::text, \
         hostname, os_family, os_version, device_type, vendor, \
         status, username, \
         to_char(last_seen AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
         FROM endpoints",
    )
    .fetch_all(pool)
    .await
    .map_err(anyhow::Error::from)?;

    let mut map: HashMap<String, DbEndpoint> = HashMap::new();
    for row in rows {
        let ip_raw = row.1.clone().unwrap_or_default();
        // INET 타입은 "192.168.0.24/32" 형태일 수 있음
        let ip = ip_raw.split('/').next().unwrap_or(&ip_raw).to_string();
        if !ip.is_empty() {
            map.insert(
                ip.clone(),
                DbEndpoint {
                    id: row.0,
                    ip,
                    mac: row.2,
                    hostname: row.3,
                    os_family: row.4,
                    os_version: row.5,
                    device_type: row.6,
                    vendor: row.7,
                    status: row.8,
                    username: row.9,
                    last_seen: row.10,
                },
            );
        }
    }
    Ok(map)
}

struct DbEndpoint {
    id: String,
    #[allow(dead_code)]
    ip: String,
    mac: Option<String>,
    hostname: Option<String>,
    os_family: Option<String>,
    os_version: Option<String>,
    device_type: Option<String>,
    vendor: Option<String>,
    status: String,
    username: Option<String>,
    last_seen: Option<String>,
}

/// GET /api/v1/network/hosts
pub async fn list_hosts(
    State(pool): State<PgPool>,
    Query(q): Query<ScanQuery>,
) -> Result<Json<Vec<HostEntry>>, AppError> {
    let (base, start, end) = subnet_range(&q.subnet)
        .ok_or_else(|| AppError::NotFound("invalid subnet format".to_string()))?;

    // ARP 테이블 수집 (두 소스 병합)
    let (arp_proc, arp_neigh) = tokio::join!(read_arp_table(), read_ip_neigh());
    let mut arp_map: HashMap<String, String> = HashMap::new();
    for entry in arp_proc.into_iter().chain(arp_neigh) {
        arp_map.entry(entry.ip).or_insert(entry.mac);
    }

    // DB 엔드포인트 로드
    let db_map = load_db_endpoints(&pool).await?;

    let mut hosts = Vec::new();
    for octet in start..=end {
        let ip = format!("{base}{octet}");

        let arp_mac = arp_map.get(&ip).cloned();
        let arp_active = arp_mac.is_some();
        let db_ep = db_map.get(&ip);

        let entry = match db_ep {
            Some(ep) => HostEntry {
                ip: ip.clone(),
                octet,
                mac: ep.mac.clone().or(arp_mac),
                hostname: ep.hostname.clone(),
                os_family: ep.os_family.clone(),
                os_version: ep.os_version.clone(),
                device_type: ep.device_type.clone(),
                vendor: ep.vendor.clone(),
                nac_status: ep.status.clone(),
                endpoint_id: Some(ep.id.clone()),
                last_auth_user: ep.username.clone(),
                arp_active,
                last_seen: ep.last_seen.clone(),
            },
            None => HostEntry {
                ip: ip.clone(),
                octet,
                mac: arp_mac,
                hostname: None,
                os_family: None,
                os_version: None,
                device_type: None,
                vendor: None,
                nac_status: "unregistered".to_string(),
                endpoint_id: None,
                last_auth_user: None,
                arp_active,
                last_seen: None,
            },
        };
        hosts.push(entry);
    }

    Ok(Json(hosts))
}
