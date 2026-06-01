# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LEntropy는 Rust 기반 **Network Access Control (NAC) 플랫폼**이다. 마이크로서비스 아키텍처로 구성되며 L2(ARP 스푸핑) + L3(nftables/iptables) + L7(Captive Portal) 계층 차단을 조합해 네트워크 접근 제어를 수행한다.

## Build & Development Commands

```bash
# 개발 환경 초기화 (최초 1회)
make setup              # .env 생성 + Docker 인프라 시작

# 인프라만 시작 (PostgreSQL, Redis, NATS)
make dev-up

# 전체 서비스 Docker 실행
make dev-all-up

# 빌드/검사
cargo check --workspace
cargo build --workspace
cargo build --workspace --release

# 테스트
cargo test --workspace                    # 단위 테스트
cargo test -p nac-fingerprint             # 특정 crate 테스트
make test-integration                     # 통합 테스트 (라이브 서버 필요)

# 린트/포맷
cargo fmt --all
cargo clippy --workspace -- -D warnings

# 파일 변경 시 자동 체크
make watch

# protobuf 재생성
cargo build -p nac-proto
```

## Architecture

### 서비스 역할 및 통신

모든 서비스 간 비동기 통신은 **NATS**를 통해 JSON으로 이뤄진다.

```
Sensor → nac.events.endpoint.detected → Policy-Manager
AAA    → nac.events.auth.response     → Policy-Manager
AgentGateway → nac.events.posture.report → Policy-Manager
Policy-Manager → nac.commands.enforcement → Enforcement
```

| 서비스 | 포트 | 역할 |
|--------|------|------|
| `policy-manager` | 8001 (HTTP) | 정책 평가·엔드포인트 수명주기 관리. 핵심 오케스트레이터 |
| `enforcement` | host network | nftables + ARP 스푸핑으로 실제 차단 실행 |
| `sensor` | — | ARP/DHCP 패킷 스니핑으로 단말 탐지 및 핑거프린팅 |
| `aaa` | 8080, 1812/udp | Captive Portal + RADIUS 인증 |
| `agent-gateway` | 50051 (gRPC) | 엔드포인트 에이전트 수신 |
| `api-gateway` | 8000 (HTTP) | JWT 인증 후 policy-manager 프록시 |
| `dhcp` | 67/udp | NAC 인식 DHCPv4 서버 |
| `endpoint-agent` | — | Windows/macOS/Linux 단말 에이전트 |

### 공유 Crate 역할

| Crate | 핵심 제공 |
|-------|-----------|
| `nac-store` | `EndpointRepo`, `PolicyRepo`, `AuditRepo`, `SessionRepo` (PostgreSQL + Redis) |
| `nac-policy-engine` | 정책 평가 로직 (`PolicyDecision`: Allow/Quarantine/Deny) |
| `nac-models` | 도메인 타입 (`Endpoint`, `AccessStatus`, `MacAddress`, `Vlan`) |
| `nac-netproto` | ARP 프레임 조작, DHCP 파싱, SNMP, ICMPv6 |
| `nac-fingerprint` | MAC OUI + DHCP PRL + TTL 기반 OS 추론 |
| `nac-auth` | LDAP 클라이언트, JWT `NacClaims` |
| `nac-bus` | NATS pub/sub 래퍼 |
| `nac-config` | `AppConfig` (환경변수 기반 설정) |
| `nac-proto` | tonic gRPC 스텁 (build.rs로 proto → Rust 생성) |

### Enforcement 차단 계층

`enforcement` 서비스는 `nac.commands.enforcement` NATS 메시지를 받아 두 가지 메커니즘을 동시 적용한다:

1. **nftables (Primary)**: `inet nac_filter` 테이블의 set 기반 MAC/IP 관리
   - `blocked_macs` / `blocked_ips`: 완전 차단 (DROP)
   - `quarantined_macs` / `quarantined_ips`: DNS(53) + Captive Portal(8080)만 허용
   - 백엔드 자동 선택: `nft` 우선, 없으면 `iptables-legacy`
2. **ARP 스푸핑 (Secondary)**: `pnet::datalink` raw socket으로 ARP reply 주입
   - 30초마다 재독살 루프 (ARP 캐시 만료 대응)

> **운영 주의**: `enforcement`는 `network_mode: host` + `NET_ADMIN` + `NET_RAW` 필요. Docker 없이 테스트 시 root 권한 및 nftables 설치 필요.

### Policy-Manager 내부 흐름

```
NATS consumer (nac.events.endpoint.detected)
  → EndpointRepo.upsert()
  → nac-policy-engine 평가
  → DB 상태 업데이트
  → NATS publish (nac.commands.enforcement)

REST POST /api/v1/endpoints/{id}/block|allow|quarantine
  → DB 상태 업데이트 + 감사 로그
  → NATS publish (nac.commands.enforcement)
```

`AppState`는 `PgPool`과 `NatsClient`를 포함한다. 기존 핸들러가 `State<PgPool>`을 추출할 수 있도록 `impl FromRef<AppState> for PgPool`이 구현되어 있다.

### Database

마이그레이션은 `services/policy-manager/migrations/`에 위치하며, 서비스 시작 시 `sqlx::migrate!`로 자동 적용된다. 외부 CLI 불필요.

## Key Conventions

- **에러 처리**: 서비스 API는 `AppError` enum (`Db`, `NotFound`, `Serialization`)으로 통일. `IntoResponse` 구현으로 HTTP 상태코드 자동 변환.
- **MAC 주소 형식**: nftables용은 소문자 콜론 구분(`aa:bb:cc:dd:ee:ff`), iptables-legacy용은 대문자(`AA:BB:CC:DD:EE:FF`). `nft_mac()` / `ipt_mac()` 헬퍼로 변환.
- **IP 주소**: DB에 CIDR 표기(`192.168.0.24/32`) 저장. enforcement 명령 발행 시 `/32` 제거 필요 (`split('/').next()`).
- **Cargo workspace**: 모든 의존성 버전은 루트 `Cargo.toml`에서 `[workspace.dependencies]`로 통합 관리.
- **proto 변경 시**: `nac-proto/build.rs`가 `tonic_build`로 자동 컴파일. `cargo build -p nac-proto` 실행.

## Integration Tests

```bash
# 인프라 및 policy-manager 실행 후:
make test-integration
# 또는
POLICY_MANAGER_URL=http://localhost:8001 \
  cargo test --manifest-path test/integration/Cargo.toml --features integration
```

## Docker Build

```bash
# 특정 서비스만 빌드 (Pi 등 느린 환경에서 권장)
docker compose build enforcement
docker compose build policy-manager

# 전체 재빌드
docker compose build
docker compose up -d
```

`Dockerfile.rust-service`는 멀티스테이지 빌드로, 의존성 캐시 최적화를 위해 dummy `main.rs`로 1차 빌드 후 실제 소스를 복사해 재빌드한다.
