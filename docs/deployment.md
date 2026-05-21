# NAC Platform — 배포 가이드

## 아키텍처 개요

```
인터넷/내부망
    │
    ▼
[nginx / LB]
    ├──▶ :80/:443  → admin-console (nginx static)
    ├──▶ :8000     → api-gateway   (JWT 인증 + proxy)
    └──▶ :8080     → aaa           (Captive Portal)

api-gateway ──▶ policy-manager:8001  (REST /api/v1/*)
aaa         ──▶ NATS              (인증 이벤트)
sensor      ──▶ NATS              (탐지 이벤트)
enforcement ──▶ NATS + raw socket (차단 실행)
agent-gateway:50051 ◀── endpoint-agent (gRPC)

공통 인프라: PostgreSQL:5432, Redis:6379, NATS:4222
```

---

## 로컬 개발 환경 (docker-compose)

### 1단계 — 환경 초기화 (최초 1회)
```bash
# 사전 요구사항: Docker Desktop, Rust 1.87+, Node 22+
git clone https://github.com/LEntropy/LEntropy.git && cd LEntropy
make setup          # .env 생성 + 인프라 컨테이너 기동
```

### 2단계 — 인프라만 기동 (서비스는 로컬 실행)
```bash
make dev-up         # postgres, redis, nats만 기동
# 터미널 각각 열어서:
make run-policy-manager   # :8001
make run-aaa              # :8080, :1812/udp, :1813/udp
make run-api-gateway      # :8000
cd web/admin-console && npm run dev   # :3000
```

### 3단계 — 전체 컨테이너 기동 (이미지 빌드 포함)
```bash
make dev-all-up     # docker compose up -d (이미지 빌드 포함)
make dev-logs       # 로그 스트리밍

# 접속
# Admin Console: http://localhost:3000  (ID: admin / PW: changeme)
# API Gateway:   http://localhost:8000/healthz
# Policy Manager: http://localhost:8001/healthz
```

---

## 테스트

```bash
# 유닛 테스트 (DB 불필요 — 56개)
make test

# TypeScript 타입 체크
make test-all       # cargo test + npm type-check

# 통합 테스트 (policy-manager 실행 중 필요)
make dev-up
make run-policy-manager &
make test-integration

# 코드 품질
make fmt            # rustfmt 적용
make lint           # clippy -D warnings
make audit          # cargo-audit 보안 취약점 검사
```

---

## 프로덕션 배포 — Kubernetes (Helm)

### 사전 요구사항
```bash
# 이미지 빌드 (각 서비스별)
docker build -f deployments/docker/Dockerfile.rust-service \
  --build-arg SERVICE_NAME=policy-manager \
  -t your-registry/nac/policy-manager:v0.1.0 .

docker build -f deployments/docker/Dockerfile.rust-service \
  --build-arg SERVICE_NAME=aaa \
  -t your-registry/nac/aaa:v0.1.0 .

# ... (각 서비스 반복)

docker build -f deployments/docker/Dockerfile.admin-console \
  -t your-registry/nac/admin-console:v0.1.0 .

# 레지스트리 푸시
docker push your-registry/nac/policy-manager:v0.1.0
# ...
```

### Helm 설치
```bash
# values.yaml 복사 후 환경 맞게 수정
cp deployments/kubernetes/nac-platform/values.yaml values-prod.yaml
# values-prod.yaml에서 이미지 registry, 시크릿, ingress host 수정

# PostgreSQL / Redis / NATS는 클러스터 내부 또는 외부 서비스 선택
# 외부 DB 사용 시 values-prod.yaml에서:
#   postgresql.enabled: false
#   commonEnv.DATABASE_URL: "postgres://..."

# 설치
helm install nac-platform deployments/kubernetes/nac-platform \
  -f values-prod.yaml \
  --namespace nac \
  --create-namespace

# 업그레이드
helm upgrade nac-platform deployments/kubernetes/nac-platform \
  -f values-prod.yaml \
  --namespace nac

# 상태 확인
kubectl get pods -n nac
kubectl get ingress -n nac
```

### 주요 values 오버라이드 예시 (values-prod.yaml)
```yaml
imageTag: "v0.1.0"

commonEnv:
  DATABASE_URL: "postgres://nac:STRONG_PW@db.internal:5432/nac"
  REDIS_URL: "redis://redis.internal:6379"
  NATS_URL: "nats://nats.internal:4222"
  JWT_SECRET: "minimum-32-character-production-secret"

policyManager:
  image:
    repository: your-registry/nac/policy-manager
  replicaCount: 3

aaa:
  image:
    repository: your-registry/nac/aaa
  env:
    RADIUS_SECRET: "your-radius-shared-secret"

apiGateway:
  ingress:
    hosts:
      - host: api.nac.company.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: nac-api-tls
        hosts: [api.nac.company.com]

adminConsole:
  ingress:
    hosts:
      - host: nac.company.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: nac-console-tls
        hosts: [nac.company.com]
```

---

## 환경변수 레퍼런스

| 서비스 | 변수 | 기본값 | 설명 |
|---|---|---|---|
| 공통 | `DATABASE_URL` | — | PostgreSQL 연결 문자열 |
| 공통 | `REDIS_URL` | — | Redis 연결 URL |
| 공통 | `NATS_URL` | — | NATS 서버 URL |
| policy-manager | `LISTEN_ADDR` | `0.0.0.0:8001` | HTTP 바인딩 주소 |
| aaa | `CAPTIVE_PORTAL_ADDR` | `0.0.0.0:8080` | Captive Portal |
| aaa | `RADIUS_AUTH_ADDR` | `0.0.0.0:1812` | RADIUS 인증 UDP |
| aaa | `RADIUS_ACCT_ADDR` | `0.0.0.0:1813` | RADIUS 어카운팅 UDP |
| aaa | `RADIUS_SECRET` | `radius-shared-secret` | RADIUS 공유 시크릿 |
| aaa | `LDAP_URL` | — | LDAP 서버 URL (미설정시 mock) |
| api-gateway | `LISTEN_ADDR` | `0.0.0.0:8000` | HTTP 바인딩 주소 |
| api-gateway | `POLICY_MANAGER_URL` | `http://localhost:8001` | 내부 policy-manager URL |
| api-gateway | `JWT_SECRET` | (기본값) | JWT 서명 시크릿 (32자+) |
| api-gateway | `ADMIN_USER` | `admin` | 관리자 로그인 ID |
| api-gateway | `ADMIN_PASS` | `changeme` | 관리자 로그인 PW |
| agent-gateway | `GRPC_ADDR` | `0.0.0.0:50051` | gRPC 바인딩 주소 |
| endpoint-agent | `AGENT_GATEWAY_ADDR` | `http://localhost:50051` | gateway gRPC URL |
| endpoint-agent | `CHECKIN_INTERVAL_SECS` | `60` | 체크인 주기 (초) |
| dhcp | `DHCP_POOL_START` | `192.168.1.100` | IP 풀 시작 |
| dhcp | `DHCP_POOL_END` | `192.168.1.200` | IP 풀 끝 |
| dhcp | `DHCP_GATEWAY` | `192.168.1.1` | 기본 게이트웨이 |

---

## 보안 체크리스트 (프로덕션 전 필수)

- [ ] `JWT_SECRET` 최소 32자 무작위 문자열로 교체
- [ ] `RADIUS_SECRET` 강력한 시크릿으로 교체
- [ ] `ADMIN_PASS` 기본값 `changeme` 교체
- [ ] PostgreSQL 비밀번호 강화
- [ ] LDAP/AD 연동 설정 (`LDAP_URL`, `LDAP_BIND_DN` 등)
- [ ] TLS 인증서 설정 (Ingress 또는 cert-manager)
- [ ] sensor/enforcement 서비스는 호스트 네트워크 + NET_RAW 권한 필요 → 노드 격리 고려
- [ ] RADIUS UDP 포트(1812/1813)는 NAS 장비 IP 기준 방화벽 제한

---

## API 레퍼런스 요약

### Policy Manager (`http://policy-manager:8001`)

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/healthz` | 헬스 체크 |
| GET | `/api/v1/endpoints` | 단말 목록 (`?limit=50&offset=0`) |
| GET | `/api/v1/endpoints/:id` | 단말 상세 |
| GET | `/api/v1/endpoints/mac/:mac` | MAC으로 단말 조회 |
| POST | `/api/v1/endpoints/:id/allow` | 단말 허용 |
| POST | `/api/v1/endpoints/:id/block` | 단말 차단 |
| POST | `/api/v1/endpoints/:id/quarantine` | 단말 격리 |
| GET | `/api/v1/policies` | 정책 목록 |
| POST | `/api/v1/policies` | 정책 생성 |
| PUT | `/api/v1/policies/:id` | 정책 수정 |
| DELETE | `/api/v1/policies/:id` | 정책 삭제 |
| GET | `/api/v1/audit` | 감사 로그 (`?limit=50&endpoint_id=...`) |
| GET | `/api/v1/stats` | 대시보드 통계 |

### API Gateway (`http://api-gateway:8000`) — JWT 필요

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/healthz` | 헬스 체크 |
| POST | `/api/auth/login` | 로그인 → JWT 발급 |
| GET | `/api/endpoints` | policy-manager 프록시 |
| POST | `/api/endpoints/:id/allow` | 단말 허용 (프록시) |
| POST | `/api/endpoints/:id/block` | 단말 차단 (프록시) |
| POST | `/api/endpoints/:id/quarantine` | 단말 격리 (프록시) |
| GET | `/api/policies` | 정책 목록 (프록시) |
| POST | `/api/policies` | 정책 생성 (프록시) |
| PUT | `/api/policies/:id` | 정책 수정 (프록시) |
| DELETE | `/api/policies/:id` | 정책 삭제 (프록시) |
| GET | `/api/audit` | 감사 로그 (프록시) |
| GET | `/api/stats` | 통계 (프록시) |
