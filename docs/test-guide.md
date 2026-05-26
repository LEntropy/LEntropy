# NAC 플랫폼 — Ubuntu 서버 + Windows 10 클라이언트 테스트 가이드

## 환경 구성

```
[Windows 10 PC]                    [Ubuntu 서버]
  - endpoint-agent.exe    gRPC      - Docker Compose (전체 스택)
  - 브라우저 (Admin UI)  ──────────▶  - :3000 Admin Console
                          REST       - :8000 API Gateway
                                     - :8001 Policy Manager
                                     - :8080 Captive Portal
                                     - :1812/UDP RADIUS Auth
                                     - :50051 gRPC (Agent Gateway)
                                     - :5432 PostgreSQL
                                     - :4222 NATS
```

---

## 사전 요구사항

### Ubuntu 서버
- Ubuntu 22.04 LTS 이상
- Docker 24+ & Docker Compose v2
- Rust 1.87+ (크로스 컴파일용)
- 방화벽 포트 오픈: 3000, 8000, 8001, 8080, 50051, 1812/UDP, 1813/UDP

### Windows 10 클라이언트
- Windows 10 64-bit (버전 1903 이상)
- PowerShell 5.1 이상 (관리자 권한)
- 브라우저 (Chrome/Edge/Firefox)
- Ubuntu 서버와 동일 네트워크 또는 라우팅 가능

---

## 1단계 — Ubuntu 서버 준비

### 1-1. 프로젝트 클론 및 환경 설정

```bash
git clone https://github.com/LEntropy/LEntropy.git
cd LEntropy

# 환경변수 파일 생성
cp .env.example .env

# 필요 시 서버 IP 확인
hostname -I | awk '{print $1}'
```

`.env` 에서 반드시 확인할 항목:
```env
# 서버 IP로 변경 (Windows에서 접속할 주소)
POLICY_MANAGER_URL=http://localhost:8001   # 내부 서비스간 통신은 그대로 유지
ADMIN_USER=admin
ADMIN_PASS=changeme          # 테스트 후 반드시 변경
JWT_SECRET=change-me-in-production-at-least-32-chars!!
RADIUS_SECRET=radius-shared-secret
```

### 1-2. Docker 빌드 & 기동

```bash
# 처음 빌드 (10~20분 소요 — Rust 컴파일)
docker compose build

# 전체 서비스 기동
docker compose up -d

# 상태 확인
docker compose ps
```

예상 출력:
```
NAME                STATUS
lentropy-postgres-1   running (healthy)
lentropy-redis-1      running (healthy)
lentropy-nats-1       running (healthy)
lentropy-policy-manager-1   running
lentropy-aaa-1              running
lentropy-agent-gateway-1    running
lentropy-api-gateway-1      running
lentropy-admin-console-1    running
```

### 1-3. 방화벽 설정 (ufw 사용 시)

```bash
sudo ufw allow 3000/tcp    # Admin Console
sudo ufw allow 8000/tcp    # API Gateway
sudo ufw allow 8001/tcp    # Policy Manager (직접 테스트용)
sudo ufw allow 8080/tcp    # Captive Portal
sudo ufw allow 50051/tcp   # gRPC Agent Gateway
sudo ufw allow 1812/udp    # RADIUS Auth
sudo ufw allow 1813/udp    # RADIUS Acct
sudo ufw reload
```

---

## 2단계 — Windows 10 에이전트 빌드

### 2-1. Ubuntu 서버에서 Windows 바이너리 크로스 컴파일

```bash
# Ubuntu에서 실행
# Windows 크로스 컴파일 타겟 추가
rustup target add x86_64-pc-windows-gnu

# 크로스 컴파일러 설치
sudo apt-get install -y gcc-mingw-w64-x86-64

# Windows용 바이너리 빌드
cargo build --release -p endpoint-agent --target x86_64-pc-windows-gnu

# 결과물 위치
ls -la target/x86_64-pc-windows-gnu/release/endpoint-agent.exe
```

### 2-2. Windows 10 PC로 파일 전송

```bash
# 서버에서 SCP로 전송하거나, 공유 폴더 사용
# 예: scp로 전송
scp target/x86_64-pc-windows-gnu/release/endpoint-agent.exe user@windows-pc:C:\nac-agent\
```

또는 서버에서 HTTP로 제공:
```bash
cd target/x86_64-pc-windows-gnu/release/
python3 -m http.server 9999
# Windows 브라우저에서: http://<서버IP>:9999/endpoint-agent.exe
```

### 2-3. Windows 10에서 에이전트 실행

PowerShell (일반 권한):
```powershell
# 디렉토리 생성
New-Item -ItemType Directory -Force -Path C:\nac-agent
cd C:\nac-agent

# 환경변수 설정 (서버 IP로 변경)
$env:AGENT_GATEWAY_ADDR = "http://<서버IP>:50051"
$env:CHECKIN_INTERVAL_SECS = "30"
$env:DEVICE_ID_FILE = "C:\nac-agent\device-id.txt"
$env:RUST_LOG = "info"

# 실행
.\endpoint-agent.exe
```

예상 로그:
```json
{"level":"INFO","service":"endpoint-agent","version":"0.1.0","message":"starting up"}
{"level":"INFO","device_id":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx","message":"device identity loaded"}
{"level":"INFO","hostname":"DESKTOP-ABC123","os":"Windows","message":"system info collected"}
{"level":"INFO","message":"connected to agent-gateway"}
{"level":"INFO","action":"allow","is_compliant":true,"message":"status report sent"}
```

---

## 3단계 — 헬스체크 테스트

### Ubuntu 서버에서 (curl)

```bash
SERVER_IP=$(hostname -I | awk '{print $1}')

# 각 서비스 헬스체크
curl -s http://localhost:8001/healthz   # policy-manager → "ok"
curl -s http://localhost:8000/healthz   # api-gateway    → "ok"
curl -s http://localhost:8080/          # captive portal  → HTML 응답

# NATS 상태
curl -s http://localhost:8222/healthz
```

### Windows 브라우저에서

| URL | 예상 결과 |
|-----|-----------|
| `http://<서버IP>:3000` | Admin Console 로그인 페이지 |
| `http://<서버IP>:8000/healthz` | `ok` 텍스트 |
| `http://<서버IP>:8080` | Captive Portal HTML |

---

## 4단계 — Admin Console 로그인 테스트

### Windows 브라우저에서

1. `http://<서버IP>:3000` 접속
2. 로그인 입력:
   - **ID**: `admin`
   - **PW**: `changeme`
3. 로그인 버튼 클릭

**예상 결과:**
- JWT 토큰 발급 후 대시보드로 이동
- 좌측 사이드바: Dashboard / Endpoints / Policies / Audit Log

**실패 시 확인:**
```bash
# 서버에서 api-gateway 로그 확인
docker compose logs api-gateway --tail=20

# JWT 토큰 직접 테스트
curl -s -X POST http://<서버IP>:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"changeme"}'
# 예상: {"token":"eyJ..."}
```

---

## 5단계 — 에이전트 등록 확인 테스트

### 순서

1. Windows에서 endpoint-agent.exe 실행 (2-3 참고)
2. 30초 대기 (첫 체크인)
3. Admin Console → **Endpoints** 메뉴 클릭
4. Windows PC의 hostname이 목록에 나타나는지 확인

**서버에서 직접 확인:**
```bash
# policy-manager API로 단말 목록 조회
curl -s http://localhost:8001/api/v1/endpoints | python3 -m json.tool

# agent-gateway 로그 확인
docker compose logs agent-gateway --tail=20
```

**예상 응답:**
```json
{
  "endpoints": [
    {
      "id": "xxxxxxxx-...",
      "mac_address": "...",
      "ip_address": "...",
      "hostname": "DESKTOP-ABC123",
      "os": "Windows 10.0.19045",
      "status": "pending",
      "last_seen": "2026-05-26T..."
    }
  ]
}
```

---

## 6단계 — 단말 제어 테스트 (Allow / Block / Quarantine)

### Admin Console에서

1. Endpoints 목록에서 Windows PC 행 클릭
2. **Allow** 버튼 → 상태가 `allowed`로 변경 확인
3. **Block** 버튼 → 상태가 `blocked`로 변경 확인
4. **Quarantine** 버튼 → 상태가 `quarantine`으로 변경 확인

### curl로 직접 테스트

```bash
# 로그인 후 토큰 저장
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"changeme"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# 단말 목록 조회 (토큰 필요)
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/endpoints | python3 -m json.tool

# 특정 단말 차단 (ID는 위 응답에서 복사)
ENDPOINT_ID="<단말_UUID>"
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/endpoints/${ENDPOINT_ID}/block

# 허용으로 변경
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/endpoints/${ENDPOINT_ID}/allow
```

---

## 7단계 — 정책(Policy) 생성 테스트

### Admin Console에서

1. **Policies** 메뉴 클릭
2. **새 정책 추가** 버튼 클릭
3. 입력:
   - 이름: `Block Unknown Devices`
   - 조건: `status == unknown`
   - 액션: `block`
4. 저장 후 목록에 나타나는지 확인

### curl로 직접 테스트

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  http://localhost:8000/api/policies \
  -d '{
    "name": "Block Unknown Devices",
    "description": "미등록 단말 자동 차단",
    "condition": "status == unknown",
    "action": "block",
    "enabled": true
  }' | python3 -m json.tool
```

---

## 8단계 — 감사 로그 확인 테스트

```bash
# 감사 로그 조회
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/audit | python3 -m json.tool
```

Admin Console → **Audit Log** 에서 아래 이벤트가 기록되어야 함:
- `endpoint_registered` — 에이전트 체크인
- `status_changed` — allow/block/quarantine 변경
- `policy_created` — 정책 생성

---

## 9단계 — RADIUS 인증 테스트

### Ubuntu에서 radtest 사용

```bash
# freeradius-utils 설치
sudo apt-get install -y freeradius-utils

# RADIUS Access-Request 전송
radtest admin changeme localhost 0 radius-shared-secret
```

**예상 응답:**
```
Sent Access-Request ...
Received Access-Accept
```

**실패 응답 확인:**
```
Received Access-Reject
```

aaa 로그 확인:
```bash
docker compose logs aaa --tail=30
```

---

## 10단계 — 통계 대시보드 테스트

```bash
# 통계 API 직접 호출
curl -s http://localhost:8001/api/v1/stats | python3 -m json.tool
```

예상 응답:
```json
{
  "total_endpoints": 1,
  "allowed": 1,
  "blocked": 0,
  "quarantine": 0,
  "pending": 0,
  "recent_events": 5
}
```

Admin Console → **Dashboard** 에서 차트로 확인.

---

## 11단계 — 로그 & 장애 진단

### 전체 서비스 로그 실시간 확인

```bash
docker compose logs -f
```

### 서비스별 로그

```bash
docker compose logs policy-manager -f
docker compose logs api-gateway -f
docker compose logs agent-gateway -f
docker compose logs aaa -f
```

### PostgreSQL 직접 조회

```bash
docker exec -it $(docker compose ps -q postgres) \
  psql -U nac -d nac -c "SELECT id, mac_address, ip_address, hostname, status, last_seen FROM endpoints;"

docker exec -it $(docker compose ps -q postgres) \
  psql -U nac -d nac -c "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 10;"
```

### NATS 이벤트 모니터링

```bash
# nats CLI 설치
curl -L https://github.com/nats-io/natscli/releases/latest/download/nats-0.1.5-linux-amd64.zip \
  -o nats.zip && unzip nats.zip
sudo mv nats-*/nats /usr/local/bin/

# 모든 NAC 이벤트 구독
nats sub -s nats://localhost:4222 "nac.>"
```

---

## 완전한 테스트 체크리스트

### 서버 기동

- [ ] `docker compose ps` — 8개 서비스 모두 `running` 상태
- [ ] `curl http://localhost:8001/healthz` → `ok`
- [ ] `curl http://localhost:8000/healthz` → `ok`
- [ ] `curl http://localhost:8080/` → HTTP 200 (Captive Portal)

### 관리자 인증

- [ ] `http://<서버IP>:3000` 브라우저 접속 → 로그인 페이지 표시
- [ ] admin / changeme 로그인 → 대시보드 이동
- [ ] 잘못된 비밀번호 입력 → 401 오류 표시
- [ ] JWT 토큰 직접 발급 curl 성공

### 에이전트 동작

- [ ] Windows에서 endpoint-agent.exe 실행 → "connected to agent-gateway" 로그
- [ ] 30초 후 Admin Console Endpoints 목록에 Windows PC 표시
- [ ] device-id.txt 파일 생성 확인 (`C:\nac-agent\device-id.txt`)
- [ ] 에이전트 재시작 후 동일 device_id 유지

### 단말 제어

- [ ] Allow → 상태 `allowed`로 변경
- [ ] Block → 상태 `blocked`로 변경
- [ ] Quarantine → 상태 `quarantine`으로 변경
- [ ] 감사 로그에 각 변경 이벤트 기록

### 정책 관리

- [ ] 정책 생성 (POST /api/policies) 성공
- [ ] 정책 목록 조회 성공
- [ ] 정책 수정 (PUT /api/policies/:id) 성공
- [ ] 정책 삭제 (DELETE /api/policies/:id) 성공

### RADIUS 인증

- [ ] `radtest admin changeme localhost 0 radius-shared-secret` → Access-Accept
- [ ] 잘못된 비밀번호 → Access-Reject
- [ ] aaa 서비스 로그에 인증 이벤트 기록

### 대시보드 통계

- [ ] `/api/v1/stats` → 단말 수 카운트 정상
- [ ] Admin Console 차트에 현황 반영

---

## 자주 발생하는 문제 및 해결

| 증상 | 원인 | 해결 |
|------|------|------|
| Admin Console 접속 불가 | 방화벽 3000 포트 차단 | `ufw allow 3000/tcp` |
| 로그인 후 빈 화면 | api-gateway CORS 또는 proxy 오류 | `docker compose logs api-gateway` 확인 |
| 에이전트 "connection refused" | agent-gateway 미기동 또는 50051 차단 | `docker compose ps agent-gateway`, `ufw allow 50051/tcp` |
| endpoint-agent.exe 실행 오류 | Windows Defender 차단 | 바이러스 제외 목록에 추가 |
| RADIUS Access-Reject | `RADIUS_SECRET` 불일치 | `.env`의 `RADIUS_SECRET`과 radtest 옵션 일치 확인 |
| policy-manager 컨테이너 크래시 | DB 마이그레이션 실패 | `docker compose logs postgres` 확인 후 `docker compose restart policy-manager` |
| 크로스 컴파일 실패 | mingw 미설치 | `sudo apt-get install gcc-mingw-w64-x86-64` |

---

## 테스트 완료 후 종료

```bash
# 서비스 중지 (데이터 유지)
docker compose stop

# 서비스 + 볼륨 전체 삭제 (초기화)
docker compose down -v
```
