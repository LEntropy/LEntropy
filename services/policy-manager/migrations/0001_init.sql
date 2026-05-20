-- NAC Platform 초기 스키마
-- Phase 1: 단말 탐지 및 자산 인벤토리

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── 단말(Endpoint) 인벤토리 ──────────────────────────────────────────────
CREATE TABLE endpoints (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    mac_address   MACADDR     NOT NULL UNIQUE,
    ip_address    INET,
    hostname      TEXT,
    -- OS/디바이스 핑거프린팅
    os_family     TEXT,        -- "Windows", "Linux", "iOS", "Android", "Unknown"
    os_version    TEXT,
    device_type   TEXT,        -- "Workstation", "Mobile", "IoT", "Printer", "Unknown"
    vendor        TEXT,        -- OUI 기반 제조사
    -- 네트워크 위치
    vlan_id       SMALLINT,
    switch_port   TEXT,
    interface     TEXT,        -- 탐지된 네트워크 인터페이스
    -- 인증
    username      TEXT,
    -- 접근 상태
    status        TEXT        NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('allowed','quarantined','denied','pending')),
    -- 타임스탬프
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_endpoints_mac       ON endpoints (mac_address);
CREATE INDEX idx_endpoints_ip        ON endpoints (ip_address);
CREATE INDEX idx_endpoints_status    ON endpoints (status);
CREATE INDEX idx_endpoints_last_seen ON endpoints (last_seen DESC);

-- ── 세션 (인증/인가 상태 추적) ───────────────────────────────────────────
CREATE TABLE sessions (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    endpoint_id   UUID        NOT NULL REFERENCES endpoints (id) ON DELETE CASCADE,
    username      TEXT,
    auth_method   TEXT,        -- "captive_portal", "802.1x", "mac_bypass"
    state         TEXT        NOT NULL DEFAULT 'detecting'
                              CHECK (state IN ('detecting','authenticating',
                                               'checking_integrity','active',
                                               'quarantined','terminated')),
    vlan_id       SMALLINT,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at      TIMESTAMPTZ,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_endpoint ON sessions (endpoint_id);
CREATE INDEX idx_sessions_state    ON sessions (state);

-- ── 정책 (Policy) ────────────────────────────────────────────────────────
CREATE TABLE policies (
    id          UUID    PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT    NOT NULL UNIQUE,
    description TEXT,
    priority    INT     NOT NULL DEFAULT 100,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    -- JSON 형태의 조건/액션 (Phase 2에서 룰 엔진 연동)
    conditions  JSONB   NOT NULL DEFAULT '[]',
    action      TEXT    NOT NULL DEFAULT 'allow'
                        CHECK (action IN ('allow','quarantine','deny')),
    vlan_id     SMALLINT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO policies (name, description, priority, conditions, action)
VALUES ('default-allow', '기본 허용 정책 (최저 우선순위)', 9999, '[]', 'allow');

-- ── 감사 로그 ────────────────────────────────────────────────────────────
CREATE TABLE audit_log (
    id          BIGSERIAL   PRIMARY KEY,
    event_type  TEXT        NOT NULL,  -- "endpoint_detected", "access_granted", etc.
    endpoint_id UUID        REFERENCES endpoints (id) ON DELETE SET NULL,
    session_id  UUID        REFERENCES sessions (id)  ON DELETE SET NULL,
    actor       TEXT,                  -- 사용자 또는 시스템 컴포넌트
    detail      JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_endpoint   ON audit_log (endpoint_id);
CREATE INDEX idx_audit_log_event_type ON audit_log (event_type);
CREATE INDEX idx_audit_log_created_at ON audit_log (created_at DESC);

-- ── updated_at 자동 갱신 트리거 ──────────────────────────────────────────
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_endpoints_updated_at
    BEFORE UPDATE ON endpoints
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_sessions_updated_at
    BEFORE UPDATE ON sessions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_policies_updated_at
    BEFORE UPDATE ON policies
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
