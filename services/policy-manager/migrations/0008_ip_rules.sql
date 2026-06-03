-- IP 주소 직접 차단 규칙 테이블
-- MAC 기반 탐지 없이 IP를 직접 차단/격리 가능
CREATE TABLE ip_rules (
    id         UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_cidr    TEXT        NOT NULL UNIQUE, -- "192.168.0.5" 또는 "10.0.0.0/24"
    action     TEXT        NOT NULL DEFAULT 'block'
                           CHECK (action IN ('block', 'quarantine')),
    note       TEXT,
    enabled    BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ip_rules_enabled ON ip_rules (enabled);
