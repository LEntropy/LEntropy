-- NAC 로컬 유저 테이블 (LDAP 미사용 환경용)
CREATE TABLE nac_users (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    username      TEXT        NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    role          TEXT        NOT NULL DEFAULT 'user'
                              CHECK (role IN ('admin', 'user')),
    enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_nac_users_username ON nac_users (username);

CREATE TRIGGER trg_nac_users_updated_at
    BEFORE UPDATE ON nac_users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
