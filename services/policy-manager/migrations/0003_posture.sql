-- Phase 4: 무결성 검사 스키마

ALTER TABLE endpoints
    ADD COLUMN IF NOT EXISTS is_compliant        BOOLEAN,
    ADD COLUMN IF NOT EXISTS last_posture_check  TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS posture_reports (
    id                  BIGSERIAL   PRIMARY KEY,
    endpoint_id         UUID        NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    os                  TEXT,
    os_version          TEXT,
    installed_sw        JSONB       NOT NULL DEFAULT '[]',
    missing_patches     JSONB       NOT NULL DEFAULT '[]',
    usb_enabled         BOOLEAN     NOT NULL DEFAULT false,
    bluetooth_enabled   BOOLEAN     NOT NULL DEFAULT false,
    folder_sharing      BOOLEAN     NOT NULL DEFAULT false,
    is_compliant        BOOLEAN,
    reported_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_posture_endpoint    ON posture_reports(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_posture_reported_at ON posture_reports(reported_at DESC);
