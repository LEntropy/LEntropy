-- 단말 테이블에 posture 정보 비정규화 컬럼 추가
-- 정책 평가 시 N+1 조회 없이 조건 매칭 가능하도록

ALTER TABLE endpoints
    ADD COLUMN IF NOT EXISTS posture_sw               JSONB,
    ADD COLUMN IF NOT EXISTS posture_missing_patches  INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS posture_usb_enabled      BOOLEAN,
    ADD COLUMN IF NOT EXISTS posture_bluetooth        BOOLEAN,
    ADD COLUMN IF NOT EXISTS posture_folder_sharing   BOOLEAN,
    ADD COLUMN IF NOT EXISTS posture_os_version       TEXT;
