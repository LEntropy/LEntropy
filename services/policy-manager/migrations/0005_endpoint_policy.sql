-- 단말별 정책 수동 할당 및 정책 예외 지원
ALTER TABLE endpoints
    ADD COLUMN IF NOT EXISTS assigned_policy_id UUID REFERENCES policies(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS policy_exempt BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN endpoints.assigned_policy_id IS '수동 할당된 정책 UUID — NULL이면 자동 우선순위 평가';
COMMENT ON COLUMN endpoints.policy_exempt IS 'true이면 정책 평가에서 제외 (수동 관리 단말)';
