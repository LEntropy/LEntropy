-- 에이전트 기반 안정적 식별자: UUID device_id를 저장
-- MAC 주소가 바뀌어도(유동 MAC, 인터페이스 교체) 같은 단말로 추적 가능
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS agent_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoints_agent_id
    ON endpoints(agent_id) WHERE agent_id IS NOT NULL;
