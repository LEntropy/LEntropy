-- 시드 정책 조건 수정: 빈 조건(전체 매칭) 정책이 우선순위 충돌 방지
-- deny-blacklist: 기본 비활성화 (MAC 목록 없이 전체 차단 방지)
UPDATE policies SET enabled = false WHERE name = 'deny-blacklist';

-- quarantine-unknown: 컴플라이언스 미준수 단말 격리
UPDATE policies
SET conditions = '[{"type":"compliant","required":false}]'
WHERE name = 'quarantine-unknown';

-- allow-corp-devices: Windows 기기 허용 (예시)
UPDATE policies
SET conditions = '[{"type":"os_family","value":"Windows"}]'
WHERE name = 'allow-corp-devices';
