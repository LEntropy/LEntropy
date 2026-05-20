-- 개발용 시드 데이터

INSERT INTO policies (name, description, priority, conditions, action, vlan_id)
VALUES
    ('quarantine-unknown',  '미등록 단말 격리',        10,  '[]', 'quarantine', 99),
    ('allow-corp-devices',  '기업 등록 단말 허용',      50,  '[]', 'allow',      10),
    ('deny-blacklist',      '블랙리스트 단말 차단',       1,  '[]', 'deny',       NULL);
