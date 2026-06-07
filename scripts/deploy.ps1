# NAC 서비스 크로스 컴파일 → Pi 배포 스크립트
# 사용법: .\scripts\deploy.ps1 <서비스명> [서비스명2 ...]
# 예시:   .\scripts\deploy.ps1 aaa
#         .\scripts\deploy.ps1 aaa policy-manager

param(
    [Parameter(Mandatory=$true, Position=0, ValueFromRemainingArguments=$true)]
    [string[]]$Services
)

$PI_HOST = "192.168.0.39"
$PI_USER = "philosophyz"
$PI_SSH  = "$PI_USER@$PI_HOST"
$TARGET  = "aarch64-unknown-linux-gnu"
$BIN_DIR = "target\$TARGET\release"

function Write-Step($msg) {
    Write-Host "`n==> $msg" -ForegroundColor Cyan
}
function Write-Ok($msg) {
    Write-Host "    [OK] $msg" -ForegroundColor Green
}
function Write-Fail($msg) {
    Write-Host "    [FAIL] $msg" -ForegroundColor Red
}

# ── 1. 크로스 컴파일 ─────────────────────────────────────────────────────────
foreach ($svc in $Services) {
    Write-Step "크로스 컴파일: $svc"
    cross build --release --target $TARGET -p $svc
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "$svc 빌드 실패 — 중단"
        exit 1
    }
    Write-Ok "$svc 빌드 완료 ($BIN_DIR\$svc)"
}

# ── 2. Pi로 전송 및 배포 ─────────────────────────────────────────────────────
foreach ($svc in $Services) {
    $bin = "$BIN_DIR\$svc"
    $container = "lentropy-$svc-1"

    Write-Step "배포: $svc → $container"

    # 실행 권한 부여
    icacls $bin /grant Everyone:RX | Out-Null

    # Pi로 전송
    Write-Host "    전송 중..." -NoNewline
    scp $bin "${PI_SSH}:/tmp/$svc"
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "SCP 실패"
        exit 1
    }
    Write-Ok "전송 완료"

    # 실행 권한 설정 + 컨테이너에 복사 + 재시작
    Write-Host "    Pi 적용 중..." -NoNewline
    ssh $PI_SSH "chmod +x /tmp/$svc && docker cp /tmp/$svc ${container}:/usr/local/bin/service && docker restart $container"
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Pi 배포 실패"
        exit 1
    }
    Write-Ok "$svc 재시작 완료"

    # 로그 5줄 출력
    Start-Sleep -Seconds 2
    Write-Host "`n    [로그 확인]" -ForegroundColor Yellow
    ssh $PI_SSH "docker logs --tail=5 $container 2>&1"
}

Write-Host "`n배포 완료!" -ForegroundColor Green
