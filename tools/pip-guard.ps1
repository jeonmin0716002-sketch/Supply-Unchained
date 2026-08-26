# Supply-Unchained — pip install 가로채기 (PowerShell)
#
# 설치:
#     notepad $PROFILE            # 없으면: New-Item -ItemType File -Force $PROFILE
#     # 아래 한 줄을 추가 (경로는 이 저장소 위치로)
#     . C:\Supply_unchained\tools\pip-guard.ps1
#
#     . .\tools\pip-guard.ps1     # 현재 세션에 바로 적용
#
# 이후 `pip install requests` 를 치면 설치 전에 스캔이 돌고, warn 이면 y/N 를 묻는다.
# install 이 아닌 pip 명령(list·show·uninstall...)은 그대로 진짜 pip 으로 넘어간다.
#
# 해제:
#     Remove-Item Function:\pip

# 이 스크립트가 있는 저장소 경로를 기억 — 다른 디렉터리에서도 스캐너를 찾을 수 있게.
$env:SU_GUARD_HOME = Split-Path -Parent $PSScriptRoot

function pip {
    # 진짜 pip 을 먼저 찾아둔다. 함수 이름이 pip 이라 Get-Command pip 은 자기 자신을
    # 잡으므로 -CommandType Application 으로 실행 파일만 고른다.
    $realPip = (Get-Command pip -CommandType Application -ErrorAction SilentlyContinue |
                Select-Object -First 1).Source

    if ($args.Count -eq 0 -or $args[0] -ne 'install') {
        if ($realPip) { & $realPip @args } else { Write-Error 'pip 을 찾을 수 없습니다' }
        return
    }

    $rest = @($args[1..($args.Count - 1)])
    Push-Location $env:SU_GUARD_HOME
    try {
        # 설치는 사용자가 지금 서 있는 환경에 들어가야 하므로 진짜 pip 경로를 넘긴다.
        # 안 넘기면 스캐너가 도는 저장소 .venv 에 깔린다.
        uv run python -m cli.su_scan guard --su-pip $realPip -- @rest
    } finally {
        Pop-Location
    }
}

Set-Alias -Name pip3 -Value pip -Scope Global
