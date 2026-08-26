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
    # 스캐너는 저장소의 .venv 에서 돌아야 하고, 설치는 사용자가 서 있는 환경으로 가야 한다.
    # 그 둘이 다른 게 정상인데, VIRTUAL_ENV 가 켜져 있으면 uv 가 "프로젝트 환경과 다르다"고
    # 경고를 찍는다 — 동작에는 영향이 없고 화면만 지저분해지므로 이 호출 동안만 가린다.
    # 설치 대상은 아래 --su-pip 로 명시해 넘기므로 이걸 가려도 엉뚱한 곳에 깔리지 않는다.
    $savedVenv = $env:VIRTUAL_ENV
    $env:VIRTUAL_ENV = $null
    try {
        uv run python -m cli.su_scan guard --su-pip $realPip -- @rest
    } finally {
        $env:VIRTUAL_ENV = $savedVenv
        Pop-Location
    }
}

Set-Alias -Name pip3 -Value pip -Scope Global
