# Supply-Unchained — pip install 가로채기 (bash / zsh / Git Bash)
#
# 설치:
#     echo "source $(pwd)/tools/pip-guard.sh" >> ~/.bashrc
#     source tools/pip-guard.sh          # 현재 셸에 바로 적용
#
# 이후 `pip install requests` 를 치면 설치 전에 스캔이 돌고, warn 이면 y/N 를 묻는다.
# install 이 아닌 pip 명령(list·show·uninstall...)은 그대로 진짜 pip 으로 넘어간다.
#
# 해제:
#     unset -f pip
#
# SU_GUARD_HOME: 이 저장소 경로. 다른 디렉터리에서 pip 을 써도 스캐너를 찾을 수 있게
# 소싱 시점의 위치를 기억해 둔다.
SU_GUARD_HOME="${SU_GUARD_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)}"
export SU_GUARD_HOME

pip() {
  if [ "$1" != "install" ]; then
    command pip "$@"
    return
  fi
  shift
  # 진짜 pip 을 미리 찾아 넘긴다 — 스캐너는 저장소의 .venv 에서 돌지만, 설치는
  # 사용자가 지금 서 있는 환경에 들어가야 한다. 이걸 안 넘기면 스캐너의 venv 에 깔린다.
  local real_pip
  real_pip="$(command -v pip 2>/dev/null)"
  # VIRTUAL_ENV 를 가리는 이유는 pip-guard.ps1 의 같은 자리 주석 참고 — 스캐너 환경과
  # 설치 대상 환경이 다른 게 정상인데 uv 가 경고를 찍어 화면이 지저분해진다.
  ( cd "$SU_GUARD_HOME" && env -u VIRTUAL_ENV uv run python -m cli.su_scan guard --su-pip "$real_pip" -- "$@" )
}

# pip3 도 같은 경로를 타게 한다
pip3() { pip "$@"; }
