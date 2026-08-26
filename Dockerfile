# 팀 결정: python:3.12-slim 베이스 (alpine 금지 — week0 회의록)
#
# 다이제스트 고정: 공급망 스캐너가 정작 자기 베이스 이미지는 움직이는 태그로 받아오면
# uv.lock 을 커밋하는 그라운드 룰과 앞뒤가 맞지 않는다. 태그는 사람이 읽기 위해 남기고,
# 실제로 강제되는 건 뒤의 @sha256 다 (태그가 다른 이미지를 가리키게 바뀌면 빌드가 실패).
#
# 갱신 방법 — 새 다이제스트를 확인하고 아래 두 줄을 바꾼다:
#   docker buildx imagetools inspect python:3.12-slim
#   docker buildx imagetools inspect ghcr.io/astral-sh/uv:latest
# 마지막 확인: 2026-08-26
FROM python:3.12-slim@sha256:7a8b475003c4fe15a2cd4e55e5cfc2f3560bdc9333d624f24cdd6d4340fd7a17

# uv — 의존성은 uv.lock 으로 고정 재현 (그라운드 룰: uv.lock 커밋)
COPY --from=ghcr.io/astral-sh/uv:latest@sha256:88bc6eb1ccd4b82efd0e1b530caffabddf50dc2bf612e66c14ea25b8ee8a4d3d /uv /usr/local/bin/uv

WORKDIR /app

# 의존성 레이어 분리: 코드만 바뀌면 이 레이어는 캐시 재사용
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# 애플리케이션 코드
COPY api/ api/
COPY common/ common/
COPY engine/ engine/
COPY scoring/ scoring/
COPY cli/ cli/
COPY dashboard/ dashboard/

# --- Secure Design: 비루트 실행 ---
# 이 프로세스가 하는 일이 곧 이유다 — 신뢰할 수 없는 sdist/wheel 을 받아서 풀고, 그 위에서
# 정적분석(bandit 포함)을 돌린다. 아카이브 파싱이나 분석기 쪽에 구멍이 하나 생기는 순간
# 그게 컨테이너 root 권한이 되면 안 된다. 코드와 venv 는 root 소유로 남겨(앱이 자기 자신을
# 덮어쓸 수 없게) 읽기 전용으로 쓰고, 쓰기가 필요한 건 /data 와 홈뿐이다.
RUN useradd --create-home --uid 10001 app \
    && mkdir -p /data \
    && chown app:app /data
USER app

# SQLite 저장 경로 (compose 에서 볼륨 마운트)
# 주의: 호스트 디렉터리를 bind mount 하면 소유자가 호스트 것으로 덮여 uid 10001 이 못 쓸 수
# 있다. compose 의 named volume(su-data)은 이미지의 소유권을 물려받으므로 그대로 동작한다.
ENV SU_DB_PATH=/data/supply_unchained.db
VOLUME ["/data"]

EXPOSE 8000
CMD ["uv", "run", "--no-sync", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
