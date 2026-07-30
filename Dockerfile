# 팀 결정: python:3.12-slim 베이스 (alpine 금지 — week0 회의록)
FROM python:3.12-slim

# uv — 의존성은 uv.lock 으로 고정 재현 (그라운드 룰: uv.lock 커밋)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

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

# SQLite 저장 경로 (compose 에서 볼륨 마운트)
ENV SU_DB_PATH=/data/supply_unchained.db
VOLUME ["/data"]

EXPOSE 8000
CMD ["uv", "run", "--no-sync", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
