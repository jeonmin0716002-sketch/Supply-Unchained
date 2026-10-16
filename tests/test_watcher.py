"""PyPI 감시기 — 피드 파싱, 주기 로직(중복·재시도·큐 기준), 검토 큐 API. 전부 오프라인."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.storage import ScanStore
from common.pypi import PackageNotFound
from watcher.feed import parse_feed
from watcher.runner import is_suspicious, run_cycle

NEW_PACKAGES_XML = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <title>PyPI newest packages</title><link>https://pypi.org/</link>
  <item><title>reqeusts added to PyPI</title>
    <link>https://pypi.org/project/reqeusts/</link></item>
  <item><title>shap-cuda added to PyPI</title>
    <link>https://pypi.org/project/shap-cuda/</link></item>
  <item><title>reqeusts added to PyPI</title>
    <link>https://pypi.org/project/reqeusts/</link></item>
</channel></rss>"""

UPDATES_XML = """<rss><channel><link>https://pypi.org/</link>
  <item><title>pyannote-metrics 4.2.0</title>
    <link>https://pypi.org/project/pyannote-metrics/4.2.0/</link></item>
  <item><title>cowork-server 0.26.10.16.1rc4</title>
    <link>https://pypi.org/project/cowork-server/0.26.10.16.1rc4/</link></item>
  <item><title>evil</title><link>https://pypi.org/project/a;rm -rf/1.0/</link></item>
</channel></rss>"""


# ── 피드 파싱 ─────────────────────────────────────────────────────

def test_parse_new_packages_feed_has_no_version_and_dedupes():
    assert parse_feed(NEW_PACKAGES_XML) == [("reqeusts", None), ("shap-cuda", None)]


def test_parse_updates_feed_reads_version_and_ignores_channel_link():
    assert parse_feed(UPDATES_XML) == [
        ("pyannote-metrics", "4.2.0"),
        ("cowork-server", "0.26.10.16.1rc4"),
    ]  # 셸 메타문자가 섞인 링크는 패턴 자체에 걸리지 않는다


# ── 주기 로직 ─────────────────────────────────────────────────────

class _Result:
    def __init__(self, record: dict):
        self._record = record

    def model_dump(self, mode: str = "json") -> dict:
        return dict(self._record)


def _record(name, version, verdict="safe", score=5, scan_id=1, typo=0.1):
    return {
        "scan_id": scan_id, "name": name, "version": version, "verdict": verdict,
        "risk_score": score, "verdict_reasons": ["test"],
        "risk_signals": {"is_new_account": True, "typosquat_score": typo},
    }


class _Fake:
    """피드·버전 조회·스캔을 대신하는 가짜. 호출 기록을 남긴다."""

    def __init__(self, items, verdicts=None, fail=(), feed_errors=()):
        self.items = items
        self.verdicts = verdicts or {}
        self.fail = set(fail)
        self.feed_errors = list(feed_errors)
        self.resolved: list[str] = []
        self.scanned: list[str] = []

    async def fetch(self, http):
        return list(self.items), list(self.feed_errors)

    async def resolve(self, name, http):
        self.resolved.append(name)
        if name == "gone":
            raise PackageNotFound("removed")
        return "1.0.0"

    async def scan(self, req, *, http, store):
        spec = f"{req.name}=={req.version}"
        self.scanned.append(spec)
        if spec in self.fail:
            raise RuntimeError("network down")
        verdict, score, typo = self.verdicts.get(req.name, ("safe", 5, 0.1))
        return _Result(_record(req.name, req.version, verdict, score, len(self.scanned), typo))


@pytest.fixture()
async def store(tmp_path):
    s = ScanStore(str(tmp_path / "w.db"))
    await s.init()
    return s


async def _cycle(fake, store, **kw):
    return await run_cycle(
        http=None, store=store, scan=fake.scan, fetch=fake.fetch, resolve=fake.resolve, **kw
    )


def test_is_suspicious_keeps_block_and_lookalike_names():
    assert is_suspicious(_record("x", "1", "block", 10))
    assert is_suspicious(_record("reqeusts", "1", "warn", 55, typo=0.88))


def test_is_suspicious_ignores_cve_only_and_new_package_baseline():
    # 알려진 CVE 만 있는 정상 패키지
    assert not is_suspicious(_record("x", "1", "warn", 20))
    # 실측 오탐 패턴 — 신규 계정 25 + 배포 버스트 15 = 40, 이름은 평범 (2026-10-16 PyPI 60건)
    assert not is_suspicious(_record("sh-agent", "0.2.0", "warn", 40, typo=0.53))


async def test_cycle_scans_new_releases_and_queues_only_suspicious(store):
    fake = _Fake(
        [("reqeusts", None), ("pyannote-metrics", "4.2.0"), ("oldlib", "2.0")],
        verdicts={"reqeusts": ("block", 90, 0.88), "oldlib": ("warn", 20, 0.1)},
    )
    report = await _cycle(fake, store)

    assert sorted(fake.scanned) == ["oldlib==2.0", "pyannote-metrics==4.2.0", "reqeusts==1.0.0"]
    assert [r["name"] for r in report.flagged] == ["reqeusts"]
    queue = await store.queue("new")
    assert [(q["name"], q["version"], q["verdict"]) for q in queue] == [
        ("reqeusts", "1.0.0", "block")
    ]


async def test_second_cycle_skips_seen_releases_and_known_names(store):
    fake = _Fake([("reqeusts", None), ("pyannote-metrics", "4.2.0")])
    await _cycle(fake, store)
    fake.scanned.clear()
    fake.resolved.clear()

    report = await _cycle(fake, store)
    assert fake.scanned == []
    assert fake.resolved == []  # 이미 본 이름은 최신 버전 조회도 건너뛴다
    assert report.scanned == 0


async def test_failed_scan_is_retried_next_cycle(store):
    fake = _Fake([("flaky", "1.0")], fail={"flaky==1.0"})
    report = await _cycle(fake, store)
    assert report.failed and report.scanned == 0

    fake.fail.clear()
    report = await _cycle(fake, store)
    assert report.scanned == 1


async def test_unresolvable_and_invalid_items_are_reported(store):
    fake = _Fake([("gone", None), ("ok", "1..0")])
    report = await _cycle(fake, store)
    assert [spec for spec, _ in report.failed] == ["gone"]
    assert report.skipped_invalid == ["ok==1..0"]
    assert fake.scanned == []


async def test_max_scans_defers_the_rest(store):
    fake = _Fake([(f"pkg{i}", "1.0") for i in range(5)])
    report = await _cycle(fake, store, max_scans=2)
    assert report.scanned == 2 and report.deferred == 3

    report = await _cycle(fake, store, max_scans=10)
    assert report.scanned == 3  # 미뤄진 것들이 다음 주기에 처리된다


async def test_feed_errors_are_surfaced_not_swallowed(store):
    fake = _Fake([], feed_errors=["https://pypi.org/rss/packages.xml: 503"])
    report = await _cycle(fake, store)
    assert report.feed_errors == ["https://pypi.org/rss/packages.xml: 503"]


# ── 검토 큐 API ───────────────────────────────────────────────────

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SU_DB_PATH", str(tmp_path / "api.db"))
    with TestClient(app) as c:
        yield c


def _seed(client, *records):
    import asyncio

    store = client.app.state.store
    for r in records:
        asyncio.run(store.enqueue(r, "2026-10-16T00:00:00+00:00"))


def test_queue_list_filters_by_status_and_patch_keeps_note(client):
    _seed(client, _record("evil", "1.0", "block", 90, 1), _record("meh", "2.0", "warn", 55, 2))
    rows = client.get("/api/v1/watch/queue", params={"status": "new"}).json()
    assert [r["name"] for r in rows] == ["meh", "evil"]  # 최신 우선

    evil = rows[1]["id"]
    r = client.patch(
        f"/api/v1/watch/queue/{evil}", json={"status": "malicious", "note": "pth 드로퍼"}
    )
    assert r.status_code == 200 and r.json()["note"] == "pth 드로퍼"
    r = client.patch(f"/api/v1/watch/queue/{evil}", json={"status": "reported"})
    assert r.json()["status"] == "reported" and r.json()["note"] == "pth 드로퍼"

    assert [r["name"] for r in client.get("/api/v1/watch/queue?status=new").json()] == ["meh"]
    assert len(client.get("/api/v1/watch/queue").json()) == 2


def test_queue_patch_rejects_unknown_status_and_missing_item(client):
    _seed(client, _record("evil", "1.0", "block", 90, 1))
    item = client.get("/api/v1/watch/queue").json()[0]["id"]
    bad = client.patch(f"/api/v1/watch/queue/{item}", json={"status": "deleted"})
    assert bad.status_code == 422
    assert client.patch("/api/v1/watch/queue/9999", json={"status": "malicious"}).status_code == 404
