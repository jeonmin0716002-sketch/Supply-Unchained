"""npm 규칙 실측 — 실제 악성 npm 패키지 탐지율과 인기 패키지 오탐률.

탐지율: DataDog `malicious-software-packages-dataset` (Apache-2.0) 의 samples/npm.
샘플은 비밀번호 ``infected`` 로 암호화된 zip 이고, 안에 풀린 타르볼(``.../package/...``)과
레지스트리 메타데이터(``package_info-*.json``)가 있다. 메타데이터는 타르볼에 없던 파일이라
분석에서 뺀다 — 넣으면 packument 의 scripts 문자열이 규칙에 걸려 탐지율이 부풀려진다.

**실행하지 않는다.** zip 안의 파일을 메모리에서만 읽어 ``ecosystems.npm.rules.analyze_tree``
를 MemoryTree 로 돌린다. 디스크에 풀지 않는 이유는 tools/eval_malware_dataset.py 와 같다
(백신이 읽기를 막아 "탐지 없음"으로 집계된다).

오탐률: 인기 패키지(``ecosystems/data/popular/npm.txt`` 또는 ``--list``) 최신 버전 타르볼을
받아 같은 규칙을 돌린다. HIGH 가 하나라도 나오면 차단(= 오탐).

    uv run python tools/eval_npm.py malware --n 300 --seed 42 --out npm-tuned.json
    uv run python tools/eval_npm.py malware --n 300 --seed 7 --exclude-from npm-tuned.json
    uv run python tools/eval_npm.py benign --n 300 --out npm-benign.json

튜닝(규칙을 고친 근거)에 쓴 세트의 수치는 참고용이다. held-out(튜닝 세트를 뺀 새 샘플)이
실제 탐지율이다.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import math
import os
import random
import sys
import tarfile
import tempfile
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.archive import is_safe_member_name
from ecosystems.npm.registry import fetch_project
from ecosystems.npm.rules import analyze_tree
from engine.rules.base import MemoryTree

REPO = "DataDog/malicious-software-packages-dataset"
RAW = f"https://raw.githubusercontent.com/{REPO}/main/samples/npm"
PASSWORD = b"infected"
MAX_SAMPLE_BYTES = 100 * 1024 * 1024
MAX_TARBALL_BYTES = 60 * 1024 * 1024
_TEXT = (".js", ".cjs", ".mjs", ".json", ".gyp", ".sh", ".ts", ".npmrc", ".py", ".bat",
         ".ps1", ".cmd")
POPULAR = Path(__file__).resolve().parents[1] / "ecosystems" / "data" / "popular" / "npm.txt"


def _gh_get(client: httpx.Client, url: str) -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    resp = client.get(url, headers=headers)
    resp.raise_for_status()
    return resp.json()


def list_samples(client: httpx.Client, kind: str) -> list[str]:
    listing = _gh_get(client, f"https://api.github.com/repos/{REPO}/contents/samples/npm")
    sha = next(x["sha"] for x in listing if x["name"] == kind)
    tree = _gh_get(client, f"https://api.github.com/repos/{REPO}/git/trees/{sha}?recursive=1")
    if tree.get("truncated"):
        print("warning: GitHub tree listing truncated", file=sys.stderr)
    return sorted(x["path"] for x in tree["tree"]
                  if x["type"] == "blob" and x["path"].endswith(".zip"))


def pick(paths: list[str], n: int, seed: int) -> list[str]:
    """패키지당 한 버전, seed 고정 무작위 n 개 (eval_malware_dataset.pick 과 같은 방식)."""
    by_pkg: dict[str, list[str]] = {}
    for p in paths:
        by_pkg.setdefault(p.split("/")[0], []).append(p)
    rng = random.Random(seed)
    chosen = [rng.choice(sorted(v)) for _, v in sorted(by_pkg.items())]
    rng.shuffle(chosen)
    return sorted(chosen[:n])


def _is_text(name: str) -> bool:
    low = name.lower()
    return low.endswith(_TEXT) or "." not in PurePosixPath(low).name


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _tar_members(data: bytes, prefix: str, out: dict[str, str]) -> None:
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for m in tf:
            if not (m.isreg() and is_safe_member_name(m.name) and _is_text(m.name)):
                continue
            total += m.size
            if total > MAX_SAMPLE_BYTES:
                break
            f = tf.extractfile(m)
            if f is not None:
                out[f"{prefix}{m.name}"] = _decode(f.read())


def read_sample(zip_path: Path) -> dict[str, str]:
    """암호화 zip → {타르볼 안 경로: 내용}. ``package_info-*.json`` 은 뺀다."""
    files: dict[str, str] = {}
    with zipfile.ZipFile(zip_path) as zf:
        total = 0
        for info in zf.infolist():
            if info.is_dir() or not is_safe_member_name(info.filename):
                continue
            total += info.file_size
            if total > MAX_SAMPLE_BYTES:
                raise ValueError("sample too large")
            name = PurePosixPath(info.filename).name
            if name.startswith("package_info-"):
                continue
            low = info.filename.lower()
            if low.endswith((".tgz", ".tar.gz")):
                _tar_members(zf.read(info, pwd=PASSWORD), info.filename + ".d/", files)
            elif _is_text(info.filename):
                files[info.filename] = _decode(zf.read(info, pwd=PASSWORD))
    return files


def _summ(findings) -> dict:
    high = sorted({f.rule for f in findings if f.severity.value in ("high", "critical")})
    med = sorted({f.rule for f in findings if f.severity.value == "medium"})
    return {"high_rules": high, "medium_rules": med, "blocked": bool(high), "warned": bool(med)}


def evaluate_one(client: httpx.Client, rel: str, kind: str, cache: Path) -> dict:
    result: dict = {"sample": rel, "name": rel.split("/")[0]}
    zip_path = cache / kind / rel
    try:
        if not zip_path.exists():
            zip_path.parent.mkdir(parents=True, exist_ok=True)
            resp = client.get(f"{RAW}/{kind}/{rel}")
            resp.raise_for_status()
            zip_path.write_bytes(resp.content)
    except httpx.HTTPError as exc:
        return {**result, "status": "download_failed", "error": str(exc)[:200]}
    try:
        files = read_sample(zip_path)
    except (ValueError, zipfile.BadZipFile, RuntimeError, OSError, tarfile.TarError) as exc:
        return {**result, "status": "unreadable", "error": str(exc)[:200]}
    findings = analyze_tree(MemoryTree(files))
    result.update(status="ok", **_summ(findings))
    has_code = any(f.endswith((".js", ".cjs", ".mjs")) for f in files)
    result["has_js"] = has_code
    if not result["blocked"]:
        result["files"] = sorted(files)[:30]
        result["findings"] = [f"{f.rule}:{f.severity.value}:{f.location}" for f in findings][:10]
    else:
        result["evidence"] = [f"{f.rule}@{f.location}: {(f.detail or '')[:160]}"
                              for f in findings if f.severity.value == "high"][:3]
    return result


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    if n == 0:
        return [0.0, 0.0]
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return [round(max(0.0, centre - half), 3), round(min(1.0, centre + half), 3)]


def _year(sample: str) -> str:
    name = sample.rsplit("/", 1)[-1]
    return name[:4] if name[:4].isdigit() else "unknown"


def summarize_malware(results: list[dict]) -> dict:
    ok = [r for r in results if r["status"] == "ok"]
    code = [r for r in ok if r["has_js"] or r["high_rules"] or r["medium_rules"]]
    blocked = sum(r["blocked"] for r in ok)
    by_year: dict[str, list[int]] = {}
    for r in ok:
        y = by_year.setdefault(_year(r["sample"]), [0, 0])
        y[0] += r["blocked"]
        y[1] += 1
    return {
        "samples": len(results),
        "analyzed": len(ok),
        "unreadable": sum(r["status"] == "unreadable" for r in results),
        "download_failed": sum(r["status"] == "download_failed" for r in results),
        "blocked": blocked,
        "block_recall": round(blocked / (len(ok) or 1), 3),
        "block_recall_ci95": wilson(blocked, len(ok)),
        "warn_or_block": sum(r["blocked"] or r["warned"] for r in ok),
        "no_js_files": len(ok) - len(code),
        "block_recall_samples_with_code": round(
            sum(r["blocked"] for r in code) / (len(code) or 1), 3),
        "block_recall_by_year": {y: f"{b}/{t}" for y, (b, t) in sorted(by_year.items())},
        "high_rule_counts": dict(Counter(x for r in ok for x in r["high_rules"])),
        "nothing_found": sum(not r["high_rules"] and not r["medium_rules"] for r in ok),
    }


def run_malware(args: argparse.Namespace) -> dict:
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        paths = list_samples(client, args.kind)
        excluded = {r["sample"].split("/")[0] for f in args.exclude_from
                    for r in json.loads(f.read_text(encoding="utf-8"))["results"]}
        paths = [p for p in paths if p.split("/")[0] not in excluded]
        chosen = paths if args.all_versions else pick(paths, args.n, args.seed)
        results = []
        for i, rel in enumerate(chosen, 1):
            results.append(evaluate_one(client, rel, args.kind, args.cache))
            if i % 25 == 0:
                print(f"  {i}/{len(chosen)}", file=sys.stderr)
    return {"mode": "malware", "kind": args.kind, "seed": args.seed,
            "excluded_packages": len(excluded), "summary": summarize_malware(results),
            "results": results}


# ── 오탐률 ────────────────────────────────────────────────────────

async def _benign_one(name: str, http: httpx.AsyncClient, sem: asyncio.Semaphore) -> dict:
    async with sem:
        try:
            project = await fetch_project(name, client=http)
            version = project.latest
            rel = project.release(version) if version else None
            if not rel or not rel.artifacts:
                return {"name": name, "status": "error", "error": "no tarball"}
            resp = await http.get(rel.artifacts[0].url)
            resp.raise_for_status()
            if len(resp.content) > MAX_TARBALL_BYTES:
                return {"name": name, "status": "error", "error": "tarball too large"}
            files: dict[str, str] = {}
            _tar_members(resp.content, "", files)
        except Exception as exc:
            return {"name": name, "status": "error", "error": f"{type(exc).__name__}: {exc}"[:200]}
    findings = await asyncio.to_thread(analyze_tree, MemoryTree(files))
    out = {"name": name, "version": version, "status": "ok", **_summ(findings)}
    out["high"] = [f"{f.rule}@{f.location}: {(f.detail or '')[:200]}"
                   for f in findings if f.severity.value == "high"]
    out["medium"] = [f"{f.rule}@{f.location}" for f in findings if f.severity.value == "medium"][:5]
    return out


async def _benign(names: list[str], concurrency: int) -> list[dict]:
    async with httpx.AsyncClient(timeout=120, follow_redirects=True) as http:
        sem = asyncio.Semaphore(concurrency)
        return await asyncio.gather(*(_benign_one(n, http, sem) for n in names))


def run_benign(args: argparse.Namespace) -> dict:
    src = args.list or POPULAR
    names = [s for line in src.read_text(encoding="utf-8").splitlines()
             if (s := line.split("#", 1)[0].strip())][: args.n]
    results = asyncio.run(_benign(names, args.concurrency))
    ok = [r for r in results if r["status"] == "ok"]
    blocked = sum(r["blocked"] for r in ok)
    return {"mode": "benign", "list": str(src), "summary": {
        "packages": len(results), "analyzed": len(ok), "errors": len(results) - len(ok),
        "blocked": blocked, "false_positive_rate": round(blocked / (len(ok) or 1), 4),
        "false_positive_ci95": wilson(blocked, len(ok)),
        "warned": sum(r["warned"] and not r["blocked"] for r in ok),
        "high_rule_counts": dict(Counter(x for r in ok for x in r["high_rules"])),
        "medium_rule_counts": dict(Counter(x for r in ok for x in r["medium_rules"])),
        "blocked_packages": [r["name"] for r in ok if r["blocked"]],
    }, "results": results}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="mode", required=True)
    m = sub.add_parser("malware")
    m.add_argument("--kind", default="malicious_intent",
                   choices=["malicious_intent", "compromised_lib"])
    m.add_argument("--n", type=int, default=300)
    m.add_argument("--seed", type=int, default=42)
    m.add_argument("--exclude-from", type=Path, action="append", default=[])
    m.add_argument("--all-versions", action="store_true")
    m.add_argument("--cache", type=Path,
                   default=Path(tempfile.gettempdir()) / "su-npm-malware-cache")
    b = sub.add_parser("benign")
    b.add_argument("--n", type=int, default=300)
    b.add_argument("--list", type=Path, default=None)
    b.add_argument("--concurrency", type=int, default=8)
    for p in (m, b):
        p.add_argument("--out", type=Path, default=Path("npm-eval.json"))
    args = ap.parse_args()
    data = run_malware(args) if args.mode == "malware" else run_benign(args)
    args.out.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(data["summary"], ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
