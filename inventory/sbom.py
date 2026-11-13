"""SBOM 읽기(CycloneDX 1.4~1.6 · SPDX 2.3 JSON)와 쓰기(CycloneDX 1.5).

purl 은 어댑터의 ``purl_type`` 으로 생태계 id 에 되돌린다. 어댑터가 없는 생태계의 purl 은
조용히 버리지 않고 ``SbomRead.unsupported`` 에 남긴다 ("못 봤다"를 "없다"로 만들지 않는다).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, unquote

import ecosystems
from ecosystems.base import Dependency


@dataclass
class SbomRead:
    dependencies: list[Dependency] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)


def parse_purl(purl: str) -> tuple[str, str, str | None] | None:
    """``pkg:type/ns/name@version?q#sub`` → (type, name, version). Maven·npm 스코프·Go 경로는
    namespace 를 이름에 합친다 (maven ``group:artifact``, 나머지 ``ns/name``)."""
    if not purl.startswith("pkg:"):
        return None
    rest = purl[4:].split("#", 1)[0].split("?", 1)[0]
    version = None
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
        version = unquote(version) or None
    parts = [unquote(p) for p in rest.strip("/").split("/") if p]
    if len(parts) < 2:
        return None
    ptype, segs = parts[0].lower(), parts[1:]
    if ptype == "maven" and len(segs) >= 2:
        name = f"{'.'.join(segs[:-1])}:{segs[-1]}"
    else:
        name = "/".join(segs)
    return ptype, name, version


def _eco_by_purl_type() -> dict[str, ecosystems.Ecosystem]:
    return {e.purl_type: e for e in ecosystems.available()}


def _dep_from_purl(purl: str, source: str, out: SbomRead,
                   table: dict[str, ecosystems.Ecosystem]) -> None:
    parsed = parse_purl(purl)
    if parsed is None:
        out.unsupported.append(purl)
        return
    ptype, name, version = parsed
    eco = table.get(ptype)
    if eco is None:
        out.unsupported.append(purl)
        return
    out.dependencies.append(Dependency(eco.id, name, version, source=source, direct=None))


def read_sbom(text: str, source: str = "sbom") -> SbomRead:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"SBOM 이 JSON 이 아닙니다: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValueError("SBOM 최상위가 객체가 아닙니다")
    out, table = SbomRead(), _eco_by_purl_type()
    if doc.get("bomFormat") == "CycloneDX":
        def walk(components: list[Any]) -> None:
            for c in components or []:
                if isinstance(c, dict):
                    if c.get("purl"):
                        _dep_from_purl(str(c["purl"]), source, out, table)
                    walk(c.get("components") or [])
        walk(doc.get("components") or [])
    elif str(doc.get("spdxVersion", "")).startswith("SPDX-"):
        for pkg in doc.get("packages") or []:
            for ref in pkg.get("externalRefs") or []:
                if ref.get("referenceType") == "purl":
                    _dep_from_purl(str(ref.get("referenceLocator", "")), source, out, table)
    else:
        raise ValueError("CycloneDX 도 SPDX 도 아닙니다 (bomFormat/spdxVersion 없음)")
    return out


def _purl(dep: Dependency, table: dict[str, ecosystems.Ecosystem]) -> str:
    """purl 을 만든다. 어댑터가 없거나 버전이 없으면 일반 규칙으로 조립."""
    eco = table.get(dep.ecosystem)
    ptype = eco.purl_type if eco else dep.ecosystem
    name = dep.name
    if ptype == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        path = f"{quote(group, safe='.')}/{quote(artifact, safe='')}"
    else:
        path = "/".join(quote(p, safe="") for p in name.split("/"))
    base = f"pkg:{ptype}/{path}"
    return f"{base}@{quote(dep.version, safe='')}" if dep.version else base


def write_cyclonedx(deps: list[Dependency], results: dict[Any, dict] | None = None) -> dict:
    """CycloneDX 1.5. ``results`` 는 ``(ecosystem, name, version)`` → 행 dict
    (``verdict``·``findings``·``vulns[{id,severity,summary,fixed}]``). 없으면 목록만 쓴다."""
    table = {e.id: e for e in ecosystems.available()}
    components, vulns = [], []
    for dep in deps:
        ref = _purl(dep, table)
        comp: dict[str, Any] = {"type": "library", "bom-ref": ref, "name": dep.name, "purl": ref}
        if dep.version:
            comp["version"] = dep.version
        row = (results or {}).get((dep.ecosystem, dep.name, dep.version))
        if row:
            props = [{"name": "supply-unchained:verdict", "value": str(row.get("verdict", ""))}]
            props += [{"name": "supply-unchained:finding", "value": str(f)}
                      for f in row.get("findings") or []]
            comp["properties"] = props
            for v in row.get("vulns") or []:
                entry: dict[str, Any] = {
                    "bom-ref": f"{v['id']}@{ref}", "id": v["id"],
                    "source": {"name": "OSV",
                               "url": f"https://osv.dev/vulnerability/{quote(v['id'])}"},
                    "ratings": [{"severity": v.get("severity", "unknown")}],
                    "affects": [{"ref": ref}],
                }
                if v.get("summary"):
                    entry["description"] = v["summary"]
                if v.get("fixed"):
                    entry["recommendation"] = f"Upgrade to {v['fixed']}"
                vulns.append(entry)
        components.append(comp)
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": datetime.now(UTC).isoformat(),
                     "tools": {"components": [
                         {"type": "application", "name": "supply-unchained"}]}},
        "components": components,
    }
    if results is not None:
        bom["vulnerabilities"] = vulns
    return bom
