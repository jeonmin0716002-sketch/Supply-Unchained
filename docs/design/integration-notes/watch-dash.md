# watch-dash 통합 요청

## cli/su_scan.py (core-pipeline 소유)
`watch` 에 옵션 추가:
```python
ecosystems: str = typer.Option("pip", help="감시할 생태계(쉼표). 예: pip,npm,cargo"),
...
report = await run_cycle(..., ecosystems=[e.strip() for e in ecosystems.split(",") if e.strip()])
```
- 리포트: `report.by_ecosystem` (생태계별 scanned/flagged), 삭제 목록은 pip 외에는 `eco:name`.
- `crosscheck` 명령: `watcher.crosscheck.crosscheck(db, since, ecosystem=<id>, osv_ecosystem=<adapter.osv_ecosystem>)`.
- 큐 위험도 표시(`_render_cycle`)는 생태계를 접두로 붙이면 좋다.

## api/schemas.py / scan.py (core-pipeline)
- 감시기는 `ScanRequest` 가 생태계를 아직 모르면 `model_construct(ecosystem=<str>)` 로 만든다.
  통합 후 `req.ecosystem` 이 str 이든 Enum 이든 `run_scan` 이 받게 해야 한다.
- `run_scan` 결과 dict 에 `ecosystem` 키가 있어야 큐가 올바른 생태계로 기록된다.

## 미완 (한도로 중단)
Part 2(tools/eval_new_uploads.py, docs/eval/watch-new-uploads.md)는 하지 못했다.
