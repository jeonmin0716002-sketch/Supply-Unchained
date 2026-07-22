# 📋 Week 0 회의록 — Supply-Unchained

- **일시:** 2026-07-22 (화) / 디스코드
- **참석:** 전민규(PL), 문승준, 김재웅
- **목표:** 스코프 최종 확정 + API 스키마 합의 + 각자 Phase 1 착수 지점 정하기

>각자 파트
🛡 전민규 — PL + 보안 코어 엔진

CVE/OSV 매칭 (OSV.dev API 연동)
정적분석 (Bandit 기반 + .pth/install-hook 커스텀 규칙)
종합 판정 로직 + 커스텀 규칙 CWE 매핑

📊 문승준 — 데이터·위험도 스코어링

PyPI 메타데이터 수집
위험 신호 정의 (신규 계정, typosquat, install script 등)
규칙 기반 위험도 스코어링 (스코어링 방식 설계는 승준 위임)

🔧 김재웅 — API·클라이언트 (풀스택)

FastAPI 통합 (/scan 엔드포인트)
CLI/프록시 (pip index-url 가로채기)
SBOM 대시보드 + Docker·배포
OSV/CVE·Bandit 결과의 CWE 파싱

연결 지점: 너(취약점+악성패턴) + 승준(위험도 점수) → 재웅이 API 응답 하나로 통합

---

## 1. 스코프 최종 확정 (도장만)

- [x] 대상: **pip 생태계** (설계는 npm 등 확장 가능하게)
- [x] 탐지: **CVE/OSV 매칭 + 정적분석 + 규칙 기반 위험도 스코어링**
- [x] 동적분석/샌드박스: **이번 MVP 제외 → Future Work**
- [ ] 세 명 전원 동의: ____

---

## 2. ⭐ API 응답 스키마 합의 (오늘 최우선)

> 이거 확정돼야 세 파트 병렬 개발 시작 가능. 시간 대부분 여기 투자.

**엔드포인트:** `POST /api/v1/scan`

```jsonc
// Request
{ "ecosystem": "pip", "name": "____", "version": "____" }

// Response (초안 — 필드 확정하기)
{
  "verdict": "safe | warn | block",
  "risk_score": 0,              // 0-100
  "vulnerabilities": [ { "source": "OSV", "id": "", "severity": "" } ],
  "static_findings": [ { "rule": "", "cwe": "", "severity": "", "location": "" } ],
  "risk_signals": { }
}
```

**결정할 것:**
- [ ] verdict 3단계(safe/warn/block) 유지? or 다르게: ____
- [ ] risk_score 범위 0~100 확정? ____
- [ ] CWE 필드 위치 = `static_findings[].cwe` 로 통일? ____
- [ ] 각 필드 최종 이름/구조: ____

**CWE 태깅 역할 경계 (확인):**
- OSV/CVE·Bandit 결과의 CWE 파싱 → **재웅** (API에서)
- 커스텀 규칙(.pth 등)의 CWE 매핑 → **민규** (엔진에서)

---

## 3. 기술 세팅 통일

- [x] Python: **3.12**
- [x] 의존성: **uv** (`uv.lock` 반드시 커밋)
- [x] Docker 베이스: **python:3.12-slim** (alpine 금지)
- [x] 취약점 소스: **OSV.dev 메인** (NVD는 나중에)
- [ ] `.gitignore`에 `.env`, `.venv/` 등록 확인: ____
- [ ] 정적분석 Bandit 사용 방식 (라이브러리 import / CLI 호출 / 룰 참고): ____

**그라운드 룰:**
- [ ] 브랜치 전략: `main`(보호) ← `feat/<파트>-<기능>` PR? ____
- [ ] 코드 리뷰 방식: ____
- [ ] 이슈 트래킹: GitHub Issues? ____

---

## 4. Phase 1 각자 착수 지점 (2주: 7/22~8/5)

> 1주차 목표 = 바이브 코딩으로 내파트 다만들어보기 일단. 이후에 pr후 통합



- [ ] 각자 1주차 목표 동의: ____

---

## 5. 일정 마일스톤

| 마일스톤 | 날짜 |
|---|---|
| Phase 1 시작 | 7/22 |
| **중간 점검 (디코)** | **7/29** |
| Phase 1 마감 | 8/5 |
| 통합(Phase 2) 마감 | 8/15 |
| 발표 준비(Phase 3) | ~8/27 |
| **제출 마감** | **8/27** |

- [ ] 다음 회의 일정: ____

---

## 6. 행정 체크

- [ ] 요강 재확인 담당: ____
  - [ ] 제출물 = 코드만? 발표자료 포함?
  - [ ] 오픈소스 라이선스 명시 필수 조건 있는지
- [ ] 데모 시나리오 방향 (레이어별 1개씩):
  - ① CVE 매칭: 구버전 취약 패키지 설치 시도
  - ② 정적분석: 악성 install script 샘플 차단
  - ③ 스코어링: typosquat 이름 패키지 위험도

---

