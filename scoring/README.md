# scoring — 데이터·위험도 스코어링 레이어 (탐지 레이어 ③)

패키지 **코드가 아니라 정황(메타데이터)**을 보고 0~100 위험도 점수를 매기는 모듈.
CVE 매칭(①)·정적분석(②)이 못 잡는, "아직 알려지지 않은 신종 악성 패키지"를
확률적으로 걸러내는 것이 목표.

> 규칙 기반 가중치 방식. 학습 데이터·모델 불필요. 점수 1점 1점이 사람이 읽을 수 있는
> 근거 문장으로 매핑됨(발표에서 "왜 차단했는지" 설명 가능한 것이 강점).

## 파일 구조

| 파일 | 역할 |
|---|---|
| `collector.py` | PyPI JSON API에서 메타데이터 수집 (**네트워크 I/O 전담**) |
| `features.py` | 메타데이터 → 위험 신호 5종 추출 (**순수 로직, 오프라인 테스트 가능**) |
| `scorer.py` | 신호에 가중치 합산 → `(RiskSignals, score)` — **API 진입점** |
| `popular_packages.py` | typosquat 비교용 인기 패키지 이름 목록 |

I/O(collector)와 판정 로직(features/scorer)을 분리해서, 스코어링 로직은 네트워크 없이
합성 데이터로 단위 테스트 가능하게 설계함.

## 위험 신호와 가중치 (초안 — 검증 샘플로 튜닝 예정)

| 신호 | 근거 | 가중치 |
|---|---|:---:|
| `is_new_account` | 패키지가 최근 생성됨 (계정 나이 프록시) | +25 |
| `typosquat_score` | 인기 패키지와 이름 유사 (0~1, 유사도에 비례) | +30 |
| `has_install_script` | 설치 시 실행되는 setup.py 존재 | +20 |
| `release_burst` | 짧은 시간에 다수 버전 몰림 (전체 대비 비율 기준) | +15 |
| (download anomaly) | 신생인데 다운로드 급증 | +10 (**미구현 hook**) |

**특수 규칙:** 유사도 ≥ 0.90인 **확실한 typosquat**은 다른 신호가 없어도 위험도를
warn 수준(40)으로 끌어올림. 가장 신뢰도 높은 악성 지표가 경고조차 못 뜨는 것을 방지.
(검증 결과 정상 패키지는 최고 0.73이라 오탐 위험 0.)

### 튜닝 검증 결과 (2026-07-24, 실제 PyPI 데이터)

| 항목 | 결과 |
|---|---|
| 정상 인기 패키지 28개 | 오탐 warn/block **0건** |
| 정상 변형 패키지 12개 (`requests-toolbelt` 등) | typosquat 오탐 **0건** (최고 0.73) |
| 알려진 typosquat 24개 | 탐지 **23/24** (floor 0.80) |
| typosquat floor | 스윕으로 **0.80 최적 확인** (완전탐지 유지하는 최고값) |

> 임계값·가중치는 검증 샘플로 계속 튜닝 예정. 회귀 테스트: `tests/test_scoring.py` (15케이스).

### 재현율(recall) 측정 — 실제 악성 패키지 11,545개 (OSSF malicious-packages, 2026-07-24)

이름 신호(typosquat)를 실제 악성 PyPI 패키지 전체에 돌린 결과:

| floor | 악성 재현율 | 정상 변형 오탐 |
|:---:|:---:|:---:|
| 0.70 | 9.9% | **3/20 (오탐 발생)** |
| 0.75 | 7.7% | 0/20 |
| **0.80** | **6.5%** | **0/20** |
| 0.90 | 3.9% | 0/20 |

**핵심 발견:** typosquat 이름 신호의 재현율은 **약 6.5%에 불과**. 이유는 실제 악성
패키지의 ~90%가 typosquat가 **아니기** 때문 — 랜덤 이름 드로퍼(`1337test`, `18923aa`),
dependency-confusion(내부 패키지명 흉내) 등이 대부분. 잡아낸 6.5%는 전부 진짜 lookalike
(`bbeautifulsoup`, `requestlib`, `python-dateutil2` 등)라 **정밀도는 높지만 범위가 좁은 신호**.

> 시사점: typosquat는 스코어러의 **하나의 입력**일 뿐, 나머지는 메타데이터 신호
> (install_script·new·burst) + 정적분석/CVE 레이어가 담당해야 함 → **멀티레이어 설계의 근거**.
> floor는 정밀도/재현율 양쪽 실측상 **0.80이 안전한 선택**(0.75로 낮추면 +1.2%p 재현율이나
> 정상 변형과의 여유가 0.02로 얇아짐).
>
### install_script 재현율 — 실제 malware 아카이브 150개 (DataDog dataset, 2026-07-24)

실제 악성 패키지 아카이브(암호화 zip, 메모리에서 목록만 검사)를 분석:

| 측정 | 악성 | 정상(참고) |
|---|:---:|:---:|
| setup.py 존재 (install_script 신호) | **94.0%** | ~36% |
| typosquat ≥0.80 | 5.3% | 0% |

**핵심:** install-time malware의 전달 수단이 `setup.py`라 실측 94%가 보유. 가중치 설계
검증됨 — `신규계정(25) + install_script(20) = 45 → warn`이 "갓 올라온 패키지가 설치 시
코드 실행"이라는 malware 시그니처를 정확히 잡음. 동시에 block(70) 미만이라 setup.py 가진
정상 신규 패키지(~36%)를 하드 차단하지 않음(계산된 균형; block엔 typosquat/정적분석 확증 필요).

> 주의: 오프라인 측정은 재현율을 **과소평가**함 — 핵심 공동신호 `is_new_account`는 업로드
> 날짜가 필요한데 삭제된 패키지라 측정 불가. 현실의 신선한 malware는 대부분 "신규"라
> new+install=45로 걸림.
>
> **갭(future work):** setup.py 없는 6%는 `pyproject.toml` PEP 517 빌드 훅 등 사용 →
> 단순 pyproject 탐지는 정상도 대부분 써서 오탐 폭증 → 빌드 백엔드 악용 탐지는 정적분석 엔진 영역.

## API 연동

`scorer.score_package(req)`가 `api/routers/scan.py`의 `_mock_risk_layer`를 대체함.
반환 타입은 계약과 동일한 `(RiskSignals, int)`. 라우터에서 `await`로 호출:

```python
from scoring.scorer import score_package
signals, risk_score = await score_package(req)
```

## 실행 / 테스트

```bash
# 의존성 (아직 프로젝트 pyproject.toml 없음 — 팀 세팅되면 uv add로 등록 필요)
uv add httpx

# API 데모 (레포 루트에서)
uvicorn api.main:app --reload
# http://localhost:8000/docs 에서 requests / reqeusts 등으로 테스트
```

## ⚠️ 알려진 한계 (발표 때 솔직하게 밝힐 것)

- **`is_new_account`는 프록시**: PyPI JSON API는 관리자 계정 생성일을 제공하지 않음.
  대신 "패키지 자체가 최근 생성됨"으로 근사. 정확히 하려면 관리자 프로필 페이지 스크래핑 필요.
- **다운로드 수 기반 신호 미구현**: PyPI JSON API가 다운로드 수를 더 이상 제공하지 않음.
  pypistats.org / BigQuery 연동은 future work.
- **`has_install_script`는 존재 여부만 판단**: setup.py가 실제로 악성인지(내용 분석)는
  정적분석 엔진(②, 민규 파트) 담당. 이 레이어는 "설치 시 실행 코드가 있다"는 사실만 표시.
- **삭제된 악성 패키지**: 탐지되면 PyPI에서 삭제되므로 메타데이터 조회 시 404.
  이 경우에도 이름 기반 typosquat 점수는 계속 동작함.
