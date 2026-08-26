# KOSSA 2025 오픈소스 개발자대회 수상작 22개 분석

> 출처: [2025 오픈소스 개발자대회 우수작 정보집](https://www.kossa.kr/materials/2025/ossp/ebook/index.html) (부문·설명·소스코드 링크) + GitHub REST API 실측(★/Fork/기여자/커밋/CI/생성일). 조회 시각 2026-08-21.
> 목적: Supply-Unchained을 유사 대회에 출품할 경우의 경쟁력 진단 및 예상 등수 추정.

## 1. 수상작 22개 원본 데이터

이북에 오타·저해상도로 인해 잘못 읽힌 org명이 4건 있었고, GitHub 검색으로 재확인했다 (원문 표기 → 실제 리포).

| 원문 표기 | 실제 org/repo |
|---|---|
| GoldBunny/QA-Maker | `GolddBunny/QA-Maker` |
| Hyeri-hc/OSSDoctor | `Hyeri-hci/OSSDoctor` |
| investica-aiye/investica | `investica-aivle/investica` |
| JoJoonBaeSsa/Taint-Bomb | `JoJoonBalSsa/Taint-Bomb` |

### 전체 표 (★/Fork/기여자/커밋/CI/생성일)

| 수상 | 프로젝트 | 부문 | 분야 | ★ | Fork | 기여자 | 커밋 | CI | 리포 생성일 | 소스코드 |
|---|---|---|---|--:|--:|--:|--:|--:|---|---|
| 대상 | Mocka | 학생 | 자유(기타) | 2 | 0 | 2 | 384 | 6 | 2025-07-10 | github.com/yyytir777/Mocka |
| 대상 | Hot Updater | 일반 | 자유(모바일) | 1,677 | 171 | 64 | 1,138 | 10 | 2023-10-22 (기존 OSS) | github.com/gronxb/hot-updater |
| 금상 | QA Maker | 학생 | 자유(AI) | 3 | 6 | 3 | 527 | 0 | 2025-04-01 | github.com/GolddBunny/QA-Maker |
| 금상 | zephyr-rtos-lecture | 일반 | 자유(기타) | 10 | 3 | 1 | 1 | 0 | 2025-01-02 | github.com/tsnlab/zephyr-rtos-lecture (+ github.com/tsnlab/zephyr) |
| 은상 | OSSDoctor (ODOC) | 학생 | 자유(기타) | 0 | 0 | 3 | 487 | 0 | 2025-07-07 | github.com/Hyeri-hci/OSSDoctor |
| 은상 | itdoc | 일반 | 자유(기타) | 130 | 3 | 4 | 231 | 3 | 2025-02-22 | github.com/do-pa/itdoc |
| 동상 | mock-fox | 학생 | 자유(기타) | 1 | 0 | 2 | 56 | 1 | 2025-06-26 | github.com/The-Plain-OSS/mock-fox |
| 동상 | express-cargo | 일반 | 자유(기타) | 107 | 0 | 5 | 230 | 6 | 2025-06-11 | github.com/Beyond-Imagination/express-cargo |
| 동상 | spring-ai-playground | 일반 | 자유(AI) | 185 | 34 | 3 | 121 | 4 | 2025-01-04 | github.com/JM-Lab/spring-ai-playground |
| 동상 | langstar | 일반 | 자유(AI) | 11 | 0 | 6 | 174 | 0 | 2025-05-09 | github.com/SurvivorsStudio/langstar |
| 동상 | colbrush | 학생 | 사회문제형(생활) | 40 | 0 | 4 | 215 | 2 | 2025-07-31 | github.com/2025-OSDC/colbrush |
| 동상 | RAGIT | 학생 | 자유(AI) | 5 | 0 | 2 | 185 | 0 | 2025-05-03 | github.com/Gyu-Chul/RAGIT |
| 동상 | opendata-mcp | 일반 | 사회문제형(생활) | 11 | 4 | 2 | 30 | 0 | 2025-07-25 | github.com/ceami/opendata-mcp (+api,+web) |
| 동상 | stateful-migration-operator | 학생 | 자유(클라우드) | 3 | 3 | 1 | 40 | 3 | 2025-07-25 | github.com/lehuannhatrang/stateful-migration-operator |
| 동상 | AutoFineTuner | 학생 | 자유(AI) | 1 | 0 | 1 | 5 | 0 | 2025-08-20 | github.com/yoosung5480/AutoFineTuner |
| 동상 | investica | 일반 | 기업형(위튼테크놀로지스) | 0 | 2 | 6 | 290 | 0 | 2025-07-26 | github.com/investica-aivle/investica |
| 동상 | teleport-plugin-slack | 학생 | 기업형(에스코어) | 0 | 0 | 2 | 432 | 5 | 2025-07-03 | github.com/teletwoboy/teleport-plugin-slack-access-request |
| 장려상 | BrainTrace | 학생 | 자유(AI) | 4 | 3 | 6 | 1,285 | 1 | 2025-07-11 | github.com/Qubit02/BrainTrace |
| 장려상 | sage | 일반 | 자유(블록체인) | 3 | 1 | 4 | 154 | 6 | 2025-07-05 | github.com/SAGE-X-project/sage |
| 장려상 | Taint-Bomb | 일반 | 사회문제형(민간) | 7 | 1 | 52 | 1,411 | 0 | 2024-07-08 (기존 OSS) | github.com/JoJoonBalSsa/Taint-Bomb |
| 특별상 | AccessibilityFixer | 학생 | 사회문제형(생활) | 0 | 2 | 6 | 111 | 1 | 2025-08-06 | github.com/osdev-challenge/AccessibilityFixer |
| 격려상 | atio | 학생 | 자유(빅데이터) | 3 | 0 | 3 | 114 | 1 | 2025-07-18 | github.com/seojaeohcode/atio |

### 코호트 요약 통계 (22개, 중앙값)

| 지표 | 중앙값 | 비고 |
|---|--:|---|
| ★ | 3.5 | 4/22팀이 0★ — 별 자체는 당락을 크게 가르지 않음 |
| 커밋 수 | ~200 | 최솟값 1(zephyr-rtos-lecture, 실작업은 별도 zephyr 포크) ~ 최댓값 1,411(Taint-Bomb, 기존 OSS) |
| 기여자 수 | 3 | 1인~64인까지 편차 큼 |
| CI 워크플로 | 1 | 22팀 중 8팀은 CI 0개 |

Hot Updater(2023-10~)와 Taint-Bomb(2024-07~)은 대회 이전부터 운영되던 **기존 오픈소스 프로젝트가 그대로 출품된 사례**다. 나머지 20개는 리포 생성일이 대체로 2025-01~2025-08 사이로, 대회 제출 시점(2025년 하반기 추정) 기준 짧게는 2주, 길게는 8개월 준비 기간을 가졌다.

## 2. 티어별 프로필

| 티어 | 팀 수 | 제작 기간 패턴 | 대표 특징 |
|---|--:|---|---|
| 대상·금상 | 4 | 4~8개월, 또는 2년+ 기존 OSS | 압도적 외부 트래픽(Hot Updater ★1,677) 또는 Maven Central/SonarCloud 같은 실제 배포 인프라(Mocka) |
| 은상 | 2 | 1~6개월 | itdoc은 npm 배포 + 전용 도메인; OSSDoctor는 ★0이지만 커밋 487회의 PR 기반 개발 흔적 |
| 동상 | 11 (최다) | **1개월~3주가 다수** | ★0~185까지 편차 크지만, 공통적으로 LICENSE + README 배지 + 실배포(Docker Hub/npm 등) 보유 |
| 장려·특별·격려 | 5 | 1개월 내외, 또는 기존 OSS | 기술적으로 가장 정교한 SAGE도 이 구간 — 기술 깊이가 등수를 보장하지 않음을 보여주는 사례 |

## 3. 코드 퀄리티 실사 (README·구조 직접 확인, 6개 표본)

| 프로젝트 | 티어 | LICENSE | README 배지 | 실배포 | 문서 톤 |
|---|---|---|---|---|---|
| Mocka | 대상 | 있음 | SonarCloud(Bugs/Coverage/Quality Gate) 4종 | **Maven Central 패키지 3개 게시** | 이모지 0, 순수 프로즈+코드 |
| SAGE | 장려상 | LGPL-3.0 | Go/Solidity/Test/Security/Codecov 5종 | Ethereum/Kaia/Solana 멀티체인 실배포, RFC 9180·9421 구현, 스마트컨트랙트 테스트 202개 | 기술 문서체, 마케팅 카피 없음 |
| Taint-Bomb | 장려상 | 있음 | Release/Marketplace 다운로드·평점 | **JetBrains 마켓플레이스 정식 출시**, 실사용자 평점 존재 | 제품 소개 페이지 톤 |
| itdoc | 은상 | Apache-2.0 | CI/NPM/Node/License/Discord 5종 | npm 배포 + itdoc.kr 도메인 + 인터랙티브 플레이그라운드 | 담백, "테스트가 곧 문서"라는 컨셉을 그대로 증명 |
| teleport-plugin-slack | 동상 (★0) | Apache-2.0 | License/Made-by/Go 3종 | Docker Hub 이미지 + ArgoCD 설치 가이드 | 실용적, TOC+이모지 소량 |
| colbrush | 동상 | (미확인) | 없음 | npm(`colbrush`) 배포 | 기능 bullet에 이모지 소량, 코드 스니펫 위주 |

**공통 패턴**: 6개 전부 LICENSE와 실제 배포처(Maven Central / npm / Docker Hub / JetBrains Marketplace)를 갖추고 있다. ★0인 팀(OSSDoctor·teleport-plugin-slack·investica·AccessibilityFixer)도 존재하지만, 그 경우 대신 PR 기반 커밋 이력(OSSDoctor 487커밋)이나 실배포(teleport-plugin-slack)로 완성도를 증명한다.

**AI-generated 문체 특징 여부**: 6개 표본 중 이모지 섹션 헤더·mermaid 다이어그램 벽·"한 줄 포지셔닝" 식 마케팅 콜아웃·미검증 통계 인용표를 쓴 사례는 없었다. 전부 배지(실제 서비스와 연결) + 프로즈 + 코드 스니펫 위주의 담백한 구성이다.

## 4. Supply-Unchained과의 비교

| 지표 | Supply-Unchained | 수상작 중앙값/비교 |
|---|---|---|
| ★ | 0 | 중앙값 3.5 — 4/22팀도 0★, 치명적이지 않음 |
| 커밋 수 | 24 | 중앙값 200 — **가장 큰 격차, 중앙값의 12%** |
| 기여자 수 | 3 | 중앙값 3 — 동일 |
| CI 워크플로 | 2 (그중 1개는 악성 패키지를 실제로 차단하는지 매 PR마다 검증하는 게이트) | 중앙값 1 — 상회 |
| 테스트 | 134개 전부 통과, 엔진 776줄 : 테스트 1,388줄 (1.8:1) | 표본 6개 중 가장 테스트 밀도가 높은 축(SAGE의 202개 컨트랙트 테스트와 비견) |
| 제작 기간 | 2026-07-15 착수, ~5주 (진행 중) | 동상 코호트(11팀) 다수가 3주~1개월로 정확히 겹침 |
| LICENSE / README 배지 / 실배포 | **전부 없음** | 확인한 6개 전부 보유 — 가장 뚜렷한 격차 |
| 동일 니치 경쟁작 | 0/22 (pip/PyPI 설치 시점 공급망 차단을 다루는 출품작 없음) | 강점 |

## 5. 예상 등수 (정량 신호 기반 추정)

공식 심사 기준(발표·시연·문서 완성도 가중치)은 비공개이므로, 이 문서에서 확인 가능한 정량 신호(제작 기간·커밋·CI·테스트·패키징)만으로 추정한 확률이다. **현재 상태 그대로 제출한다고 가정한 값**이며, 제출 전 개선 여부에 따라 크게 이동한다.

| 등급 | 추정 확률 | 근거 |
|---|--:|---|
| 대상·금상 | ~5% | 2년+ 기존 OSS(Hot Updater) 또는 4~8개월 준비 + Maven Central급 배포 인프라(Mocka)가 필요 — 5주 차 프로젝트로는 도달 어려움 |
| 은상 | ~10% | itdoc 수준의 npm 배포·전용 도메인, 또는 OSSDoctor 수준의 487커밋 PR 이력 중 하나는 필요 — 현재 둘 다 부족 |
| 동상 | ~38% (최유력) | 제작 기간·팀 규모·CI 구성이 동상 코호트 중앙값과 가장 근접. teleport-plugin-slack(★0)처럼 "실동작 증명"만으로 동상을 받은 선례 존재 — Supply-Unchained의 CI 게이트가 이 조건 충족 |
| 장려·특별·격려상 | ~27% | 커밋 24회(코호트 최하위권), LICENSE·배지·실배포 부재가 겹치면 SAGE처럼 기술은 좋아도 동상 미만으로 밀릴 위험 |
| 비수상(우수작 탈락) | ~20% | 위 격차가 개선되지 않고 제출 시점까지 "Phase 1 진행 중" 상태가 유지될 경우 |

## 6. 등급을 올리기 위한 우선순위 조치

1. **LICENSE 추가 + README 배지 3~5종.** 확인한 6개 수상작 전부(★0짜리 포함)가 갖춘 최소 조건. 30분~반나절 작업.
2. **실배포 하나.** TestPyPI/PyPI 패키지 게시 또는 Docker Hub 이미지 — teleport-plugin-slack이 ★0으로 동상을 받은 근거와 동일한 신호.
3. **커밋 이력을 동상 중앙값(200회) 방향으로 두껍게.** 기능·테스트·수정 단위로 잘게 커밋. opendata-mcp(30회)·stateful-migration-operator(40회)는 동상 안에서도 최하위권이니 최소 그 이상 목표.
4. **README의 "Phase 1 진행 중" 배너를 제출 전 실제로 해소.** CLI/프록시·대시보드·Bandit 연동 완료.
5. **README 문체 정리.** 이모지 헤더·mermaid 다이어그램·마케팅 콜아웃 축소, Sonatype/ReversingLabs/Verizon DBIR 인용 통계는 실제 출처 링크를 걸거나 검증 안 되면 삭제 — 수상작 6개는 전부 담백한 기술 문서체였고, "문서만 화려하고 실물은 Phase 1"인 불일치가 가장 위험한 인상을 준다.
6. **차별화를 발표 전면에.** pip 설치 시점 공급망 사전 차단은 22개 수상작 어디에도 없는 니치. 다만 SAGE 사례가 보여주듯 기술적 정교함 자체가 등수를 보장하지 않으므로, "왜 필요한가"를 기술 깊이보다 먼저 설명할 것.

## 부록: 조회 방법

```bash
gh api repos/<org>/<repo> --jq '{stars, forks, language, open_issues, pushed_at, size, created_at}'
gh api repos/<org>/<repo>/contributors?per_page=100 --jq 'length'
gh api repos/<org>/<repo>/readme -H "Accept: application/vnd.github.raw"
```
