# AI Scanner

AI 기반 웹 취약점 자동진단 문서 세트입니다. 이 디렉터리는 통합 프로젝트 소개가 아니라, AI가 웹 애플리케이션을 대상으로 정찰, 퍼징, 검증, 분류, 보고서화까지 수행하는 진단 절차 자체를 설명하기 위한 공간입니다.

현재 구성은 실제 실행 코드 저장소라기보다, AI 진단 에이전트가 어떤 기준으로 움직이고 어떤 산출물을 남겨야 하는지 정의한 운영 문서에 가깝습니다. 따라서 이 브랜치 또는 디렉터리를 볼 때는 "서비스 소개"보다 "AI 진단 체계"를 읽는 관점이 맞습니다.

이 AI 자동진단 체계는 Claude Code를 중심으로 설계한 워크플로우를 바탕으로 정리되었습니다. 단순히 AI에게 취약점을 찾아보라고 지시하는 방식이 아니라, Claude Code가 Phase별 역할을 나눠 정찰, 벡터별 탐지, 실증 검증, 위험도 분류, 최종 보고서 작성까지 순차적으로 수행하도록 문서화한 구조입니다. 따라서 이 README와 하위 Phase 문서들은 "Claude Code로 어떻게 웹 취약점 진단을 운영할 것인가"를 설명하는 작업 기준서에 가깝습니다.

---

## 개요

AI Scanner는 웹 애플리케이션 보안 진단을 단계별로 자동화하기 위한 문서 기반 프레임워크입니다. 대상 시스템의 엔드포인트를 수집하고, 공격 벡터별로 프로브를 전송하고, 의심 신호를 재검증한 뒤, 확정 취약점을 위험도와 표준 분류 체계에 맞춰 보고서로 정리하는 흐름을 기준으로 설계되어 있습니다.

이 구조는 단순한 취약점 스크립트 모음과 다릅니다. 정찰 단계에서 수집한 정보를 기반으로 다음 단계의 테스트 우선순위를 정하고, 퍼징 단계에서는 모든 엔드포인트와 공격 벡터를 가능한 한 빠짐없이 훑고, 검증 단계에서는 실제 HTTP 응답과 권한 매트릭스를 바탕으로 오탐과 확정 취약점을 구분합니다. 마지막으로 분류 단계에서는 CVSS, CWE, OWASP, SK 진단 항목 기준으로 위험도를 표준화하고, 보고서 단계에서 실무자가 바로 전달 가능한 Markdown 산출물로 정리합니다.

즉 이 디렉터리의 목적은 "AI가 어떻게 생각해야 하는가"를 정하는 데 있습니다. 어떤 단계에서 무엇을 해야 하는지, 무엇을 해서는 안 되는지, 어떤 형식으로 기록해야 하는지를 먼저 고정함으로써, 진단 품질과 결과물 형식을 일정하게 유지하려는 방향입니다.

---

## 목적

- 웹 취약점 진단 절차를 Phase 단위로 표준화
- AI가 임의 판단이 아니라 체크리스트와 근거 기반으로 진단하도록 강제
- 후보 취약점과 확정 취약점을 분리해 오탐을 줄이는 구조 마련
- 최종 결과를 SK 진단 항목, OWASP, CWE, CVSS 체계와 연결
- 실습, 재현, 문서화가 가능한 Markdown 기반 산출물 생성

---

## 진단 대상 범위

AI Scanner는 주로 웹 애플리케이션과 API를 대상으로 합니다. 특히 아래와 같은 항목을 주요 범위로 다룹니다.

- 인증 및 인가
- 관리자 기능 노출
- IDOR 및 Broken Access Control
- XSS, CSRF, SQL Injection
- Path Traversal, File Upload, Command Injection
- SSRF, XXE, Open Redirect
- 비즈니스 로직 결함 및 Race Condition
- 서버 정보 노출, 보안 헤더, 쿠키/토큰 설정

또한 문서 기준은 SK 진단 항목 체계를 따릅니다. 실제 가이드에서는 XSS, Injection, IDOR, 악성 파일 업로드, 패스워드 정책, 권한 상승 및 ACL 미흡 같은 항목별 판단 기준과 대응 방안이 정의되어 있으며, AI Scanner는 이런 가이드를 자동 진단 흐름으로 연결하는 역할을 합니다.

---

## 전체 진단 흐름

| Phase | 문서 | 역할 |
|------|------|------|
| Phase 1 | `Tool_Phase_1.md` | 정찰, 엔드포인트 수집, 환경 추론, 우선순위 설정 |
| Phase 2 | `Tool_Phase_2.md` | 공격 벡터별 전수 탐침, 후보 취약점 수집 |
| Phase 3 | `Tool_Phase_3.md` | 인증/인가 및 논리 취약점 심층 검증 |
| Phase 4 | `Tool_Phase_4.md` | CVSS, CWE, OWASP, SK 항목 기준 위험도 분류 |
| Phase 5 | `Tool_Phase_5.md` | 최종 보고서 및 독립 취약점 보고서 작성 |

이 다섯 단계는 앞 단계 결과를 다음 단계 입력으로 사용하는 구조입니다. 따라서 설계상으로는 Recon 없이 Fuzzing만 수행하거나, 검증 없이 바로 보고서를 만드는 흐름을 허용하지 않습니다.

---

## Phase별 설명

### Phase 1. Recon & OSINT

첫 단계에서는 대상 시스템의 공격면을 최대한 넓게 파악합니다. JS 번들, Source Map, 노출된 경로, 관리자 페이지, 숨겨진 API, 서버 헤더, CORS, SSL/TLS 정책, 인증 구조를 분석해 이후 단계의 우선순위를 정합니다. 이 단계의 핵심은 취약점 확정이 아니라 "어디를 먼저 봐야 하는가"를 구조화하는 것입니다.

### Phase 2. Advanced Fuzzing & Scanning

두 번째 단계에서는 Phase 1에서 수집한 엔드포인트에 대해 공격 벡터별 탐침을 전수 수행합니다. XSS, CSRF, SQL Injection, 파라미터 조작, XXE, SSRF, 비즈니스 로직, 악성 파일 업로드, Open Redirect, Command Injection, Path Traversal 같은 벡터를 기준으로 신호를 수집합니다. 이 단계에서는 확정 판정보다 후보군 확보가 중요합니다.

### Phase 3. Deep Logic & Auth Verification

세 번째 단계에서는 후보군을 실제 취약점으로 확정할 수 있는지 재현 중심으로 검증합니다. ADMIN, MANAGER, STAFF, USER, 비인증 상태를 포함한 토큰 매트릭스를 구성해 접근제어, 인증 우회, IDOR, BAC, Race Condition을 교차 검증합니다. 이 단계에서 실증된 결과만 확정 취약점으로 취급합니다.

### Phase 4. Triage & Threat Modeling

네 번째 단계에서는 확정 취약점에 대해 CVSS v3.1 벡터를 산정하고, OWASP Top 10 2021 및 CWE ID와 연결합니다. 오탐과 방어 확인 항목도 함께 정리해 결과의 신뢰도를 높입니다. 즉, 이 단계는 발견보다 분류와 우선순위화가 중심입니다.

### Phase 5. Advanced Reporting

마지막 단계에서는 앞선 결과를 통합해 최종 보고서를 작성합니다. SK 28개 항목 기준 통합 보고서와, 각 취약점별 독립 보고서를 별도로 만드는 구조를 취합니다. 이 방식은 실무자용 종합 보고와 취약점 단건 보고를 분리해 전달하기 좋다는 장점이 있습니다.

---

## 산출물 구조

AI Scanner 문서 체계가 전제하는 대표 산출물 구조는 아래와 같습니다.

- `candidates/`: 퍼징 단계에서 수집된 의심 신호
- `vulnerabilities/`: 검증을 거쳐 확정된 취약점
- `mitigated/`: 방어가 확인된 항목
- `logs/`: reasoning log, 분류 로그, 최종 인덱스 등 중간 결과
- `reports/`: 취약점 단건 보고서
- `FINAL_REPORT.md`: 통합 최종 보고서

이 구조의 핵심은 후보군과 확정 취약점을 분리하는 점입니다. 자동진단에서 가장 큰 문제 중 하나가 오탐인데, 이 디렉터리의 설계는 이를 줄이기 위해 `탐지`와 `확정`을 분리해 두고 있습니다.

---

## 작성 원칙

각 Phase 문서는 공통적으로 몇 가지 원칙을 강하게 요구합니다.

- 실제 통신과 응답을 기준으로 판단
- 뇌피셜이나 프레임워크에 대한 막연한 신뢰 금지
- reasoning log를 통해 판단 근거 기록
- 정해진 단계 외 작업 금지
- 오탐보다 미탐을 줄이기 위한 넓은 탐지 후 엄격한 검증
- 최종 보고서는 Markdown 기반으로 일관되게 작성

즉, AI Scanner는 단순 자동화보다도 "검증 가능한 자동화"를 지향합니다.

---

## 적용 기준

이 문서 세트는 SK 진단 항목 체계와 OWASP, CWE, CVSS를 함께 사용합니다.

- SK 진단 항목: 국내 진단 기준에 맞춘 점검 체계
- OWASP Top 10: 웹 취약점 분류 기준
- CWE: 취약점 유형 식별 체계
- CVSS v3.1: 위험도 점수화 기준

이 조합을 통해 진단 결과를 단순 발견 목록이 아니라, 재현 가능하고 설명 가능한 보안 산출물로 바꾸는 것이 목표입니다.

---

## 포함 문서

- [Tool_Phase_1.md](/Users/user/Desktop/desktop/CODE/SK_Rookies_File/project/최종%20프로젝트/Final_PJT/AI_Scanner/Tool_Phase_1.md)
- [Tool_Phase_2.md](/Users/user/Desktop/desktop/CODE/SK_Rookies_File/project/최종%20프로젝트/Final_PJT/AI_Scanner/Tool_Phase_2.md)
- [Tool_Phase_3.md](/Users/user/Desktop/desktop/CODE/SK_Rookies_File/project/최종%20프로젝트/Final_PJT/AI_Scanner/Tool_Phase_3.md)
- [Tool_Phase_4.md](/Users/user/Desktop/desktop/CODE/SK_Rookies_File/project/최종%20프로젝트/Final_PJT/AI_Scanner/Tool_Phase_4.md)
- [Tool_Phase_5.md](/Users/user/Desktop/desktop/CODE/SK_Rookies_File/project/최종%20프로젝트/Final_PJT/AI_Scanner/Tool_Phase_5.md)

---

## 참고

이 디렉터리는 AI 자동진단 자체를 설명하는 문서 공간입니다. 통합 프로젝트 전체 설명, 취약 웹사이트와 안전 웹사이트 비교, 브랜치 가이드는 별도 README에서 다루고, 여기서는 AI 진단 절차와 산출물 기준만 유지하는 편이 맞습니다.
