# 프로젝트 통합 소개 및 브랜치 가이드 — VCE / VulnScanner

- **프로젝트명**: 클라우드 구축을 통한 취약점 진단 및 모의해킹 프로젝트
- **작성일**: 2026-04-14
- **Main 브랜치 역할**: 전체 프로젝트 구조와 세부 브랜치를 설명하는 통합 README
- **구성 브랜치**: `secure-web` / `vul-web` / `auto-script`

---

## 브랜치 바로가기

- [취약한 웹 소스코드 (`vul-web`)](https://github.com/khsqowp/SK_Rookies_FinalPJT/tree/vul-web)
- [안전한 웹 소스코드 (`secure-web`)](https://github.com/khsqowp/SK_Rookies_FinalPJT/tree/secure-web)
- [자동화 스크립트 소스코드 (`auto-script`)](https://github.com/khsqowp/SK_Rookies_FinalPJT/tree/auto-script)

---

## 개요

이 프로젝트는 하나의 결과물만 설명하는 저장소가 아니라, 취약한 웹 서비스의 구현, 취약점 분석과 이행 조치, 그리고 취약점 진단 자동화 도구까지 하나의 흐름으로 묶어 설명하는 통합형 프로젝트입니다. 즉, "취약한 서비스가 어떻게 구성되었는가", "어떤 취약점이 있었는가", "그 취약점을 어떻게 줄였는가", "이 과정을 자동화 도구 관점에서는 어떻게 확장할 수 있는가"를 함께 보여주는 구조입니다.

전체 흐름은 세 개의 브랜치로 나뉩니다. `vul-web`은 취약점 진단과 모의해킹 실습을 위해 만든 이행 전 취약 웹사이트 브랜치입니다. `secure-web`은 같은 서비스 구조를 바탕으로 취약점을 조치하고 보안 설정을 강화한 이행 후 안전 웹사이트 브랜치입니다. `auto-script`는 OS, 웹서버, DBMS, 클라우드 환경을 대상으로 진단 항목을 자동화하는 취약점 진단 스크립트 및 GUI 도구 브랜치입니다.

따라서 `main` 브랜치는 실제 개발이 이뤄지는 작업 브랜치라기보다, 세 브랜치의 역할과 관계를 설명하는 통합 안내 브랜치로 보는 것이 맞습니다. 취약 웹사이트와 안전 웹사이트를 비교해보려면 `vul-web`과 `secure-web`을 보면 되고, 자동 진단 도구를 확인하려면 `auto-script`를 보면 됩니다.

---

## 1. 프로젝트 구성

| 브랜치 | 역할 | 설명 |
|------|------|------|
| `vul-web` | 이행 전 취약 웹사이트 | 보안 진단 및 모의해킹 실습을 위한 취약한 가상자산 웹 서비스 |
| `secure-web` | 이행 후 안전 웹사이트 | 취약점 조치, 권한 분리, 입력 검증, 파일 통제, 정보 노출 차단 등을 반영한 개선 버전 |
| `auto-script` | 자동 진단 스크립트 | OS, WebServer, DBMS, Cloud 환경의 취약점 진단을 자동화하는 도구 |

---

## 2. 브랜치별 설명

### `vul-web` — 이행 전 취약 웹사이트

`vul-web` 브랜치는 취약점 진단과 모의해킹 실습을 위한 교육용 가상자산 거래소 서비스입니다. 거래소, 은행, 관리자 기능이 포함되어 있으며, 보안 학습을 위해 일부 취약한 구현이나 미흡한 방어가 남아 있는 상태를 기준으로 사용됩니다. 이 브랜치는 "어떤 취약점이 존재할 수 있는가"를 직접 분석하고 검증하는 출발점 역할을 합니다.

이 브랜치의 목적은 실제 서비스 운영이 아니라, 취약점 진단 교육용 환경을 제공하는 것입니다. 따라서 실서비스 수준의 보안을 보장하지 않으며, 일부 기능은 의도적으로 취약하거나 미완성된 방어 상태를 포함할 수 있습니다.

주요 관찰 대상:

- 인증 및 인가 미흡
- 관리자 기능 노출 가능성
- 입력값 검증 부족
- 파일 업로드 취약점 가능성
- XSS, CSRF, 정보 노출 가능성
- 세션 및 토큰 처리 취약성

### `secure-web` — 이행 후 안전 웹사이트

`secure-web` 브랜치는 `vul-web`을 기반으로 취약점 조치와 보안 구조 개선을 적용한 이행 후 버전입니다. 거래소, 은행, 관리자 기능은 유지하되, 서비스 분리, 권한 검증, 민감정보 응답 통제, 업로드 파일 검증, 오류 메시지 정리, 코드 및 서버 정보 노출 차단 같은 조치가 반영되어 있습니다.

이 브랜치는 단순히 "보안 기능을 조금 추가한 버전"이 아니라, 취약한 서비스가 실제로 어떤 수정 과정을 거쳐 더 안전한 구조로 전환되는지를 보여주는 결과물입니다. 따라서 `vul-web`과 `secure-web`을 비교하면 취약점 분석과 조치 이행 과정을 가장 명확하게 확인할 수 있습니다.

주요 조치 방향:

- 관리자/사용자/은행 서비스 및 세션 분리
- JWT 기반 인증 및 역할 기반 인가 강화
- 입력값 유효성 검증 및 DTO 바인딩 적용
- 파일 업로드 확장자 및 Magic Byte 검증
- 민감정보 마스킹과 관리자 전용 언마스킹 분리
- 오류 메시지, 파일 경로, 헤더, 코드 노출 차단
- 토큰 정책 개선, 중복 로그인 방지, 이전 토큰 무효화
- 회원가입/로그인 흐름 안정화 및 금융 처리 무결성 강화

### `auto-script` — 취약점 진단 자동화 도구

`auto-script` 브랜치는 웹 서비스 자체가 아니라, 취약점 진단 항목을 자동으로 점검하기 위한 보안 진단 도구입니다. 이 도구는 로컬, SSH, AWS SSM, Docker 환경을 통해 OS, 웹서버, DBMS, 클라우드 자산을 진단하고 결과 리포트를 자동으로 생성하는 것을 목표로 합니다.

이 브랜치는 취약 웹사이트와 안전 웹사이트를 "진단 대상"으로 바라보는 관점에 가깝습니다. 즉, `vul-web`과 `secure-web`이 진단과 조치의 대상이라면, `auto-script`는 그러한 대상을 좀 더 체계적이고 반복 가능한 방식으로 점검하기 위한 자동화 도구입니다.

주요 기능:

- SK 표준 가이드 / 주요정보통신기반시설 가이드 선택 진단
- 로컬, SSH, AWS SSM, Docker 연결 지원
- OS, WebServer, DBMS, AWS 환경 진단
- TXT, LOG, Excel 기반 리포트 자동 생성
- GUI 실행 파일 제공 가능

---

## 3. 전체 프로젝트 흐름

| 단계 | 설명 |
|------|------|
| 1단계 | `vul-web`에서 취약한 서비스 구조와 취약점 포인트를 확인 |
| 2단계 | 취약점 진단 항목 기준으로 문제를 분석하고 조치 방향 수립 |
| 3단계 | `secure-web`에서 조치 이행 및 보안 구조 개선 반영 |
| 4단계 | `auto-script`를 통해 진단 과정을 자동화하고 결과 리포트 생성 |

이 프로젝트는 단순히 웹사이트 하나를 만드는 흐름이 아니라, 취약한 상태의 서비스에서 시작해 조치가 반영된 서비스로 이동하고, 다시 그 과정을 자동 진단 도구와 연결하는 흐름을 갖습니다. 이 점이 일반적인 웹 개발 프로젝트와 가장 크게 다른 부분입니다.

---

## 4. 웹 서비스 설명

웹 서비스 영역은 `vul-web`과 `secure-web`에서 공통적으로 다루는 대상입니다.

### Exchange

| 항목 | 내용 |
|------|------|
| 대상 사용자 | 일반 사용자 |
| 서비스 성격 | 가상자산 거래 메인 서비스 |
| 주요 기능 | 시세 조회, 자산 조회, 주문, 거래내역, 커뮤니티, 이벤트, 고객지원 |

### Bank

| 항목 | 내용 |
|------|------|
| 대상 사용자 | 일반 사용자 |
| 서비스 성격 | 금융 기능 분리 서비스 |
| 주요 기능 | 계좌 조회, 입금, 출금, 이체 |

### Admin

| 항목 | 내용 |
|------|------|
| 대상 사용자 | 운영자, 관리자, 직원 |
| 서비스 성격 | 관리자 전용 백오피스 |
| 주요 기능 | 회원 관리, 신분증 승인, 자산 회수, 문의 처리, 직원 관리 |

---

## 5. 웹 서비스 기술 스택

이 섹션은 현재 기준으로 `secure-web` 브랜치의 기술 스택을 기준으로 정리합니다. 과거 일부 문서에는 Next.js 기준 설명이 남아 있을 수 있지만, 현재 정리 기준은 `React (Vite)`입니다.

| 구분 | 기술 | 상세 내용 |
|------|------|-----------|
| Frontend | React 19 | 거래소, 은행, 관리자 UI를 구성하는 핵심 라이브러리 |
| Frontend | TypeScript 5 | 화면 상태와 API 응답 모델링을 위한 정적 타입 시스템 |
| Frontend | Vite 7 | 프론트엔드 개발 서버 및 빌드 도구 |
| Frontend | React Router DOM 7 | 서비스별 화면 라우팅과 인증 흐름 분기 처리 |
| Frontend | styled-components | 서비스별 UI 스타일 분리를 위한 CSS-in-JS 도구 |
| Frontend | axios | 공통 API 호출, 인터셉터, 토큰 처리 |
| Frontend | lightweight-charts | 거래소 차트 표현 |
| Frontend | react-hook-form | 입력 중심 화면의 폼 상태 관리 |
| Frontend | react-markdown / remark-gfm | 마크다운 콘텐츠 렌더링 |
| Frontend | lucide-react | UI 아이콘 구성 |
| Frontend | matter-js | 일부 인터랙티브 요소 구현 |
| Backend | Java 17 | Spring Boot 3 계열과 호환되는 LTS 환경 |
| Backend | Spring Boot 3.4.2 | 백엔드 핵심 프레임워크 |
| Backend | Spring Web | REST API 처리 |
| Backend | Spring Security | 인증, 인가, 역할 기반 접근 통제 |
| Backend | Spring Data JPA | 엔티티-DB 매핑과 데이터 접근 처리 |
| Backend | Spring Validation | DTO 입력값 유효성 검사 |
| Backend | Spring OAuth2 Client | Kakao, Naver 소셜 로그인 연동 |
| Backend | JJWT 0.11.5 | JWT 발급, 검증, 클레임 처리 |
| Backend | Jsoup 1.18.3 | 사용자 입력 기반 HTML 정리 및 XSS 완화 |
| Backend | Lombok | 반복 코드 감소 |
| Backend | Spring Boot Actuator | 애플리케이션 상태 점검 지원 |
| Database / Infra | Oracle Free 23.4 | 회원, 자산, 주문, 거래, 문의, 관리자 데이터 저장 |
| Database / Infra | Hibernate / Oracle Dialect | Oracle 환경 ORM 지원 |
| Database / Infra | Docker | 백엔드, 프론트엔드, DB 컨테이너 실행 기반 |
| Database / Infra | Docker Compose | 다중 서비스 실행 구성 |
| Database / Infra | OpenResty (Nginx) | 프론트엔드 정적 파일 서빙 및 SPA 라우팅 |
| Database / Infra | Gradle | 백엔드 빌드와 의존성 관리 |
| External API | Upbit Quotation API | 시세, 호가, 캔들, 체결 데이터 연동 |

---

## 6. 이행 후 브랜치(`secure-web`) 기준 주요 보안 조치

| 항목 | 내용 |
|------|------|
| 인증 방식 | JWT 기반 인증 |
| 인가 방식 | 역할 기반 접근 제어 |
| 세션 관리 | 관리자/사용자 세션 분리 |
| 입력 통제 | DTO 바인딩 + 유효성 검증 |
| 파일 통제 | 확장자 화이트리스트 + Magic Byte 검증 |
| 민감정보 보호 | 응답 마스킹 + 언마스킹 권한 분리 |
| 배포 보안 | 프로덕션 빌드 기반 정적 서빙 |

주요 조치 방향:

- JWT 기반 인증과 역할 기반 인가
- 관리자/사용자/은행 로그인 분리
- 토큰 정책 개선과 이전 토큰 무효화
- 입력값 검증과 DTO 바인딩
- 업로드 파일 확장자 및 Magic Byte 검증
- 민감정보 마스킹
- 관리자 전용 언마스킹 API
- 오류 메시지, 파일 경로, 헤더, 코드 노출 차단
- race condition 및 금융 처리 무결성 보완

---

## 7. 자동 진단 도구(`auto-script`) 설명

| 항목 | 내용 |
|------|------|
| 프로젝트 성격 | 취약점 진단 자동화 도구 |
| 적용 가이드 | SK 표준 가이드 / 주요정보통신기반시설 가이드 |
| 진단 대상 | OS, WebServer, DBMS, Cloud(AWS) |
| 연결 방식 | 로컬, SSH, AWS SSM, Docker |
| 결과물 | LOG, TXT, Excel, Markdown 리포트 |

자동 진단 도구는 웹 서비스 자체를 구현하는 브랜치가 아니라, 진단 과정을 반복 가능하게 만들기 위한 도구 브랜치입니다. 로컬 서버, 원격 서버, AWS 자원, Docker 컨테이너를 대상으로 진단을 수행하고, 결과를 리포트로 정리하는 데 초점을 둡니다.

대표 진단 영역:

- Linux / Windows 보안 설정
- Nginx / IIS 웹서버 점검
- MySQL / PostgreSQL / MSSQL / Oracle DBMS 점검
- AWS IAM, S3, RDS, CloudTrail, 보안그룹, VPC 점검

---

## 8. 참고 문서

- `secure-web` 관련 문서
  - [docs/security_exchange.md](docs/security_exchange.md)
  - [docs/security_bank.md](docs/security_bank.md)
  - [docs/security_admin.md](docs/security_admin.md)
  - [docs/api_spec.md](docs/api_spec.md)
  - [docs/system_architecture_analysis.md](docs/system_architecture_analysis.md)
  - [docs/project_requirements.md](docs/project_requirements.md)
  - [docs/privacy_policy.md](docs/privacy_policy.md)

---

## 9. 주의 사항

- `vul-web`은 교육용 취약 환경을 포함하므로 실서비스에 사용하면 안 됩니다.
- `secure-web`은 이행 후 버전이지만, 교육용 프로젝트라는 성격 자체는 유지됩니다.
- 문서 일부에는 과거 `Next.js` 기반 설명이 남아 있을 수 있으나, 현재 웹 서비스 기준 기술 스택은 `React (Vite)`입니다.
- `main` 브랜치는 통합 안내용이며, 실제 코드 검토는 각 브랜치에서 확인하는 것이 맞습니다.

---

## 10. 팀

- 김동현(부팀장)
- 김하늘
- 김한수
- 김현진
- 박지빈(팀장)
- 박찬웅
- 신동원
- 우혜미
- 전소원
