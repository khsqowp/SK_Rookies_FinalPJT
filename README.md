# VCE (Vulnerability Crypto Exchange)

VCE는 보안 진단 및 모의해킹 실습을 위해 만든 교육용 가상자산 거래소 프로젝트입니다.  
Spring Boot 기반 백엔드, Next.js 기반 프론트엔드, Oracle DB를 사용하며 거래소 화면과 은행 화면을 분리한 구조를 가지고 있습니다.

> [!WARNING]
> 이 프로젝트는 실제 서비스가 아니라 취약점 진단 학습을 위한 실습용 환경입니다.  
> 일부 기능에는 의도적으로 취약한 구현이 포함되어 있으므로 운영 환경에 배포하거나 실서비스에 재사용하면 안 됩니다.

## 프로젝트 한눈에 보기

- 보안 학습용 가상자산 거래소 플랫폼
- Spring Boot 3.4 + Java 17 + Oracle Free 기반 백엔드
- Next.js 15 + React 19 기반 듀얼 프론트엔드
- JWT, OAuth2(Kakao/Naver), KYC, 자산 관리, 주문/체결, 커뮤니티, 고객지원, 관리자 기능 포함
- 교육 목적의 의도적 취약점 실습 포인트 포함

## 주요 기능

- 회원가입, 로그인, JWT 인증, OAuth2 로그인
- KYC 추가 정보 입력 및 신분증 이미지 업로드
- 가상자산 잔고 조회, 입금/출금, 내부 지갑 전송
- 시장가/지정가 주문, 미체결 주문 조회, 거래 내역 조회
- 업비트 시세/오더북/캔들 데이터 연동
- 커뮤니티 게시글, 댓글, 좋아요, 파일 업로드
- FAQ, 1:1 문의, 관리자 답변 처리
- 관리자 대시보드, 회원 상태 변경, 자산 회수, 거래/문의 모니터링
- 출석 이벤트, 광고 미션, 이벤트 페이지
- 거래소 프론트와 은행 프론트를 분리한 멀티 프론트엔드 구성

## 아키텍처

```text
Exchange Front (Next.js) ─┐
                          ├─ Backend API (Spring Boot)
Bank Front (Next.js) ─────┘            │
                                       └─ Oracle Database
```

- `exchange-front`: 거래소, 커뮤니티, 이벤트, 관리자 화면
- `bank-front`: 가상은행/계좌 성격의 분리 UI
- `backend`: 인증, 자산, 주문, 커뮤니티, 관리자 API
- `oracle-db`: 스키마 및 초기 데이터가 함께 올라가는 Oracle Free 컨테이너

## 기술 스택

| 구분 | 사용 기술 |
| --- | --- |
| Backend | Java 17, Spring Boot 3.4.2, Spring Security, Spring Data JPA, OAuth2 Client, JWT |
| Frontend | Next.js 15.3.0, React 19, TypeScript, styled-components |
| Database | Oracle Free 23.4, Hibernate, JPA |
| Infra | Docker, Docker Compose, Gradle |
| External API | Upbit quotation API |

## 디렉터리 구조

```text
.
├─ docs/                         # 요구사항, 아키텍처, 배포 환경, 개인정보처리방침, PoC 문서
├─ frontend/                     # Next.js 프론트엔드 (exchange / bank / admin)
├─ src/main/java/com/rookies/sk/ # Spring Boot 애플리케이션 코드
├─ src/main/resources/db/        # Oracle schema.sql, init.sql
├─ docker-compose.yml            # 로컬 통합 실행용 Compose
├─ docker-compose.app.yml        # 백엔드 배포용 Compose
├─ docker-compose.exchange-front.yml
├─ Dockerfile                    # 백엔드 이미지 빌드
└─ build.gradle                  # 백엔드 빌드 설정
```

## 주요 페이지와 API 영역

### 프론트엔드 페이지

- `/crypto`, `/exchange`, `/balances`, `/investments`, `/trends`
- `/community`, `/events`, `/support`, `/mypage`
- `/admin/login`, `/admin/dashboard`
- `/bank`

### 백엔드 API 범주

- `/api/auth`: 로그인, 토큰 갱신, 회원 정보, KYC 완료
- `/api/assets`: 자산 조회, 입출금
- `/api/orders`: 주문 생성, 조회, 취소
- `/api/wallets`: 지갑 주소 조회, 내부 전송
- `/api/transactions`: 거래 내역
- `/api/market`: 업비트 시세 프록시
- `/api/community`: 게시글, 댓글, 좋아요, 업로드
- `/api/support`: FAQ, 문의
- `/api/admin`: 관리자 기능
- `/api/events`, `/api/news`

## 빠른 실행

### 1. 환경 변수 준비

루트에는 백엔드 및 Docker Compose용 환경 파일이 필요합니다.

```bash
cp .env.example .env
```

프론트엔드 로컬 실행용 환경 파일도 준비합니다.

```bash
cp frontend/.env.example frontend/.env.local
```

Windows PowerShell에서는 아래처럼 복사하면 됩니다.

```powershell
Copy-Item .env.example .env
Copy-Item frontend/.env.example frontend/.env.local
```

로컬 실행 시에는 아래 값들을 `localhost` 기준으로 맞춰 두는 것을 권장합니다.

- `FRONTEND_URL`
- `CORS_ALLOWED_ORIGINS`
- `NEXT_PUBLIC_API_BASE_URL`
- `NEXT_PUBLIC_EXCHANGE_FRONTEND_URL`
- `NEXT_PUBLIC_BANK_FRONTEND_URL`
- `NEXT_SERVER_ACTION_ALLOWED_ORIGINS`

### 2. Docker Compose로 전체 실행

가장 간단한 방법은 전체 스택을 한 번에 올리는 것입니다.

```bash
docker compose up --build
```

기본 접속 주소는 환경 변수에 따라 달라질 수 있지만, 일반적으로 아래 구성을 사용합니다.

- Exchange Front: `http://localhost:15173`
- Bank Front: `http://localhost:15174` 또는 `.env`의 `HOST_BANK_FRONT_PORT`
- Backend API: `http://localhost:18080`
- Oracle DB: `localhost:1521/FREEPDB1`

### 3. 로컬 개발 모드로 분리 실행

DB만 Docker로 띄우고, 백엔드와 프론트를 로컬에서 실행할 수도 있습니다.

백엔드:

```bash
docker compose up -d oracle-db
./gradlew bootRun
```

Windows에서는:

```powershell
docker compose up -d oracle-db
.\gradlew.bat bootRun
```

프론트엔드:

```bash
cd frontend
npm install
npm run dev:exchange
```

은행 프론트까지 함께 띄우려면 별도 터미널에서 아래 명령을 추가로 실행합니다.

```bash
cd frontend
npm run dev:bank
```

## 기본 계정

애플리케이션 시작 시 아래 계정이 자동 초기화될 수 있습니다.

| 역할 | 이메일 | 비밀번호 |
| --- | --- | --- |
| ADMIN | `admin@vce.com` | `admin1234` |
| MANAGER | `manager@vce.com` | `manager1234` |
| STAFF | `staff@vce.com` | `staff1234` |
| TEST USER | `test@vce.com` | `test1234` |

일반 테스트 로그인 API는 `/api/auth/test/login` 경로를 사용합니다.

## 환경 파일 가이드

- `.env.example`: 통합 실행용 예시
- `.env.backend.example`: 백엔드 배포용 예시
- `frontend/.env.example`: 프론트 로컬 개발용 예시
- `frontend/.env.exchange.example`: 거래소 프론트 배포/개발용 예시
- `frontend/.env.bank.example`: 은행 프론트 배포/개발용 예시

배포 환경 분리는 [docs/deployment-env.md](docs/deployment-env.md)를 참고하면 됩니다.

## 참고 문서

- [docs/project_requirements.md](docs/project_requirements.md)
- [docs/system_architecture_analysis.md](docs/system_architecture_analysis.md)
- [docs/deployment-env.md](docs/deployment-env.md)
- [docs/privacy_policy.md](docs/privacy_policy.md)
- [docs/poc.html](docs/poc.html)

## 주의 사항

- 이 저장소는 교육용 취약 환경을 포함합니다.
- 실거래, 실명정보, 실제 운영계정 용도로 사용하면 안 됩니다.
- OAuth2 연동은 Kakao/Naver 클라이언트 정보가 있을 때만 정상 동작합니다.
- 일부 예전 보조 문서에는 React/Vite 기반 설명이 남아 있을 수 있으나, 현재 프론트엔드 구현은 Next.js 기준입니다.
