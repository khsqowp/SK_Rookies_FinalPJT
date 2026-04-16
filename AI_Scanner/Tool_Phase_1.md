# TOOL PHASE 1: Recon & OSINT (정찰 및 Endpoint 발견)

---

## 0. 절대 규칙

- 한국어로 대답하고, 설명하고, 문서 및 보고서도 한국어를 사용해서 작성할것
**이 Phase에서 수행하는 것:**
- 대상 웹 애플리케이션의 모든 Endpoint 발굴
- 환경 정보(서버, 헤더, SSL, CORS, 인증 구조) 추론
- 숨겨진 파일·경로·파라미터 탐색
- 발견 결과를 기능별로 구조화하여 저장

**이 Phase에서 절대 수행하지 않는 것:**
- ❌ Phase 2 이후(Fuzzing, 검증, 분류) 진행
- ❌ 취약점 확정 또는 중간 결론 도출
- ❌ 이전 진단 결과 참고

**토큰 관리 원칙:**
- 서버 응답 전체를 그대로 읽지 않음. 반드시 `./scripts/ai_curl.sh` 래퍼를 통해 요약 수신.
- 스캐너 원본 JSON 직접 열람 금지. `./scripts/parse_endpoints.sh`를 통해 URL 목록만 추출.

**Reasoning Log 원칙:**
- 모든 판단 근거(왜 이 경로를 고위험으로 보는지 등)를 `logs/reasoning.log`에 기록.

---

## 1. 진단 항목 매핑 (SK 標準)

| SK 항목 | 분석 관점 |
|---------|----------|
| **3-4** | 관리자/대시보드 페이지가 인증 없이 노출되는가 |
| **3-6** | 백업·테스트·개발용 파일 또는 경로가 외부에서 접근 가능한가 |
| **6-2** | JS 번들에 API Key, 비밀키, 하드코딩된 자격증명이 포함되어 있는가 |
| **7-1** | HTTP 응답 헤더에 서버 종류·버전 정보가 과도하게 노출되는가 |
| **7-2** | 인증 없이 접근 가능한 숨겨진 디렉터리·경로가 존재하는가 |
| **7-3** | 보안 헤더(HSTS, CSP, X-Frame-Options 등)가 누락되었는가 |
| **7-4** | 구버전 TLS 허용, HSTS 미적용 등 SSL/TLS 정책이 취약한가 |

---

## 2. 분석 포인트 (단계별)

### A. 정적 소스 분석 (JS 번들 / Source Map)

**분석 관점:**
- JS 파일 내 `/api/` 패턴 포함 문자열 경로 추출
- Source Map(`.js.map`) 공개 노출 여부 → 노출 시 원본 소스 복원 가능
- 하드코딩된 API Key, Bearer 토큰, Secret, DB 접속 문자열 탐색 (SK 6-2)
- 숨겨진 관리자 경로(`/admin`, `/manage`, `/internal`, `/dashboard`) 탐색 (SK 3-4)
- 사용된 외부 라이브러리 및 버전 정보 식별 (SK 6-1: 구버전 취약 라이브러리)
- 인증 토큰 생성·검증 로직이 클라이언트 측에 노출되어 있는가 (SK 4-3)

**추가 심층 분석:**
- `webpack://` 스키마 또는 Source Map URL을 통한 원본 디렉터리 구조 복원 가능 여부
- 환경 변수(`.env`)가 번들에 인라인으로 포함되어 있는가
- 개발 모드(`NODE_ENV=development`) 분기에서만 노출되는 디버그 엔드포인트가 있는가

---

### B. 동적 Endpoint 스캐닝

**분석 관점:**
- 크롤링 결과에서 로그인 전/후 접근 가능한 Endpoint 분리 분류
- 경로 브루트포스 결과에서 403(차단됨), 200(접근 가능), 401(인증 필요)를 구분
- Swagger UI, `/api/docs`, `/v3/api-docs`, `/graphql` 등 API 문서 노출 여부 (SK 3-6)
  - 노출 시: 전체 Endpoint·파라미터 스키마 공개됨 → 즉시 고위험 처리

**추가 심층 분석:**
- **GraphQL 사용 여부 확인:** `/graphql` Endpoint 탐색 후 Introspection Query 허용 여부 확인
  - Introspection이 허용되면 전체 스키마(쿼리/뮤테이션/필드)가 노출됨
  - Schema에서 내부 관리자 뮤테이션(`createAdmin`, `deleteUser` 등) 탐색
- **WebSocket Endpoint 탐색:** `ws://`, `wss://` Endpoint 확인 및 인증 요구 여부 파악
- **API 버전 열거:** `/v1`, `/v2`, `/v3`, `/api/v1`, `/api/v2` 패턴으로 구버전 API 노출 확인
  - 구버전 API는 최신 보안 패치가 적용되지 않은 경우가 많음
- **숨겨진 파라미터 탐색:** 공개된 API 파라미터 외에 숨겨진 파라미터 존재 여부 탐색
  - Phase 2 퍼징 대상 파라미터 목록 보강

---

### C. 환경 추론 (서버 헤더 / 메소드 / SSL / CORS)

**분석 관점 (SK 7-1 ~ 7-4):**

| 확인 항목 | 취약 여부 판단 기준 |
|----------|-------------------|
| `Server` 응답 헤더 | 버전 정보 노출 시 취약 (SK 7-1, 7-3) |
| `X-Powered-By` 헤더 | 기술스택 노출 시 취약 |
| `Strict-Transport-Security` | 헤더 부재 시 HTTP 다운그레이드 가능 (SK 7-4) |
| `X-Frame-Options` / `CSP` | 부재 시 클릭재킹 / XSS 공격 가능성 증가 (SK 7-3) |
| `X-Content-Type-Options` | `nosniff` 미설정 시 MIME 스니핑 공격 가능 (SK 7-3) |
| `Referrer-Policy` | 과도한 리퍼러 정보 노출 여부 |
| OPTIONS 메소드 허용 여부 | CORS 우회 가능성 점검 필요 |
| TLS 버전 | TLS 1.0/1.1 허용 시 다운그레이드 공격 위험 (SK 7-4) |

**CORS 정책 심층 분석:**
- `Access-Control-Allow-Origin: *` 설정 여부 → 모든 도메인에서 CORS 허용 시 취약
- `Access-Control-Allow-Credentials: true`와 `*` 와일드카드가 동시에 설정되어 있는가
- 임의 도메인(`Origin: https://evil.com`)을 요청 헤더에 삽입했을 때 반영되는가 → CORS 반사 취약점
- 인증이 필요한 API에 대해 CORS로 인해 타 도메인에서 인증 정보를 포함한 요청이 가능한가

---

### D. 인증 구조 파악

**분석 관점:**
- 인증 방식 식별: 세션 쿠키, JWT, OAuth2, API Key 등
- JWT 사용 시:
  - 토큰 만료 시간(exp) 설정 여부 및 길이 (만료 없는 JWT는 탈취 시 영구 사용 가능)
  - 알고리즘 종류 확인 (HS256 / RS256 등)
  - JWT payload에 민감 정보(비밀번호, 권한 정보 등)가 과도하게 포함되어 있는가 (SK 5-2)
- 세션 쿠키 사용 시:
  - `HttpOnly`, `Secure`, `SameSite` 속성 설정 여부 확인
- 인증 토큰이 URL 파라미터에 포함되어 전달되는가 (로그에 기록될 위험)

---

### E. Endpoint 기능 분류 및 공격 우선순위 설정

**분류 기준:**

| 카테고리 | 우선순위 | 이유 |
|---------|--------|------|
| 인증 (`/auth`, `/login`, `/token`, `/oauth`) | 최고 | 인증 우회 시 전체 시스템 위험 |
| 관리자 (`/admin`, `/manage`, `/staff`, `/internal`) | 최고 | 권한 상승 취약점 핵심 대상 |
| 금융/결제 (`/pay`, `/transaction`, `/wallet`, `/bank`) | 최고 | 비즈니스 로직 결함 시 직접 손실 |
| 파일 (`/upload`, `/file`, `/image`, `/document`) | 높음 | WebShell 업로드 가능성 |
| 사용자 자원 (`/users/{id}`, `/profile`, `/account`) | 높음 | IDOR 취약점 핵심 대상 |
| 외부 연동 (`/webhook`, `/proxy`, `/redirect`, `/fetch`) | 높음 | SSRF 핵심 대상 |
| 게시판/공개 (`/board`, `/posts`, `/comment`) | 중간 | Stored XSS 가능성 |
| API 버전 구버전 (`/v1/`, `/v2/`) | 중간 | 보안 패치 누락 가능성 |
| GraphQL (`/graphql`) | 높음 | Introspection 허용 + 인가 우회 가능성 |

---

## 3. 출력물 생성 규칙

출력 파일: `candidates/0-1_RECON/summary.json`

```json
{
  "phase": "1-RECON",
  "scan_date": "",
  "total_endpoints": 0,
  "categories": {
    "auth": [],
    "admin": [],
    "finance": [],
    "upload": [],
    "user": [],
    "external_integration": [],
    "board": [],
    "graphql": [],
    "old_api_versions": [],
    "websocket": [],
    "unknown": []
  },
  "high_priority_targets": [
    {
      "endpoint": "",
      "method": "",
      "reason": "",
      "sk_map": []
    }
  ],
  "env_findings": {
    "server_header_exposed": false,
    "x_powered_by_exposed": false,
    "hsts_missing": false,
    "csp_missing": false,
    "x_frame_options_missing": false,
    "cors_wildcard": false,
    "cors_reflection": false,
    "options_method_allowed": false,
    "tls_weak_version": false,
    "swagger_exposed": false,
    "graphql_introspection_allowed": false,
    "old_api_version_exposed": false
  },
  "auth_structure": {
    "type": "",
    "jwt_algorithm": "",
    "cookie_security_flags": {
      "httponly": false,
      "secure": false,
      "samesite": ""
    }
  },
  "hardcoded_secrets_found": false,
  "sourcemap_exposed": false
}
```

---

## 4. 검증 (Self-Validation)

- [ ] 래퍼 스크립트(`ai_curl.sh`, `parse_endpoints.sh`)를 경유하여 통신했는가?
- [ ] JS 번들에서 API 경로 및 하드코딩 자격증명 탐색을 수행했는가?
- [ ] Source Map 노출 여부를 확인했는가?
- [ ] GraphQL Introspection 허용 여부를 확인했는가?
- [ ] 구버전 API 경로(`/v1`, `/v2`) 노출 여부를 확인했는가?
- [ ] CORS 정책(와일드카드, 반사 취약점)을 점검했는가?
- [ ] JWT/세션 쿠키의 보안 속성을 파악했는가?
- [ ] WebSocket Endpoint 탐색을 수행했는가?
- [ ] 모든 Endpoint가 기능별 카테고리로 분류되었는가?
- [ ] 판단 근거가 `logs/reasoning.log`에 기록되었는가?
