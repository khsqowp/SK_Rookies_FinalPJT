# TOOL PHASE 4: Triage & Threat Modeling (위험도 분류)

---

## 0. 절대 규칙

**이 Phase에서 수행하는 것:**
- Phase 3 확정 취약점에 대한 CVSS v3.1 위험도 점수 산정
- OWASP Top 10(2021) / CWE ID 맵핑
- 오탐(FP) 분류 및 방어 항목(Mitigated) 정리
- `logs/classification/triage_summary.json` 생성

**이 Phase에서 절대 수행하지 않는 것:**
- ❌ 추가 통신/패킷 발송
- ❌ 새로운 취약점 발견 시도
- ❌ Phase 5(보고서) 작성 시작

**평가 원칙:**
- 임의 등급 부여 금지. 반드시 CVSS v3.1 평가 벡터를 항목별로 논리적으로 판단하여 점수를 도출.
- 공격 증거가 없는 것은 오탐(FP)으로 분류.
- 방어된 항목(403, 401 차단)은 `mitigated/`에 Positive Finding으로 유지.

---

## 1. CVSS v3.1 분석 포인트 (메트릭별 판단 기준)

| 메트릭 | 코드 | 판단 기준 |
|--------|------|----------|
| Attack Vector | AV | N: 인터넷 원격 공격 가능 / L: 로컬 접근 필요 |
| Attack Complexity | AC | L: 조건 없이 즉시 가능 / H: 특수 조건·타이밍 필요 |
| Privileges Required | PR | N: 인증 불필요 / L: 일반 계정 필요 / H: 관리자 계정 필요 |
| User Interaction | UI | N: 피해자 개입 불필요 / R: 피해자 행위(클릭 등) 필요 |
| Scope | S | U: 취약 컴포넌트 내 영향 / C: 다른 컴포넌트로 확대 |
| Confidentiality | C | N: 영향 없음 / L: 일부 정보 노출 / H: 전체 정보 탈취 가능 |
| Integrity | I | N: 영향 없음 / L: 일부 수정 / H: 전체 데이터 수정·삭제 가능 |
| Availability | A | N: 영향 없음 / L: 성능 저하 / H: 서비스 완전 중단 가능 |

**위험 등급:**

| 등급 | 점수 | 대응 기준 |
|------|------|----------|
| CRITICAL | 9.0~10.0 | 즉시 (24시간 이내) |
| HIGH | 7.0~8.9 | 1주 이내 패치 |
| MEDIUM | 4.0~6.9 | 일정 기간 내 패치 |
| LOW | 0.1~3.9 | 낮은 우선도 |

---

## 2. 취약점 유형별 분석 포인트

**BAC (권한 상승):**
- 네트워크 원격 공격 가능 → `AV:N`
- 낮은 권한 계정만 있으면 즉시 시도 가능 → `AC:L`, `PR:L`
- 시스템 전체 장악으로 영향 확장 → `S:C`, `C:H`, `I:H`

**Stored XSS:**
- 피해자가 게시글을 열람해야 실행 → `UI:R`
- 피해자 컨텍스트로 영향 확장(세션 탈취) → `S:C`
- 세션 탈취 수준인가, 단순 경고문인가 → `C:L` vs `C:H` 구분

**IDOR:**
- 피해가 개별 사용자에 머무는가 vs 전체로 확장되는가 → `S:U` vs `S:C` 구분
- 금융·개인정보 완전 노출 → `C:H`
- 조회만 vs 수정·삭제까지 가능한가 → `I` 값 구분

**WebShell/파일 업로드:**
- 서버에서 임의 코드 실행 가능 → `S:C`, `C:H`, `I:H`, `A:H`
- 업로드만 가능하고 실행 불가 → Integrity만 일부 영향

**비즈니스 로직 / Race Condition:**
- 실제 금전적 손실 발생 → `I:H`
- 조건 없이 반복 적용 가능 → `AC:L`

---

## 3. 글로벌 표준 맵핑 (SK × OWASP × CWE)

| 취약점 유형 | SK 항목 | OWASP 2021 | CWE ID |
|------------|---------|------------|--------|
| 권한 상승 (BAC) | 4-5 | A01:2021 | CWE-285 |
| Stored XSS | 1-1 | A03:2021 | CWE-79 |
| SQL Injection | 1-2 | A03:2021 | CWE-89 |
| IDOR | 1-3 | A01:2021 | CWE-639 |
| 악성 파일 업로드 | 2-1 | A04:2021 | CWE-434 |
| 비즈니스 로직 결함 | 1-6 | A04:2021 | CWE-840 |
| JWT/인증 취약점 | 4-3 | A07:2021 | CWE-287 |
| 서버 정보 노출 | 7-1~7-4 | A05:2021 | CWE-200 |
| Command Injection | 4-4 | A03:2021 | CWE-78 |
| Path Traversal | 4-6 | A01:2021 | CWE-22 |

---

## 4. 오탐(FP) 및 방어 항목(Mitigated) 기준

**오탐으로 분류하는 경우:**
- Phase 3 검증 시 재현 불가
- Time-based SQLi에서 응답 지연이 네트워크 딜레이와 구분 불가
- 페이로드 반영은 되었으나 실제 실행 불가능한 구조

**방어 항목으로 기록하는 경우:**
- 낮은 권한 토큰으로 관리자 API 접근 시 403 정상 반환
- 파일 업로드 시 확장자 화이트리스트로 차단 확인
- JWT 알고리즘 None 공격 시 서명 검증 차단 확인

---

## 5. 출력 포맷 (triage_summary.json)

출력 타겟: `logs/classification/triage_summary.json`

```json
{
  "report_date": "",
  "project_status": "",
  "confirmed_vulnerabilities": { "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0 },
  "false_positives": 0,
  "mitigated_findings": 0,
  "detailed_findings": [
    {
      "id": "",
      "title": "",
      "sk_mapper": "",
      "cwe": "",
      "owasp": "",
      "cvss_vector": "CVSS:3.1/AV:.../...",
      "cvss_score": 0.0,
      "severity": "",
      "endpoint": "",
      "evidence_file": "",
      "remediation_priority": 0
    }
  ],
  "false_positive_list": [],
  "mitigated_list": []
}
```

---

## 6. 검증 (Self-Validation)

- [ ] 모든 확정 취약점에 CVSS v3.1 벡터 8개 항목이 논리적 근거와 함께 도출되었는가?
- [ ] SK 항목 외에 CWE ID와 OWASP Top 10(2021) 카테고리가 맵핑되었는가?
- [ ] 오탐(FP) 분류 사유가 `logs/reasoning.log`에 명시되었는가?
- [ ] 방어 확인 항목이 `mitigated/`에 Positive Finding으로 기록되었는가?
- [ ] CRITICAL 취약점에 remediation_priority: 1이 설정되었는가?
