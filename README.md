# VulnScanner — 취약점 진단 자동화 도구

> 클라우드 구축을 통한 취약점진단(SK표준·주요정보통신기반시설) 및 모의해킹 프로젝트의 일환으로 개발된 보안 진단 자동화 도구입니다.

---

## 프로젝트 개요

| 항목 | 내용 |
|------|------|
| 프로젝트명 | 클라우드 구축을 통한 취약점진단 및 모의해킹 컨설팅 |
| 핵심 키워드 | 취약점진단 · 모의해킹 · 클라우드보안 · 자동화 |
| 적용 가이드 | SK Shieldus 표준 가이드 / 주요정보통신기반시설 보호 가이드 |
| 진단 대상 | OS(Linux·Windows) · WebServer(Nginx·IIS) · DBMS(MySQL·PostgreSQL·MSSQL·Oracle) · Cloud(AWS) |

---

## 팀원

| 이름 | 역할 |
|------|------|
| 박지빈 | 팀장 |
| 김동현 | 팀원 |
| 김하늘 | 팀원 |
| 김한수 | 팀원 |
| 김현진 | 팀원 |
| 박찬웅 | 팀원 |
| 신동원 | 팀원 |
| 우혜미 | 팀원 |
| 전소원 | 팀원 |

---

## 주요 기능

- **이중 가이드 지원**: SK 표준 가이드 / 주요정보통신기반시설(주통기) 가이드 선택 진단
- **다양한 연결 방식**: 로컬 · SSH(PEM/패스워드) · AWS SSM · Docker
- **자동 리포트 생성**: 진단 완료 시 로그(.log) · TXT(.txt) · Excel(.xlsx) 자동 저장
- **명령어 추출**: 도메인별 점검 명령어를 Excel/TXT로 내보내기
- **GUI 앱**: macOS(.app) · Windows(.exe) 단독 실행 가능

---

## 진단 모듈

### SK 표준 가이드

| 번호 | 모듈 | 주요 점검 항목 |
|------|------|----------------|
| 1 | OS - Linux | 계정·패스워드 관리(12), 파일·권한(23), 네트워크 서비스(10), 로그(3), 애플리케이션(6), 시스템 보안(3), 패치(1) |
| 2 | OS - Windows | 계정 정책, 레지스트리, 감사 정책, RDP, SMB |
| 3 | WebServer - Nginx | 버전 노출, 디렉토리 리스팅, SSL/TLS, 보안 헤더, HTTP 메서드 |
| 4 | WebServer - IIS | 디렉토리 브라우징, 버전 노출, HTTP 메서드, 로그 |
| 5 | DBMS (MySQL/PG/MSSQL) | 포트 노출, 기본 계정, 원격 root, 감사 로그 |
| 6 | Oracle 11g~21c | 계정·권한, 보안 설정, 환경 파일, 감사 (서버/Docker/RDS) |
| 7 | Cloud - AWS | IAM, 보안그룹, S3, RDS, CloudTrail, VPC, 백업 |

### 주요정보통신기반시설(주통기) 가이드

SK 표준 대비 확장된 점검 항목을 별도 모듈로 제공합니다.

| 번호 | 모듈 | 비고 |
|------|------|------|
| 1 | OS - Linux (주통기) | 67개 항목 |
| 2 | OS - Windows (주통기) | 주통기 기준 레지스트리·정책 |
| 3 | DBMS (주통기) | MySQL·PostgreSQL·MSSQL 주통기 항목 |
| 4 | Cloud - AWS (주통기) | AWS 주통기 항목 |

---

## 연결 방식

| 방식 | 설명 |
|------|------|
| 로컬 | 현재 시스템 직접 진단 |
| SSH (PEM) | PEM 키 파일로 원격 서버 접속 |
| SSH (Password) | 패스워드 인증으로 원격 서버 접속 |
| AWS SSM | EC2 Session Manager 접속 (키 불필요) |
| Docker | 로컬 또는 원격 컨테이너 내부 진단 |

---

## 리포트 출력

진단 완료 시 `reports/` 폴더에 자동 저장됩니다.

| 형식 | 파일 | 내용 |
|------|------|------|
| 로그 (`.log`) | 항상 자동 저장 | 명령어 및 실행 결과 raw 데이터 |
| TXT (`.txt`) | 항상 자동 저장 | 전체 진단 결과 상세 리포트 |
| Excel (`.xlsx`) | 항상 자동 저장 | 항목별 취약/안전/수동확인 색상 구분 |
| Markdown (`.md`) | 선택 시 저장 | 마크다운 형식 리포트 |

---

## 앱 실행 (빌드된 파일 사용)

Python 설치 없이 실행 가능합니다.

| OS | 파일 | 실행 방법 |
|----|------|-----------|
| macOS | `dist/VulnScanner.app` | 더블클릭 |
| Windows | `dist/VulnScanner.exe` | 더블클릭 |

> **macOS 최초 실행 시**: 보안 경고가 뜨면
> 시스템 환경설정 → 개인 정보 보호 및 보안 → "확인 없이 열기" 클릭

---

## 직접 빌드

### 요구사항

- Python 3.9 이상 (python.org 설치 권장, Microsoft Store Python 비권장)
- 플랫폼별 빌드 필요: macOS에서 빌드 → macOS 앱 / Windows에서 빌드 → Windows 앱

### 설치 및 빌드

```bash
git clone <repo-url>
cd SK_Rookies_FinalPJT

# 의존성 설치
pip install -r requirements.txt
pip install pyinstaller

# macOS 아이콘 생성 (macOS 전용)
python3 make_icon.py

# 앱 빌드
pyinstaller vuln-scanner-gui.spec --noconfirm
```

빌드 결과물:
- macOS: `dist/VulnScanner.app`
- Windows: `dist/VulnScanner.exe`

### 의존성

```
paramiko>=3.0    # SSH 원격 실행
boto3>=1.26      # AWS API
openpyxl>=3.1    # Excel 리포트
oracledb>=1.4    # Oracle DB 연결
```

---

## 추가 설치 (선택)

### Oracle RDS 진단

앱 실행 컴퓨터에 Oracle Instant Client가 필요합니다.

```bash
# macOS
brew install instantclient-basic

# Windows
# Oracle 공식 사이트에서 Instant Client Basic 다운로드
# → C:\oracle\instantclient 에 압축 해제
```

### AWS SSM 포트 포워딩 (Oracle RDS SSM 터널)

```bash
# macOS
brew install awscli
brew install --cask session-manager-plugin

# Windows
# AWS CLI: https://aws.amazon.com/cli/ 에서 MSI 설치
# Session Manager Plugin: AWS 공식 문서 참고
```

---

## AWS Cloud 진단

boto3가 로컬 AWS 자격증명을 자동으로 사용합니다.
`~/.aws/credentials` 또는 환경변수가 자동 적용됩니다.

### 필요 IAM 권한

```bash
# SecurityAudit 관리형 정책 부여 (권장)
aws iam attach-user-policy \
  --user-name <사용자명> \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

### 자격증명 확인

```bash
aws sts get-caller-identity   # 현재 연결된 계정 확인
aws iam list-users            # IAM 권한 정상 여부 확인
```

---

## 디렉토리 구조

```
SK_Rookies_FinalPJT/
├── gui.py                  # GUI 진입점 (tkinter)
├── main.py                 # CLI 진입점
├── export_commands.py      # 명령어 추출 모듈
├── requirements.txt        # Python 의존성
├── vuln-scanner-gui.spec   # PyInstaller 빌드 설정
├── make_icon.py            # macOS 아이콘 생성 스크립트
├── core/
│   ├── base_scanner.py     # 스캐너 추상 기반 클래스
│   ├── remote.py           # SSH / SSM / Docker 실행기
│   ├── result.py           # 결과 데이터 모델
│   └── reporter.py         # 리포트 생성 (Excel·TXT·Log·Markdown)
├── modules/
│   ├── os/                 # Linux, Windows 스캐너
│   ├── webserver/          # Nginx, IIS 스캐너
│   ├── dbms/               # MySQL/PG/MSSQL, Oracle 스캐너
│   └── cloud/              # AWS 스캐너
└── reports/                # 생성된 진단 리포트 저장 폴더
```

---

## 프로젝트 세부 과제

| 차수 | 주요 목표 | 주요 산출물 |
|------|-----------|-------------|
| 1차 | 프로젝트 목표 수립 및 항목 이해 | 수행 계획서, 전체 WBS |
| 2차 | 수행 계획서 작성 및 기준 비교 | 수행 계획서, WBS 수정본 |
| 3차 | 조치 방법 이해 및 이행점검 준비 | 진단 결과 보고서 |
| 4차 | 보고서 고도화 및 이행점검 수행 | 진단 결과 보고서, 이행점검 보고서, 발표 PPT |
| 5차 | 최종 결과보고 및 마무리 | 이행점검 보고서, 최종 발표 PPT |
