# 네이버 광고 슬롯 관리 시스템

Flask 기반의 네이버 쇼핑 및 플레이스 광고 슬롯 관리 웹 애플리케이션입니다.

## 주요 기능

### 사용자 관리
- 3단계 계층 구조 (관리자 → 총판 → 대행사)
- 사용자 등록 및 승인 시스템
- 역할별 접근 권한 관리

### 슬롯 관리
- 쇼핑 슬롯 등록 및 관리
- 플레이스 슬롯 등록 및 관리
- 엑셀 파일 일괄 업로드/다운로드
- 슬롯 상태 관리 (empty → pending → approved → live)

### 승인 워크플로우
- 계층별 승인 프로세스
- 슬롯 생성/수정/삭제 승인
- 일괄 승인 기능

### 정산 시스템
- 자동 정산 계산 (30원 × 슬롯1개 × 기간)
- 정산 내역 관리
- 환불 처리 시스템

## 기술 스택
- **Backend**: Python Flask
- **Database**: PostgreSQL
- **Frontend**: Bootstrap 5, Feather Icons
- **Authentication**: Flask-Login
- **File Processing**: openpyxl, pandas

## 설치 및 실행

### 1. 의존성 설치
```bash
pip install -r requirements.txt
```

### 2. 환경 변수 설정
```bash
export DATABASE_URL="postgresql://username:password@localhost/database_name"
export SESSION_SECRET="your-secret-key"
```

### 3. 애플리케이션 실행
```bash
# 개발 환경
python main.py

# 프로덕션 환경
gunicorn --bind 0.0.0.0:5000 main:app
```

## 기본 계정
- **관리자**: admin / adminpassword

## 프로젝트 구조
```
├── app.py                 # 메인 애플리케이션
├── main.py               # 진입점
├── models.py             # 데이터베이스 모델
├── templates/            # HTML 템플릿
│   ├── admin/           # 관리자 페이지
│   ├── distributor/     # 총판 페이지
│   ├── agency/          # 대행사 페이지
│   └── auth/            # 인증 페이지
├── static/              # 정적 파일
│   ├── css/
│   ├── js/
│   └── img/
├── uploads/             # 업로드 파일
└── downloads/           # 다운로드 파일
```

## 데이터베이스 모델
- **User**: 사용자 정보 및 역할
- **ShoppingSlot**: 쇼핑 슬롯 데이터
- **PlaceSlot**: 플레이스 슬롯 데이터
- **SlotApproval**: 승인 요청
- **Settlement**: 정산 정보
- **SlotRefundRequest**: 환불 요청

## 워크플로우

### 슬롯 등록 프로세스
1. 총판이 빈 슬롯 생성
2. 대행사가 슬롯 정보 입력
3. 계층별 승인 진행
4. 승인 완료 시 'live' 상태로 변경
5. 자동 정산 처리

### 환불 프로세스
1. 사용자가 환불 요청
2. 관리자 승인
3. 남은 기간 비례 환불 계산
4. 정산 내역 업데이트

## 라이센스
이 프로젝트는 MIT 라이센스를 따릅니다.