# 네이버 광고 슬롯 관리 시스템

네이버 쇼핑 및 플레이스 광고 슬롯을 효율적으로 관리하는 웹 애플리케이션입니다.

## 주요 기능

### 사용자 계층 구조
- **관리자 (Admin)**: 전체 시스템 관리
- **총판 (Distributor)**: 대행사 관리 및 슬롯 할당
- **대행사 (Agency)**: 슬롯 등록 및 관리

### 핵심 기능
1. **슬롯 관리**
   - 쇼핑 슬롯 관리
   - 플레이스 슬롯 관리
   - 엑셀 일괄 업로드/다운로드

2. **승인 워크플로우**
   - 계층적 승인 프로세스
   - 슬롯 생성/수정/삭제 승인

3. **정산 시스템**
   - 자동 정산 계산
   - 환불 처리
   - 정산 내역 관리

## 기술 스택
- **Backend**: Flask (Python)
- **Database**: PostgreSQL
- **Frontend**: Bootstrap 5 (Dark Theme)
- **Authentication**: Flask-Login

## 설치 방법

1. 저장소 클론
```bash
git clone [repository-url]
cd naver-ad-slot-manager
```

2. 필요한 패키지 설치
```bash
pip install -r requirements.txt
```

3. 환경 변수 설정
```bash
DATABASE_URL=postgresql://user:password@host:port/dbname
SESSION_SECRET=your-secret-key
```

4. 데이터베이스 초기화
```bash
python app.py
```

5. 애플리케이션 실행
```bash
gunicorn --bind 0.0.0.0:5000 main:app
```

## 기본 계정
- Username: admin
- Password: adminpassword

## 라이센스
이 프로젝트는 비공개 프로젝트입니다.