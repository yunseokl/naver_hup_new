# 네이버 광고 슬롯 관리 시스템

## 프로젝트 개요
네이버 쇼핑 및 플레이스 광고 슬롯을 효율적으로 관리하기 위한 웹 애플리케이션입니다. 관리자, 총판, 대행사의 계층 구조를 통해 슬롯 할당 및 관리를 간소화하였습니다.

## 주요 기능
- 사용자 관리 (관리자/총판/대행사)
- 쇼핑 슬롯 관리
- 플레이스 슬롯 관리
- 슬롯 승인 워크플로우
- 정산 관리
- 엑셀 파일 일괄 업로드/다운로드
- 환불 시스템

## 시스템 요구사항
- Python 3.9 이상
- Flask 웹 프레임워크
- PostgreSQL 데이터베이스
- 기타 requirements.txt에 명시된 패키지

## 설치 방법
1. 의존성 설치:
```
pip install -r requirements.txt
```

2. 데이터베이스 연결 설정:
DATABASE_URL 환경 변수 설정 (PostgreSQL 연결 문자열)

3. 애플리케이션 실행:
```
gunicorn --bind 0.0.0.0:5000 main:app
```

## 관리자 계정
- 기본 관리자 계정: admin / adminpassword

## 프로젝트 구조
- `app.py`: 애플리케이션 라우팅 및 주요 비즈니스 로직
- `main.py`: 애플리케이션 진입점
- `models.py`: 데이터베이스 모델
- `templates/`: HTML 템플릿
- `static/`: 정적 파일 (CSS, JS, 이미지)
- `uploads/`: 업로드된 파일 저장 디렉토리
- `downloads/`: 다운로드용 파일 저장 디렉토리

## 정산 계산 방식
정산 계산은 다음 공식을 사용합니다:
```
정산 금액 = 30원 × 슬롯 1개(100유입) × 기간(일수)
```

## 슬롯 상태 흐름
- empty → pending → approved → live → inactive/refunded