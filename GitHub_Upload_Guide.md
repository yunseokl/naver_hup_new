# GitHub 업로드 가이드

## 1. GitHub 저장소 생성
1. GitHub에 로그인하고 새 저장소를 생성하세요
2. 저장소 이름: `naver-ad-slot-manager`
3. Description: "네이버 쇼핑/플레이스 광고 슬롯 관리 시스템"
4. Public 또는 Private 선택
5. README.md 추가하지 않기 (이미 프로젝트에 포함됨)

## 2. 로컬에서 Git 설정 (터미널에서 실행)

```bash
# Git 사용자 정보 설정 (최초 1회만)
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# 프로젝트 폴더로 이동
cd /path/to/your/project

# Git 저장소 초기화 (이미 되어있다면 생략)
git init

# 모든 파일 추가
git add .

# 커밋 생성
git commit -m "Initial commit: 네이버 광고 슬롯 관리 시스템"

# GitHub 저장소와 연결
git remote add origin https://github.com/YOUR_USERNAME/naver-ad-slot-manager.git

# GitHub에 업로드
git push -u origin main
```

## 3. 주요 파일 설명
- `app.py`: 메인 애플리케이션 파일
- `main.py`: 진입점
- `models.py`: 데이터베이스 모델
- `templates/`: HTML 템플릿 파일들
- `static/`: CSS, JS, 이미지 파일들
- `requirements.txt`: Python 의존성 패키지 목록
- `.gitignore`: Git에서 제외할 파일 목록

## 4. 프로젝트 설명 추가
GitHub 저장소의 README.md를 수정하여 프로젝트 설명을 추가하세요.

## 5. 배포 시 주의사항
- DATABASE_URL 환경변수 설정 필요
- 기본 관리자 계정: admin / adminpassword
- Python 3.9 이상 필요