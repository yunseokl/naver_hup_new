# GitHub 업로드 가이드

## 1. GitHub 저장소 생성
1. GitHub에 로그인
2. "New repository" 클릭
3. Repository name: `naver-ad-slot-manager`
4. Private/Public 선택
5. "Create repository" 클릭

## 2. 로컬에서 Git 초기화 및 업로드

터미널에서 다음 명령어 실행:

```bash
# Git 초기화
git init

# 모든 파일 추가
git add .

# 첫 커밋
git commit -m "Initial commit: 네이버 광고 슬롯 관리 시스템"

# GitHub 저장소 연결 (YOUR_USERNAME을 실제 GitHub 사용자명으로 변경)
git remote add origin https://github.com/YOUR_USERNAME/naver-ad-slot-manager.git

# main 브랜치로 변경
git branch -M main

# GitHub에 푸시
git push -u origin main
```

## 3. 중요 파일 목록

### 핵심 파일
- `app.py` - 메인 애플리케이션 로직
- `models.py` - 데이터베이스 모델
- `main.py` - 애플리케이션 엔트리 포인트
- `templates/` - HTML 템플릿
- `static/` - CSS, JavaScript 파일

### 설정 파일
- `.gitignore` - Git에서 제외할 파일 목록
- `README.md` - 프로젝트 설명
- `pyproject.toml` - Python 프로젝트 설정

## 4. 환경 변수 설정 (GitHub Secrets)

GitHub 저장소 설정에서 다음 시크릿 추가:
- `DATABASE_URL` - PostgreSQL 연결 문자열
- `SESSION_SECRET` - Flask 세션 시크릿 키

## 5. 배포 시 주의사항

- 데이터베이스는 별도로 준비 필요
- `uploads/`, `downloads/`, `export/` 폴더는 비어있음 (gitignore 처리됨)
- 기본 admin 계정 비밀번호 변경 필수

## 6. 다운로드 방법

현재 프로젝트를 ZIP 파일로 다운로드하려면:
1. Replit 에디터에서 파일 목록 상단의 점 3개 메뉴 클릭
2. "Download as zip" 선택

또는 터미널에서:
```bash
zip -r naver-ad-slot-manager.zip . -x "*.pyc" -x "__pycache__/*" -x ".git/*" -x "uploads/*" -x "downloads/*" -x "export/*"
```