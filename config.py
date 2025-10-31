"""
애플리케이션 설정 모듈
환경별 설정을 관리하는 Config 클래스들
"""
import os
from datetime import timedelta


class Config:
    """기본 설정"""
    
    # 기본 Flask 설정
    SECRET_KEY = os.environ.get('SESSION_SECRET', 'dev-secret-key-change-in-production')
    
    # 데이터베이스 설정
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 300,
        'pool_pre_ping': True,
        'pool_size': 10,
        'max_overflow': 20,
        'pool_timeout': 30,
        'echo': False,
    }
    
    # 파일 업로드 설정
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 64 * 1024 * 1024))
    ALLOWED_EXTENSIONS = {'xlsx', 'xls'}
    
    # 세션 설정
    SESSION_COOKIE_SECURE = False  # 개발 환경에서는 False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # CSRF 설정
    WTF_CSRF_TIME_LIMIT = None
    WTF_CSRF_ENABLED = True
    
    # 로깅 설정
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'logs/app.log')
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 5
    
    # 페이지네이션 설정
    ITEMS_PER_PAGE = 20
    MAX_ITEMS_PER_PAGE = 100
    
    # 이메일 설정 (선택사항)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')


class DevelopmentConfig(Config):
    """개발 환경 설정"""
    DEBUG = True
    TESTING = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        **Config.SQLALCHEMY_ENGINE_OPTIONS,
        'echo': True,  # SQL 쿼리 로깅 활성화
    }


class ProductionConfig(Config):
    """프로덕션 환경 설정"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True  # HTTPS 전용
    
    # 프로덕션에서는 SECRET_KEY 필수
    @property
    def SECRET_KEY(self):
        secret_key = os.environ.get('SESSION_SECRET')
        if not secret_key or secret_key == 'dev-secret-key-change-in-production':
            raise ValueError('프로덕션 환경에서는 SESSION_SECRET 환경변수를 반드시 설정해야 합니다.')
        return secret_key


class TestingConfig(Config):
    """테스트 환경 설정"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'  # 인메모리 데이터베이스
    SQLALCHEMY_ENGINE_OPTIONS = {}  # SQLite는 pool 옵션 불필요
    WTF_CSRF_ENABLED = False  # 테스트에서는 CSRF 비활성화


# 환경별 설정 매핑
config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config(env_name=None):
    """환경 이름으로 설정 클래스 가져오기"""
    if env_name is None:
        env_name = os.environ.get('FLASK_ENV', 'development')
    return config_by_name.get(env_name, DevelopmentConfig)
