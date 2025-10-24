"""
pytest 설정 및 픽스처 정의
"""
import pytest
import sys
import os

# 상위 디렉토리를 Python 경로에 추가
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app as flask_app, db
from models import User, Role, ShoppingSlot, PlaceSlot, SlotQuota
from config import TestingConfig


@pytest.fixture
def app():
    """Flask 애플리케이션 픽스처"""
    # 테스트용 DATABASE_URL 설정
    os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
    flask_app.config.from_object(TestingConfig)
    
    with flask_app.app_context():
        db.create_all()
        
        # 기본 역할 생성
        roles_data = {
            'admin': '시스템 관리자',
            'distributor': '총판',
            'agency': '대행사'
        }
        
        for role_name, description in roles_data.items():
            role = Role(name=role_name, description=description)
            db.session.add(role)
        
        db.session.commit()
        
        yield flask_app
        
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """테스트 클라이언트 픽스처"""
    return app.test_client()


@pytest.fixture
def runner(app):
    """CLI 러너 픽스처"""
    return app.test_cli_runner()


@pytest.fixture
def admin_user(app):
    """관리자 사용자 픽스처"""
    role = Role.query.filter_by(name='admin').first()
    user = User(
        username='admin',
        email='admin@test.com',
        company_name='Test Admin',
        phone='010-1234-5678',
        role=role,
        is_active=True
    )
    user.set_password('Admin1234')
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def distributor_user(app):
    """총판 사용자 픽스처"""
    role = Role.query.filter_by(name='distributor').first()
    user = User(
        username='distributor',
        email='distributor@test.com',
        company_name='Test Distributor',
        phone='010-2345-6789',
        role=role,
        is_active=True
    )
    user.set_password('Dist1234')
    db.session.add(user)
    
    # 슬롯 할당량 생성
    quota = SlotQuota(
        user=user,
        shopping_slots_limit=100,
        place_slots_limit=100,
        shopping_slots_used=0,
        place_slots_used=0
    )
    db.session.add(quota)
    
    db.session.commit()
    return user


@pytest.fixture
def agency_user(app, distributor_user):
    """대행사 사용자 픽스처"""
    role = Role.query.filter_by(name='agency').first()
    user = User(
        username='agency',
        email='agency@test.com',
        company_name='Test Agency',
        phone='010-3456-7890',
        role=role,
        parent_id=distributor_user.id,
        is_active=True
    )
    user.set_password('Agency1234')
    db.session.add(user)
    
    # 슬롯 할당량 생성
    quota = SlotQuota(
        user=user,
        shopping_slots_limit=50,
        place_slots_limit=50,
        shopping_slots_used=0,
        place_slots_used=0
    )
    db.session.add(quota)
    
    db.session.commit()
    return user


@pytest.fixture
def authenticated_client(client, admin_user):
    """인증된 클라이언트 픽스처"""
    client.post('/login', data={
        'username': 'admin',
        'password': 'Admin1234'
    })
    return client
