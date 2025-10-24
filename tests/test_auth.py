"""
인증 및 권한 테스트
"""
import pytest
from flask import session
from models import User, Role
from app import db


class TestLogin:
    """로그인 기능 테스트"""
    
    def test_login_page_loads(self, client):
        """로그인 페이지 로드"""
        response = client.get('/login')
        assert response.status_code == 200
        assert b'login' in response.data.lower() or b'\xeb\xa1\x9c\xea\xb7\xb8\xec\x9d\xb8' in response.data  # '로그인' in UTF-8
    
    def test_successful_login(self, client, admin_user):
        """성공적인 로그인"""
        response = client.post('/login', data={
            'username': 'admin',
            'password': 'Admin1234'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        # 대시보드로 리다이렉트 확인
        assert b'dashboard' in response.data.lower() or b'\xeb\x8c\x80\xec\x8b\x9c\xeb\xb3\xb4\xeb\x93\x9c' in response.data
    
    def test_failed_login_wrong_password(self, client, admin_user):
        """잘못된 비밀번호로 로그인 시도"""
        response = client.post('/login', data={
            'username': 'admin',
            'password': 'wrongpassword'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        # 에러 메시지 확인
        assert b'error' in response.data.lower() or b'\xec\x98\xa4\xeb\xa5\x98' in response.data or b'\xec\x9e\x98\xeb\xaa\xbb' in response.data
    
    def test_failed_login_nonexistent_user(self, client):
        """존재하지 않는 사용자로 로그인 시도"""
        response = client.post('/login', data={
            'username': 'nonexistent',
            'password': 'Test1234'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'error' in response.data.lower() or b'\xec\x98\xa4\xeb\xa5\x98' in response.data
    
    def test_logout(self, client, admin_user):
        """로그아웃"""
        # 로그인
        client.post('/login', data={
            'username': 'admin',
            'password': 'Admin1234'
        })
        
        # 로그아웃
        response = client.get('/logout', follow_redirects=True)
        assert response.status_code == 200
        
        # 대시보드 접근 시도 (리다이렉트되어야 함)
        response = client.get('/dashboard')
        assert response.status_code == 302  # 리다이렉트
    
    def test_login_required_redirect(self, client):
        """로그인 없이 보호된 페이지 접근"""
        response = client.get('/dashboard')
        assert response.status_code == 302  # 로그인 페이지로 리다이렉트
        assert b'login' in response.location.lower()


class TestRegistration:
    """회원가입 기능 테스트"""
    
    def test_registration_page_loads(self, client):
        """회원가입 페이지 로드"""
        response = client.get('/register')
        assert response.status_code == 200
        assert b'register' in response.data.lower() or b'\xed\x9a\x8c\xec\x9b\x90\xea\xb0\x80\xec\x9e\x85' in response.data
    
    def test_successful_registration_distributor(self, client, app):
        """총판 회원가입 성공"""
        role = Role.query.filter_by(name='distributor').first()
        
        response = client.post('/register', data={
            'username': 'newdist',
            'email': 'newdist@test.com',
            'password': 'Test1234',
            'confirm_password': 'Test1234',
            'company_name': 'New Distributor',
            'phone': '010-9999-8888',
            'role_id': role.id,
            'agree_terms': 'on'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        
        # 사용자가 생성되었는지 확인
        user = User.query.filter_by(username='newdist').first()
        assert user is not None
        assert user.email == 'newdist@test.com'
        assert user.is_active is False  # 승인 대기 상태
    
    def test_successful_registration_agency(self, client, app, distributor_user):
        """대행사 회원가입 성공"""
        role = Role.query.filter_by(name='agency').first()
        
        response = client.post('/register', data={
            'username': 'newagency',
            'email': 'newagency@test.com',
            'password': 'Test1234',
            'confirm_password': 'Test1234',
            'company_name': 'New Agency',
            'phone': '010-8888-7777',
            'role_id': role.id,
            'parent_id': distributor_user.id,
            'agree_terms': 'on'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        
        user = User.query.filter_by(username='newagency').first()
        assert user is not None
        assert user.parent_id == distributor_user.id
    
    def test_registration_password_mismatch(self, client, app):
        """비밀번호 불일치"""
        role = Role.query.filter_by(name='distributor').first()
        
        response = client.post('/register', data={
            'username': 'testuser',
            'email': 'test@test.com',
            'password': 'Test1234',
            'confirm_password': 'Different1234',
            'company_name': 'Test Company',
            'phone': '010-1111-2222',
            'role_id': role.id,
            'agree_terms': 'on'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'error' in response.data.lower() or b'\xec\x9d\xbc\xec\xb9\x98' in response.data
    
    def test_registration_weak_password(self, client, app):
        """약한 비밀번호"""
        role = Role.query.filter_by(name='distributor').first()
        
        response = client.post('/register', data={
            'username': 'testuser',
            'email': 'test@test.com',
            'password': 'weak',
            'confirm_password': 'weak',
            'company_name': 'Test Company',
            'phone': '010-1111-2222',
            'role_id': role.id,
            'agree_terms': 'on'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        # 비밀번호 복잡도 에러
        assert b'8' in response.data or b'\xeb\xb9\x84\xeb\xb0\x80\xeb\xb2\x88\xed\x98\xb8' in response.data
    
    def test_registration_duplicate_username(self, client, app, admin_user):
        """중복 사용자명"""
        role = Role.query.filter_by(name='distributor').first()
        
        response = client.post('/register', data={
            'username': 'admin',  # 이미 존재하는 사용자명
            'email': 'newemail@test.com',
            'password': 'Test1234',
            'confirm_password': 'Test1234',
            'company_name': 'Test Company',
            'phone': '010-1111-2222',
            'role_id': role.id,
            'agree_terms': 'on'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'\xec\x9d\xb4\xeb\xaf\xb8' in response.data or b'already' in response.data.lower()
    
    def test_registration_duplicate_email(self, client, app, admin_user):
        """중복 이메일"""
        role = Role.query.filter_by(name='distributor').first()
        
        response = client.post('/register', data={
            'username': 'newuser',
            'email': 'admin@test.com',  # 이미 존재하는 이메일
            'password': 'Test1234',
            'confirm_password': 'Test1234',
            'company_name': 'Test Company',
            'phone': '010-1111-2222',
            'role_id': role.id,
            'agree_terms': 'on'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'\xec\x9d\xb4\xeb\xaf\xb8' in response.data or b'already' in response.data.lower()
    
    def test_registration_no_terms_agreement(self, client, app):
        """약관 동의 없음"""
        role = Role.query.filter_by(name='distributor').first()
        
        response = client.post('/register', data={
            'username': 'testuser',
            'email': 'test@test.com',
            'password': 'Test1234',
            'confirm_password': 'Test1234',
            'company_name': 'Test Company',
            'phone': '010-1111-2222',
            'role_id': role.id
            # agree_terms 누락
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'\xeb\x8f\x99\xec\x9d\x98' in response.data or b'terms' in response.data.lower()


class TestAccessControl:
    """접근 제어 테스트"""
    
    def test_admin_access(self, client, admin_user):
        """관리자 페이지 접근"""
        client.post('/login', data={
            'username': 'admin',
            'password': 'Admin1234'
        })
        
        response = client.get('/admin/dashboard')
        assert response.status_code == 200
    
    def test_non_admin_cannot_access_admin_page(self, client, agency_user):
        """비관리자는 관리자 페이지 접근 불가"""
        client.post('/login', data={
            'username': 'agency',
            'password': 'Agency1234'
        })
        
        response = client.get('/admin/dashboard')
        assert response.status_code == 403 or response.status_code == 302
    
    def test_distributor_access(self, client, distributor_user):
        """총판 페이지 접근"""
        client.post('/login', data={
            'username': 'distributor',
            'password': 'Dist1234'
        })
        
        response = client.get('/distributor/dashboard')
        assert response.status_code == 200
    
    def test_agency_access(self, client, agency_user):
        """대행사 페이지 접근"""
        client.post('/login', data={
            'username': 'agency',
            'password': 'Agency1234'
        })
        
        response = client.get('/agency/dashboard')
        assert response.status_code == 200
