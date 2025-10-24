"""
models.py 모듈 테스트
"""
import pytest
from datetime import date, datetime
from models import User, Role, ShoppingSlot, PlaceSlot, SlotQuota, SlotApproval
from app import db


class TestUserModel:
    """User 모델 테스트"""
    
    def test_create_user(self, app):
        """사용자 생성"""
        role = Role.query.filter_by(name='admin').first()
        user = User(
            username='testuser',
            email='test@example.com',
            company_name='Test Company',
            phone='010-1234-5678',
            role=role,
            is_active=True
        )
        user.set_password('Test1234')
        
        db.session.add(user)
        db.session.commit()
        
        assert user.id is not None
        assert user.username == 'testuser'
        assert user.email == 'test@example.com'
        assert user.check_password('Test1234')
        assert not user.check_password('wrong')
    
    def test_user_roles(self, app, admin_user, distributor_user, agency_user):
        """사용자 역할 확인"""
        assert admin_user.is_admin()
        assert not admin_user.is_distributor()
        assert not admin_user.is_agency()
        
        assert distributor_user.is_distributor()
        assert not distributor_user.is_admin()
        assert not distributor_user.is_agency()
        
        assert agency_user.is_agency()
        assert not agency_user.is_admin()
        assert not agency_user.is_distributor()
    
    def test_user_hierarchy(self, app, distributor_user, agency_user):
        """사용자 계층 구조"""
        assert agency_user.distributor == distributor_user
        assert agency_user in distributor_user.agencies.all()
    
    def test_password_hashing(self, app):
        """비밀번호 해싱"""
        role = Role.query.filter_by(name='admin').first()
        user = User(
            username='pwtest',
            email='pwtest@test.com',
            role=role
        )
        
        # 비밀번호 설정
        user.set_password('MyPassword123')
        
        # 비밀번호가 해싱되어 저장됨
        assert user.password_hash != 'MyPassword123'
        
        # 올바른 비밀번호 확인
        assert user.check_password('MyPassword123')
        
        # 잘못된 비밀번호 확인
        assert not user.check_password('WrongPassword')


class TestShoppingSlotModel:
    """ShoppingSlot 모델 테스트"""
    
    def test_create_shopping_slot(self, app, agency_user):
        """쇼핑 슬롯 생성"""
        slot = ShoppingSlot(
            user=agency_user,
            slot_name='테스트 슬롯',
            status='pending',
            slot_type='standard',
            product_name='테스트 상품',
            slot_price=100000,
            start_date=date(2024, 1, 1),
            end_date=date(2024, 1, 31)
        )
        
        db.session.add(slot)
        db.session.commit()
        
        assert slot.id is not None
        assert slot.slot_name == '테스트 슬롯'
        assert slot.status == 'pending'
        assert slot.user == agency_user
        assert slot.slot_price == 100000
    
    def test_shopping_slot_relationships(self, app, agency_user):
        """쇼핑 슬롯 관계"""
        slot = ShoppingSlot(
            user=agency_user,
            slot_name='관계 테스트',
            status='pending',
            slot_price=50000
        )
        
        db.session.add(slot)
        db.session.commit()
        
        # 사용자와의 관계
        assert slot in agency_user.shopping_slots.all()
        
        # 승인 요청 관계
        approval = SlotApproval(
            requester=agency_user,
            shopping_slot=slot,
            approval_type='create',
            status='pending'
        )
        db.session.add(approval)
        db.session.commit()
        
        assert approval in slot.approvals.all()


class TestPlaceSlotModel:
    """PlaceSlot 모델 테스트"""
    
    def test_create_place_slot(self, app, agency_user):
        """플레이스 슬롯 생성"""
        slot = PlaceSlot(
            user=agency_user,
            slot_name='테스트 플레이스',
            status='pending',
            slot_type='search',
            place_name='테스트 장소',
            address='서울시 강남구',
            slot_price=80000,
            start_date=date(2024, 1, 1),
            end_date=date(2024, 1, 31)
        )
        
        db.session.add(slot)
        db.session.commit()
        
        assert slot.id is not None
        assert slot.slot_name == '테스트 플레이스'
        assert slot.place_name == '테스트 장소'
        assert slot.slot_type == 'search'


class TestSlotQuotaModel:
    """SlotQuota 모델 테스트"""
    
    def test_quota_limits(self, app, agency_user):
        """할당량 제한 확인"""
        quota = agency_user.quota
        
        assert quota is not None
        assert quota.shopping_slots_limit == 50
        assert quota.place_slots_limit == 50
        assert quota.shopping_slots_used == 0
        assert quota.place_slots_used == 0
    
    def test_can_use_slot(self, app, agency_user):
        """슬롯 사용 가능 여부"""
        quota = agency_user.quota
        
        # 초기 상태: 사용 가능
        assert quota.can_use_shopping_slot() is True
        assert quota.can_use_place_slot() is True
        
        # 한계까지 사용
        quota.shopping_slots_used = quota.shopping_slots_limit
        db.session.commit()
        
        # 더 이상 사용 불가
        assert quota.can_use_shopping_slot() is False
        assert quota.can_use_place_slot() is True  # 플레이스는 여전히 가능


class TestSlotApprovalModel:
    """SlotApproval 모델 테스트"""
    
    def test_create_approval(self, app, agency_user, distributor_user):
        """승인 요청 생성"""
        slot = ShoppingSlot(
            user=agency_user,
            slot_name='승인 테스트',
            status='pending',
            slot_price=100000
        )
        db.session.add(slot)
        db.session.commit()
        
        approval = SlotApproval(
            requester=agency_user,
            approver=distributor_user,
            shopping_slot=slot,
            approval_type='create',
            status='pending',
            comment='테스트 승인 요청'
        )
        db.session.add(approval)
        db.session.commit()
        
        assert approval.id is not None
        assert approval.requester == agency_user
        assert approval.approver == distributor_user
        assert approval.slot_type == 'shopping'
        assert approval.slot == slot
    
    def test_approval_slot_type(self, app, agency_user):
        """승인 요청 슬롯 타입 확인"""
        # 쇼핑 슬롯
        shopping_slot = ShoppingSlot(
            user=agency_user,
            slot_name='쇼핑 슬롯',
            status='pending'
        )
        db.session.add(shopping_slot)
        db.session.commit()
        
        shopping_approval = SlotApproval(
            requester=agency_user,
            shopping_slot=shopping_slot,
            approval_type='create',
            status='pending'
        )
        db.session.add(shopping_approval)
        db.session.commit()
        
        assert shopping_approval.slot_type == 'shopping'
        
        # 플레이스 슬롯
        place_slot = PlaceSlot(
            user=agency_user,
            slot_name='플레이스 슬롯',
            status='pending'
        )
        db.session.add(place_slot)
        db.session.commit()
        
        place_approval = SlotApproval(
            requester=agency_user,
            place_slot=place_slot,
            approval_type='create',
            status='pending'
        )
        db.session.add(place_approval)
        db.session.commit()
        
        assert place_approval.slot_type == 'place'


class TestRoleModel:
    """Role 모델 테스트"""
    
    def test_roles_exist(self, app):
        """기본 역할 존재 확인"""
        admin_role = Role.query.filter_by(name='admin').first()
        distributor_role = Role.query.filter_by(name='distributor').first()
        agency_role = Role.query.filter_by(name='agency').first()
        
        assert admin_role is not None
        assert distributor_role is not None
        assert agency_role is not None
    
    def test_role_relationships(self, app, admin_user):
        """역할 관계 확인"""
        admin_role = Role.query.filter_by(name='admin').first()
        
        assert admin_user in admin_role.users.all()
