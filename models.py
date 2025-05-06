import os
from datetime import datetime
from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# 사용자 역할 정의
class Role(db.Model):
    """사용자 역할 모델"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)  # admin, distributor(총판), agency(대행사)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    users = db.relationship('User', backref='role', lazy='dynamic')
    
    def __repr__(self):
        return f'<Role {self.name}>'

# 사용자 모델
class User(UserMixin, db.Model):
    """사용자 모델"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    company_name = db.Column(db.String(100))  # 회사명
    phone = db.Column(db.String(20))  # 연락처
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # 역할 관계
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    
    # 총판인 경우, 관리하는 대행사 관계
    parent_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    agencies = db.relationship('User', backref=db.backref('distributor', remote_side=[id]), lazy='dynamic')
    
    # 슬롯 관계
    shopping_slots = db.relationship('ShoppingSlot', backref='user', lazy='dynamic')
    place_slots = db.relationship('PlaceSlot', backref='user', lazy='dynamic')
    
    # 승인 요청 관계
    approvals_requested = db.relationship('SlotApproval', foreign_keys='SlotApproval.requester_id', backref='requester', lazy='dynamic')
    approvals_handled = db.relationship('SlotApproval', foreign_keys='SlotApproval.approver_id', backref='approver', lazy='dynamic')
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role.name == 'admin'
    
    def is_distributor(self):
        return self.role.name == 'distributor'
    
    def is_agency(self):
        return self.role.name == 'agency'

# 쇼핑 슬롯 모델
class ShoppingSlot(db.Model):
    """쇼핑 슬롯 모델"""
    id = db.Column(db.Integer, primary_key=True)
    is_selected = db.Column(db.Boolean, default=False)  # 선택 여부
    
    # 소유자 정보
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # 상태 정보
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected, active, inactive
    
    # 슬롯 기본 정보
    slot_name = db.Column(db.String(100), nullable=False)  # 슬롯 이름
    store_type = db.Column(db.String(50))  # 스마트스토어/쇼핑 
    product_id = db.Column(db.String(100))  # 광고품ID
    shopping_campaign_id = db.Column(db.String(100))  # 쇼핑캠페인ID
    
    # 제품 관련 정보
    product_name = db.Column(db.String(200))  # 상품명
    keywords = db.Column(db.Text)  # 키워드 (쉼표로 구분)
    store_name = db.Column(db.String(100))  # 스토어명
    price = db.Column(db.Integer)  # 가격
    sale_price = db.Column(db.Integer)  # 세일가격
    product_image_url = db.Column(db.String(255))  # 제품 이미지 URL
    
    # 성과 관련 정보
    impressions = db.Column(db.String(50))  # 노출수
    clicks = db.Column(db.String(50))  # 클릭수
    amount = db.Column(db.String(50))  # 금액
    
    # 날짜 정보
    start_date = db.Column(db.Date)  # 시작일
    end_date = db.Column(db.Date)  # 종료일
    
    # 기타 정보
    bid_type = db.Column(db.String(50))  # 입찰방식
    targeting = db.Column(db.String(20))  # 타겟팅
    
    # 슬롯 관련 정보
    slot_price = db.Column(db.Integer)  # 슬롯 단가 (원)
    admin_price = db.Column(db.Integer)  # 어드민 정산가 (원)
    settlement_status = db.Column(db.String(20), default='pending')  # 정산 상태 (pending, completed)
    notes = db.Column(db.Text)  # 메모
    
    # 파일 정보
    filename = db.Column(db.String(255))  # 업로드된 파일명
    original_filename = db.Column(db.String(255))  # 원래 파일명
    
    # 시스템 정보
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    # 승인 관계
    approvals = db.relationship('SlotApproval', backref='shopping_slot', lazy='dynamic', 
                              foreign_keys='SlotApproval.shopping_slot_id')
    
    def __repr__(self):
        return f'<ShoppingSlot {self.slot_name}>'

# 플레이스 슬롯 모델
class PlaceSlot(db.Model):
    """플레이스 슬롯 모델"""
    id = db.Column(db.Integer, primary_key=True)
    is_selected = db.Column(db.Boolean, default=False)  # 선택 여부
    
    # 소유자 정보
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # 상태 정보
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected, active, inactive
    
    # 슬롯 기본 정보
    slot_name = db.Column(db.String(100), nullable=False)  # 슬롯 이름
    place_id = db.Column(db.String(100))  # 광고주ID
    business_category = db.Column(db.String(100))  # 업종분류 코드
    business_type = db.Column(db.String(100))  # 업종분류 명
    
    # 장소 관련 정보
    place_name = db.Column(db.String(200))  # 키워드
    address = db.Column(db.String(300))  # 주소
    
    # 수치 정보
    impressions = db.Column(db.String(50))  # 노출수
    clicks = db.Column(db.String(50))  # 클릭수
    cost = db.Column(db.String(50))  # 비용
    
    # 상태 정보
    operation_status = db.Column(db.String(100))  # 운영 상태 (예: "심사중", "ON", "OFF")
    status_reason = db.Column(db.String(100))  # 상태 이유
    status_detail = db.Column(db.String(255))  # 상태 상세 (예: "경쟁입찰(PCMB)")
    
    # 날짜 정보
    start_date = db.Column(db.Date)  # 시작일
    end_date = db.Column(db.Date)  # 종료일
    deadline_date = db.Column(db.Date)  # 마감일
    
    # 슬롯 관련 정보
    slot_price = db.Column(db.Integer)  # 슬롯 단가 (원)
    admin_price = db.Column(db.Integer)  # 어드민 정산가 (원)
    settlement_status = db.Column(db.String(20), default='pending')  # 정산 상태 (pending, completed)
    notes = db.Column(db.Text)  # 메모
    
    # 파일 정보
    filename = db.Column(db.String(255))  # 업로드된 파일명
    original_filename = db.Column(db.String(255))  # 원래 파일명
    
    # 시스템 정보
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    # 승인 관계
    approvals = db.relationship('SlotApproval', backref='place_slot', lazy='dynamic',
                              foreign_keys='SlotApproval.place_slot_id')
    
    def __repr__(self):
        return f'<PlaceSlot {self.slot_name}>'

# 슬롯 승인 모델
class SlotApproval(db.Model):
    """슬롯 승인 요청 모델"""
    id = db.Column(db.Integer, primary_key=True)
    
    # 관계 정보
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # 요청자 (대행사)
    approver_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # 승인자 (총판 또는 관리자)
    
    # 슬롯 정보 (둘 중 하나만 설정)
    shopping_slot_id = db.Column(db.Integer, db.ForeignKey('shopping_slot.id'))
    place_slot_id = db.Column(db.Integer, db.ForeignKey('place_slot.id'))
    
    # 승인 정보
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    approval_type = db.Column(db.String(20), nullable=False)  # create, update, delete
    comment = db.Column(db.Text)  # 승인/거절 코멘트
    
    # 시간 정보
    requested_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime)  # 처리 시간
    
    def __repr__(self):
        return f'<SlotApproval {self.id}: {self.status}>'
    
    @property
    def slot_type(self):
        if self.shopping_slot_id:
            return 'shopping'
        elif self.place_slot_id:
            return 'place'
        return None
    
    @property
    def slot(self):
        if self.shopping_slot_id:
            return self.shopping_slot
        elif self.place_slot_id:
            return self.place_slot
        return None