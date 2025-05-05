import os
from datetime import datetime
from app import db

class ShoppingData(db.Model):
    """네이버 쇼핑 데이터 모델"""
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(200), nullable=False)  # 제품명 (필수)
    price = db.Column(db.Integer, nullable=False)  # 가격 (필수)
    category = db.Column(db.String(100), nullable=False)  # 카테고리 (필수)
    brand = db.Column(db.String(100))  # 브랜드
    description = db.Column(db.Text)  # 제품 설명
    features = db.Column(db.Text)  # 제품 특징
    specifications = db.Column(db.Text)  # 제품 사양
    shipping_info = db.Column(db.Text)  # 배송 정보
    filename = db.Column(db.String(255))  # 업로드된 파일명
    original_filename = db.Column(db.String(255))  # 원래 파일명
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ShoppingData {self.product_name}>'
    
    @classmethod
    def from_dict(cls, data, filename=None, original_filename=None):
        """딕셔너리에서 ShoppingData 객체 생성"""
        return cls(
            product_name=data.get('product_name'),
            price=data.get('price'),
            category=data.get('category'),
            brand=data.get('brand'),
            description=data.get('description'),
            features=data.get('features'),
            specifications=data.get('specifications'),
            shipping_info=data.get('shipping_info'),
            filename=filename,
            original_filename=original_filename
        )

class PlaceData(db.Model):
    """네이버 플레이스 데이터 모델"""
    id = db.Column(db.Integer, primary_key=True)
    place_name = db.Column(db.String(200), nullable=False)  # 장소명 (필수)
    category = db.Column(db.String(100), nullable=False)  # 카테고리 (필수)
    address = db.Column(db.String(300), nullable=False)  # 주소 (필수)
    phone = db.Column(db.String(20))  # 전화번호
    business_hours = db.Column(db.Text)  # 영업시간
    description = db.Column(db.Text)  # 설명
    website = db.Column(db.String(255))  # 웹사이트
    parking_info = db.Column(db.Text)  # 주차 정보
    filename = db.Column(db.String(255))  # 업로드된 파일명
    original_filename = db.Column(db.String(255))  # 원래 파일명
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<PlaceData {self.place_name}>'
    
    @classmethod
    def from_dict(cls, data, filename=None, original_filename=None):
        """딕셔너리에서 PlaceData 객체 생성"""
        return cls(
            place_name=data.get('place_name'),
            category=data.get('category'),
            address=data.get('address'),
            phone=data.get('phone'),
            business_hours=data.get('business_hours'),
            description=data.get('description'),
            website=data.get('website'),
            parking_info=data.get('parking_info'),
            filename=filename,
            original_filename=original_filename
        )