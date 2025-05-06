import os
from datetime import datetime
from app import db

class ShoppingData(db.Model):
    """네이버 쇼핑 데이터 모델"""
    id = db.Column(db.Integer, primary_key=True)
    # 이미지에 있는 필드에 맞춰 수정
    select = db.Column(db.Boolean, default=False)  # 선택 여부
    store_type = db.Column(db.String(100))  # 스마트스토어/쇼핑 
    product_id = db.Column(db.String(100))  # 광고품ID
    shopping_campaign_id = db.Column(db.String(100))  # 쇼핑캠페인ID
    
    # 제품 관련 정보
    product_name = db.Column(db.String(200))  # 상품명
    keywords = db.Column(db.Text)  # 키워드 (쉼표로 구분)
    store_name = db.Column(db.String(100))  # 스토어명
    price = db.Column(db.Integer)  # 가격
    sale_price = db.Column(db.Integer)  # 세일가격
    
    # 성과 관련 정보
    impressions = db.Column(db.String(50))  # 노출수 (예: "0 / 1,280")
    amount = db.Column(db.String(50))  # 금액 (예: "1067000000")
    
    # 날짜 정보
    start_date = db.Column(db.String(50))  # 시작일 (예: "2025-05-29")
    end_date = db.Column(db.String(50))  # 종료일 (예: "2025-05-29")
    
    # 기타 정보
    bid_type = db.Column(db.String(50))  # 입찰방식 (예: "10원")
    targeting = db.Column(db.String(20))  # 타겟팅 (예: "MC")
    
    filename = db.Column(db.String(255))  # 업로드된 파일명
    original_filename = db.Column(db.String(255))  # 원래 파일명
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ShoppingData {self.product_name}>'
    
    @classmethod
    def from_dict(cls, data, filename=None, original_filename=None):
        """딕셔너리에서 ShoppingData 객체 생성"""
        return cls(
            select=data.get('select', False),
            store_type=data.get('store_type'),
            product_id=data.get('product_id'),
            shopping_campaign_id=data.get('shopping_campaign_id'),
            product_name=data.get('product_name'),
            keywords=data.get('keywords'),
            store_name=data.get('store_name'),
            price=data.get('price'),
            sale_price=data.get('sale_price'),
            impressions=data.get('impressions'),
            amount=data.get('amount'),
            start_date=data.get('start_date'),
            end_date=data.get('end_date'),
            bid_type=data.get('bid_type'),
            targeting=data.get('targeting'),
            filename=filename,
            original_filename=original_filename
        )

class PlaceData(db.Model):
    """네이버 플레이스 데이터 모델"""
    id = db.Column(db.Integer, primary_key=True)
    # 이미지에 있는 필드에 맞춰 수정
    select = db.Column(db.Boolean, default=False)  # 선택 여부
    place_id = db.Column(db.String(100))  # 광고주ID
    business_category = db.Column(db.String(100))  # 업종분류 코드
    business_type = db.Column(db.String(100))  # 업종분류 명
    
    # 장소 관련 정보
    place_name = db.Column(db.String(200))  # 키워드
    address = db.Column(db.String(300))  # 주소
    
    # 수치 정보
    impressions = db.Column(db.String(50))  # 노출수/클릭수 (예: "161 / 2,520")
    cost = db.Column(db.String(50))  # 비용
    
    # 상태 정보
    status = db.Column(db.String(100))  # 상태 (예: "심사중", "ON", "OFF")
    status_reason = db.Column(db.String(100))  # 상태 이유
    status_detail = db.Column(db.String(255))  # 상태 상세 (예: "경쟁입찰(PCMB)")
    
    # 날짜 정보
    start_date = db.Column(db.String(50))  # 시작일 (예: "2025-05-06")
    end_date = db.Column(db.String(50))  # 종료일 (예: "2025-05-20")
    deadline_date = db.Column(db.String(50))  # 마감일 (예: "2025-05-20T")
    
    filename = db.Column(db.String(255))  # 업로드된 파일명
    original_filename = db.Column(db.String(255))  # 원래 파일명
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<PlaceData {self.place_name}>'
    
    @classmethod
    def from_dict(cls, data, filename=None, original_filename=None):
        """딕셔너리에서 PlaceData 객체 생성"""
        return cls(
            select=data.get('select', False),
            place_id=data.get('place_id'),
            business_category=data.get('business_category'),
            business_type=data.get('business_type'),
            place_name=data.get('place_name'),
            address=data.get('address'),
            impressions=data.get('impressions'),
            cost=data.get('cost'),
            status=data.get('status'),
            status_reason=data.get('status_reason'),
            status_detail=data.get('status_detail'),
            start_date=data.get('start_date'),
            end_date=data.get('end_date'),
            deadline_date=data.get('deadline_date'),
            filename=filename,
            original_filename=original_filename
        )