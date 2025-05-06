import os
import logging
import uuid
import pandas as pd
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort
from flask import g, current_app
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Define the database base
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)

# Create the Flask application
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64MB max upload size
app.config["ALLOWED_EXTENSIONS"] = {'xlsx', 'xls'}

# Initialize the database with the app
db.init_app(app)

# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = '이 페이지에 접근하려면 로그인이 필요합니다.'
login_manager.login_message_category = 'warning'

# Import models after initializing db to avoid circular imports
from models import User, Role, ShoppingSlot, PlaceSlot, SlotApproval

# 초기화 함수를 생성합니다
def create_tables_and_defaults():
    """애플리케이션 초기 설정 - 테이블 생성 및 기본 사용자/역할 설정"""
    with app.app_context():
        db.create_all()
        
        # 기본 역할 생성
        roles = {
            'admin': '시스템 관리자',
            'distributor': '총판',
            'agency': '대행사'
        }
        
        for role_name, description in roles.items():
            if not Role.query.filter_by(name=role_name).first():
                role = Role(name=role_name, description=description)
                db.session.add(role)
        
        # 기본 관리자 계정 생성
        if not User.query.filter_by(username='admin').first():
            admin_role = Role.query.filter_by(name='admin').first()
            admin = User(
                username='admin',
                email='admin@example.com',
                company_name='시스템 관리자',
                role=admin_role
            )
            admin.set_password('adminpassword')
            db.session.add(admin)
        
        db.session.commit()

# app 초기화 후 바로 실행합니다
create_tables_and_defaults()

# User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Custom decorators for role-based access control
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def distributor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (not current_user.is_distributor() and not current_user.is_admin()):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def agency_or_above_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# 인증 관련 라우트
@app.route('/login', methods=['GET', 'POST'])
def login():
    """사용자 로그인 처리"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            next_page = request.args.get('next')
            if not next_page or urlparse(next_page).netloc != '':
                next_page = url_for('dashboard')
            
            return redirect(next_page)
        
        flash('아이디 또는 비밀번호가 잘못되었습니다.', 'danger')
    
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    """사용자 로그아웃 처리"""
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@admin_required
def register():
    """새 사용자 등록 (관리자만 가능)"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        company_name = request.form.get('company_name')
        phone = request.form.get('phone')
        role_id = request.form.get('role_id')
        parent_id = request.form.get('parent_id')
        
        if User.query.filter_by(username=username).first():
            flash('이미 사용 중인 아이디입니다.', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('이미 사용 중인 이메일입니다.', 'danger')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            email=email,
            company_name=company_name,
            phone=phone,
            role_id=role_id
        )
        user.set_password(password)
        
        # 부모 ID 설정 (총판 경우)
        if parent_id and int(parent_id) > 0:
            user.parent_id = parent_id
        
        db.session.add(user)
        db.session.commit()
        
        flash('사용자가 성공적으로 등록되었습니다.', 'success')
        return redirect(url_for('users'))
    
    roles = Role.query.all()
    distributors = User.query.join(Role).filter(Role.name == 'distributor').all()
    return render_template('admin/register.html', roles=roles, distributors=distributors)

# 메인 라우트
@app.route('/')
def index():
    """메인 랜딩 페이지"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """사용자 대시보드"""
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    elif current_user.is_distributor():
        return redirect(url_for('distributor_dashboard'))
    else:  # 대행사
        return redirect(url_for('agency_dashboard'))

# 관리자 라우트
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """관리자 대시보드"""
    users_count = User.query.count()
    distributors_count = User.query.join(Role).filter(Role.name == 'distributor').count()
    agencies_count = User.query.join(Role).filter(Role.name == 'agency').count()
    
    pending_approvals = SlotApproval.query.filter_by(status='pending').count()
    shopping_slots = ShoppingSlot.query.count()
    place_slots = PlaceSlot.query.count()
    
    return render_template('admin/dashboard.html',
                          users_count=users_count,
                          distributors_count=distributors_count,
                          agencies_count=agencies_count,
                          pending_approvals=pending_approvals,
                          shopping_slots=shopping_slots,
                          place_slots=place_slots)

@app.route('/admin/users')
@admin_required
def users():
    """사용자 관리 페이지"""
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/approvals')
@admin_required
def admin_approvals():
    """관리자용 승인 요청 관리 페이지"""
    approvals = SlotApproval.query.filter_by(status='pending').all()
    return render_template('admin/approvals.html', approvals=approvals)

@app.route('/admin/approve/<int:approval_id>/<action>')
@admin_required
def admin_approve_request(approval_id, action):
    """승인 요청 처리"""
    approval = SlotApproval.query.get_or_404(approval_id)
    
    if action == 'approve':
        approval.status = 'approved'
        approval.approver_id = current_user.id
        approval.processed_at = datetime.utcnow()
        
        # 슬롯 상태 업데이트
        if approval.slot_type == 'shopping':
            approval.shopping_slot.status = 'approved'
        else:
            approval.place_slot.status = 'approved'
        
        flash('승인 요청이 수락되었습니다.', 'success')
    
    elif action == 'reject':
        approval.status = 'rejected'
        approval.approver_id = current_user.id
        approval.processed_at = datetime.utcnow()
        
        # 슬롯 상태 업데이트
        if approval.slot_type == 'shopping':
            approval.shopping_slot.status = 'rejected'
        else:
            approval.place_slot.status = 'rejected'
        
        flash('승인 요청이 거절되었습니다.', 'success')
    
    db.session.commit()
    return redirect(url_for('admin_approvals'))

# 총판 라우트
@app.route('/distributor/dashboard')
@distributor_required
def distributor_dashboard():
    """총판 대시보드"""
    agencies_count = current_user.agencies.count()
    
    # 이 총판에 속한 대행사들의 ID 리스트
    agency_ids = [agency.id for agency in current_user.agencies]
    
    # 이 총판에 속한 대행사들의 슬롯 통계
    shopping_slots = ShoppingSlot.query.filter(ShoppingSlot.user_id.in_(agency_ids)).count() if agency_ids else 0
    place_slots = PlaceSlot.query.filter(PlaceSlot.user_id.in_(agency_ids)).count() if agency_ids else 0
    
    # 승인 상태별 슬롯 통계
    shopping_pending = ShoppingSlot.query.filter(
        ShoppingSlot.user_id.in_(agency_ids), 
        ShoppingSlot.status == 'pending'
    ).count() if agency_ids else 0
    
    shopping_approved = ShoppingSlot.query.filter(
        ShoppingSlot.user_id.in_(agency_ids), 
        ShoppingSlot.status == 'approved'
    ).count() if agency_ids else 0
    
    shopping_rejected = ShoppingSlot.query.filter(
        ShoppingSlot.user_id.in_(agency_ids), 
        ShoppingSlot.status == 'rejected'
    ).count() if agency_ids else 0
    
    place_pending = PlaceSlot.query.filter(
        PlaceSlot.user_id.in_(agency_ids), 
        PlaceSlot.status == 'pending'
    ).count() if agency_ids else 0
    
    place_approved = PlaceSlot.query.filter(
        PlaceSlot.user_id.in_(agency_ids), 
        PlaceSlot.status == 'approved'
    ).count() if agency_ids else 0
    
    place_rejected = PlaceSlot.query.filter(
        PlaceSlot.user_id.in_(agency_ids), 
        PlaceSlot.status == 'rejected'
    ).count() if agency_ids else 0
    
    # 이 총판에게 온 승인 요청
    pending_approvals = SlotApproval.query.filter(
        SlotApproval.status == 'pending',
        SlotApproval.requester_id.in_(agency_ids)
    ).count() if agency_ids else 0
    
    return render_template('distributor/dashboard.html',
                          agencies_count=agencies_count,
                          shopping_slots=shopping_slots,
                          place_slots=place_slots,
                          pending_approvals=pending_approvals,
                          shopping_pending=shopping_pending,
                          shopping_approved=shopping_approved,
                          shopping_rejected=shopping_rejected,
                          place_pending=place_pending,
                          place_approved=place_approved,
                          place_rejected=place_rejected)

@app.route('/distributor/agencies')
@distributor_required
def distributor_agencies():
    """총판의 대행사 관리 페이지"""
    agencies = current_user.agencies.all()
    return render_template('distributor/agencies.html', agencies=agencies)

@app.route('/distributor/approvals')
@distributor_required
def distributor_approvals():
    """총판용 승인 요청 관리 페이지"""
    # 이 총판에 속한 대행사들의 ID 리스트
    agency_ids = [agency.id for agency in current_user.agencies]
    
    approvals = SlotApproval.query.filter(
        SlotApproval.status == 'pending',
        SlotApproval.requester_id.in_(agency_ids)
    ).all()
    
    return render_template('distributor/approvals.html', approvals=approvals)

@app.route('/distributor/approve/<int:approval_id>/<action>')
@distributor_required
def distributor_approve_request(approval_id, action):
    """총판의 승인 요청 처리"""
    approval = SlotApproval.query.get_or_404(approval_id)
    
    # 이 승인 요청이 자신의 대행사에서 온 것인지 확인
    if approval.requester.parent_id != current_user.id:
        abort(403)
    
    if action == 'approve':
        approval.status = 'approved'
        approval.approver_id = current_user.id
        approval.processed_at = datetime.utcnow()
        
        # 슬롯 상태 업데이트
        if approval.slot_type == 'shopping':
            approval.shopping_slot.status = 'approved'
        else:
            approval.place_slot.status = 'approved'
        
        flash('승인 요청이 수락되었습니다.', 'success')
    
    elif action == 'reject':
        approval.status = 'rejected'
        approval.approver_id = current_user.id
        approval.processed_at = datetime.utcnow()
        
        # 슬롯 상태 업데이트
        if approval.slot_type == 'shopping':
            approval.shopping_slot.status = 'rejected'
        else:
            approval.place_slot.status = 'rejected'
        
        flash('승인 요청이 거절되었습니다.', 'success')
    
    db.session.commit()
    return redirect(url_for('distributor_approvals'))

# 대행사 라우트
@app.route('/agency/dashboard')
@login_required
def agency_dashboard():
    """대행사 대시보드"""
    if not current_user.is_agency():
        abort(403)
    
    # 이 대행사의 슬롯 통계
    shopping_slots_count = current_user.shopping_slots.count()
    place_slots_count = current_user.place_slots.count()
    
    # 승인 상태별 슬롯 수
    pending_shopping_slots = current_user.shopping_slots.filter_by(status='pending').count()
    approved_shopping_slots = current_user.shopping_slots.filter_by(status='approved').count()
    rejected_shopping_slots = current_user.shopping_slots.filter_by(status='rejected').count()
    
    pending_place_slots = current_user.place_slots.filter_by(status='pending').count()
    approved_place_slots = current_user.place_slots.filter_by(status='approved').count()
    rejected_place_slots = current_user.place_slots.filter_by(status='rejected').count()
    
    return render_template('agency/dashboard.html',
                          shopping_slots_count=shopping_slots_count,
                          place_slots_count=place_slots_count,
                          pending_shopping_slots=pending_shopping_slots,
                          approved_shopping_slots=approved_shopping_slots,
                          rejected_shopping_slots=rejected_shopping_slots,
                          pending_place_slots=pending_place_slots,
                          approved_place_slots=approved_place_slots,
                          rejected_place_slots=rejected_place_slots)

@app.route('/agency/shopping-slots')
@login_required
def agency_shopping_slots():
    """대행사 쇼핑 슬롯 관리 페이지"""
    if not current_user.is_agency():
        abort(403)
    
    shopping_slots = current_user.shopping_slots.all()
    return render_template('agency/shopping_slots.html', shopping_slots=shopping_slots)

@app.route('/agency/place-slots')
@login_required
def agency_place_slots():
    """대행사 플레이스 슬롯 관리 페이지"""
    if not current_user.is_agency():
        abort(403)
    
    place_slots = current_user.place_slots.all()
    return render_template('agency/place_slots.html', place_slots=place_slots)

# 쇼핑 슬롯 관련 라우트
@app.route('/shopping-slots/create', methods=['GET', 'POST'])
@login_required
def create_shopping_slot():
    """쇼핑 슬롯 생성"""
    if not current_user.is_agency():
        abort(403)
    
    if request.method == 'POST':
        # 폼 데이터 처리
        slot_name = request.form.get('slot_name')
        store_type = request.form.get('store_type')
        product_id = request.form.get('product_id')
        shopping_campaign_id = request.form.get('shopping_campaign_id')
        product_name = request.form.get('product_name')
        keywords = request.form.get('keywords')
        store_name = request.form.get('store_name')
        price = request.form.get('price')
        sale_price = request.form.get('sale_price')
        
        # 날짜 처리
        start_date = request.form.get('start_date')
        if start_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        
        end_date = request.form.get('end_date')
        if end_date:
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        
        bid_type = request.form.get('bid_type')
        targeting = request.form.get('targeting')
        
        # 슬롯 생성
        shopping_slot = ShoppingSlot(
            user_id=current_user.id,
            slot_name=slot_name,
            store_type=store_type,
            product_id=product_id,
            shopping_campaign_id=shopping_campaign_id,
            product_name=product_name,
            keywords=keywords,
            store_name=store_name,
            price=price if price else None,
            sale_price=sale_price if sale_price else None,
            start_date=start_date,
            end_date=end_date,
            bid_type=bid_type,
            targeting=targeting,
            product_image_url="/static/img/placeholder-product.svg"
        )
        
        db.session.add(shopping_slot)
        db.session.flush()  # ID 생성을 위해 플러시
        
        # 승인 요청 생성
        approval = SlotApproval(
            requester_id=current_user.id,
            shopping_slot_id=shopping_slot.id,
            approval_type='create'
        )
        
        db.session.add(approval)
        db.session.commit()
        
        flash('쇼핑 슬롯이 생성되었고 승인 요청이 제출되었습니다.', 'success')
        return redirect(url_for('agency_shopping_slots'))
    
    return render_template('agency/create_shopping_slot.html')

@app.route('/shopping-slots/upload', methods=['GET', 'POST'])
@login_required
def upload_shopping_slots():
    """쇼핑 슬롯 일괄 업로드"""
    if not current_user.is_agency():
        abort(403)
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('파일이 없습니다.', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('선택된 파일이 없습니다.', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            # 안전한 파일명 생성 및 저장
            original_filename = secure_filename(file.filename)
            filename = f"{uuid.uuid4().hex}_{original_filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            try:
                # 엑셀 파일 처리
                df = pd.read_excel(filepath)
                
                # 데이터프레임의 열 이름 확인
                if len(df.columns) == 0:
                    flash('파일에 데이터가 없습니다.', 'danger')
                    return redirect(request.url)
                
                # 데이터 변환 및 저장
                success_count = 0
                error_count = 0
                
                for idx, row in df.iterrows():
                    try:
                        # 필수 필드 검증
                        slot_name = str(row.get('slot_name', f'슬롯 {idx+1}'))
                        
                        # 날짜 처리
                        start_date = None
                        if 'start_date' in row and not pd.isna(row['start_date']):
                            if isinstance(row['start_date'], str):
                                start_date = datetime.strptime(row['start_date'], '%Y-%m-%d').date()
                            else:
                                start_date = row['start_date'].date()
                        
                        end_date = None
                        if 'end_date' in row and not pd.isna(row['end_date']):
                            if isinstance(row['end_date'], str):
                                end_date = datetime.strptime(row['end_date'], '%Y-%m-%d').date()
                            else:
                                end_date = row['end_date'].date()
                        
                        # 슬롯 생성
                        shopping_slot = ShoppingSlot(
                            user_id=current_user.id,
                            slot_name=slot_name,
                            store_type=str(row.get('store_type', '')),
                            product_id=str(row.get('product_id', '')),
                            shopping_campaign_id=str(row.get('shopping_campaign_id', '')),
                            product_name=str(row.get('product_name', '')),
                            keywords=str(row.get('keywords', '')),
                            store_name=str(row.get('store_name', '')),
                            price=int(row.get('price', 0)) if not pd.isna(row.get('price', 0)) else None,
                            sale_price=int(row.get('sale_price', 0)) if not pd.isna(row.get('sale_price', 0)) else None,
                            start_date=start_date,
                            end_date=end_date,
                            bid_type=str(row.get('bid_type', '')),
                            targeting=str(row.get('targeting', '')),
                            product_image_url="/static/img/placeholder-product.svg",
                            filename=filename,
                            original_filename=original_filename
                        )
                        
                        db.session.add(shopping_slot)
                        db.session.flush()  # ID 생성을 위해 플러시
                        
                        # 승인 요청 생성
                        approval = SlotApproval(
                            requester_id=current_user.id,
                            shopping_slot_id=shopping_slot.id,
                            approval_type='create'
                        )
                        
                        db.session.add(approval)
                        success_count += 1
                    except Exception as e:
                        logger.error(f"Error processing row {idx}: {e}")
                        error_count += 1
                
                db.session.commit()
                
                flash(f'{success_count}개의 쇼핑 슬롯이 생성되었고 승인 요청이 제출되었습니다. ({error_count}개 실패)', 'success')
                return redirect(url_for('agency_shopping_slots'))
                
            except Exception as e:
                logger.error(f"Error processing Excel file: {e}")
                flash(f'엑셀 파일 처리 중 오류가 발생했습니다: {str(e)}', 'danger')
        else:
            flash('허용되지 않는 파일 형식입니다. .xlsx 또는 .xls 파일을 업로드하세요.', 'danger')
    
    return render_template('agency/upload_shopping_slots.html')

# 플레이스 슬롯 관련 라우트
@app.route('/place-slots/create', methods=['GET', 'POST'])
@login_required
def create_place_slot():
    """플레이스 슬롯 생성"""
    if not current_user.is_agency():
        abort(403)
    
    if request.method == 'POST':
        # 폼 데이터 처리
        slot_name = request.form.get('slot_name')
        place_id = request.form.get('place_id')
        business_category = request.form.get('business_category')
        business_type = request.form.get('business_type')
        place_name = request.form.get('place_name')
        address = request.form.get('address')
        operation_status = request.form.get('operation_status')
        status_reason = request.form.get('status_reason')
        status_detail = request.form.get('status_detail')
        
        # 날짜 처리
        start_date = request.form.get('start_date')
        if start_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        
        end_date = request.form.get('end_date')
        if end_date:
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        
        deadline_date = request.form.get('deadline_date')
        if deadline_date:
            deadline_date = datetime.strptime(deadline_date, '%Y-%m-%d').date()
        
        # 슬롯 생성
        place_slot = PlaceSlot(
            user_id=current_user.id,
            slot_name=slot_name,
            place_id=place_id,
            business_category=business_category,
            business_type=business_type,
            place_name=place_name,
            address=address,
            operation_status=operation_status,
            status_reason=status_reason,
            status_detail=status_detail,
            start_date=start_date,
            end_date=end_date,
            deadline_date=deadline_date
        )
        
        db.session.add(place_slot)
        db.session.flush()  # ID 생성을 위해 플러시
        
        # 승인 요청 생성
        approval = SlotApproval(
            requester_id=current_user.id,
            place_slot_id=place_slot.id,
            approval_type='create'
        )
        
        db.session.add(approval)
        db.session.commit()
        
        flash('플레이스 슬롯이 생성되었고 승인 요청이 제출되었습니다.', 'success')
        return redirect(url_for('agency_place_slots'))
    
    return render_template('agency/create_place_slot.html')

@app.route('/place-slots/upload', methods=['GET', 'POST'])
@login_required
def upload_place_slots():
    """플레이스 슬롯 일괄 업로드"""
    if not current_user.is_agency():
        abort(403)
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('파일이 없습니다.', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('선택된 파일이 없습니다.', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            # 안전한 파일명 생성 및 저장
            original_filename = secure_filename(file.filename)
            filename = f"{uuid.uuid4().hex}_{original_filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            try:
                # 엑셀 파일 처리
                df = pd.read_excel(filepath)
                
                # 데이터프레임의 열 이름 확인
                if len(df.columns) == 0:
                    flash('파일에 데이터가 없습니다.', 'danger')
                    return redirect(request.url)
                
                # 데이터 변환 및 저장
                success_count = 0
                error_count = 0
                
                for idx, row in df.iterrows():
                    try:
                        # 필수 필드 검증
                        slot_name = str(row.get('slot_name', f'플레이스 슬롯 {idx+1}'))
                        
                        # 날짜 처리
                        start_date = None
                        if 'start_date' in row and not pd.isna(row['start_date']):
                            if isinstance(row['start_date'], str):
                                start_date = datetime.strptime(row['start_date'], '%Y-%m-%d').date()
                            else:
                                start_date = row['start_date'].date()
                        
                        end_date = None
                        if 'end_date' in row and not pd.isna(row['end_date']):
                            if isinstance(row['end_date'], str):
                                end_date = datetime.strptime(row['end_date'], '%Y-%m-%d').date()
                            else:
                                end_date = row['end_date'].date()
                        
                        deadline_date = None
                        if 'deadline_date' in row and not pd.isna(row['deadline_date']):
                            if isinstance(row['deadline_date'], str):
                                deadline_date = datetime.strptime(row['deadline_date'], '%Y-%m-%d').date()
                            else:
                                deadline_date = row['deadline_date'].date()
                        
                        # 슬롯 생성
                        place_slot = PlaceSlot(
                            user_id=current_user.id,
                            slot_name=slot_name,
                            place_id=str(row.get('place_id', '')),
                            business_category=str(row.get('business_category', '')),
                            business_type=str(row.get('business_type', '')),
                            place_name=str(row.get('place_name', '')),
                            address=str(row.get('address', '')),
                            operation_status=str(row.get('operation_status', '')),
                            status_reason=str(row.get('status_reason', '')),
                            status_detail=str(row.get('status_detail', '')),
                            start_date=start_date,
                            end_date=end_date,
                            deadline_date=deadline_date,
                            filename=filename,
                            original_filename=original_filename
                        )
                        
                        db.session.add(place_slot)
                        db.session.flush()  # ID 생성을 위해 플러시
                        
                        # 승인 요청 생성
                        approval = SlotApproval(
                            requester_id=current_user.id,
                            place_slot_id=place_slot.id,
                            approval_type='create'
                        )
                        
                        db.session.add(approval)
                        success_count += 1
                    except Exception as e:
                        logger.error(f"Error processing row {idx}: {e}")
                        error_count += 1
                
                db.session.commit()
                
                flash(f'{success_count}개의 플레이스 슬롯이 생성되었고 승인 요청이 제출되었습니다. ({error_count}개 실패)', 'success')
                return redirect(url_for('agency_place_slots'))
                
            except Exception as e:
                logger.error(f"Error processing Excel file: {e}")
                flash(f'엑셀 파일 처리 중 오류가 발생했습니다: {str(e)}', 'danger')
        else:
            flash('허용되지 않는 파일 형식입니다. .xlsx 또는 .xls 파일을 업로드하세요.', 'danger')
    
    return render_template('agency/upload_place_slots.html')

# 오류 처리 라우트
@app.errorhandler(404)
def page_not_found(e):
    """404 오류 처리"""
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    """403 오류 처리"""
    return render_template('errors/403.html'), 403

@app.errorhandler(500)
def internal_server_error(e):
    """500 오류 처리"""
    logger.error(f"Server error: {e}")
    return render_template('errors/500.html'), 500

# 홈페이지 라우트는 위에 이미 정의되어 있음

@app.route('/shopping', methods=['GET', 'POST'])
def shopping():
    """Handle Naver Shopping form submission."""
    if request.method == 'POST':
        # 파일 업로드 처리
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                # 안전한 파일명 생성 및 저장
                original_filename = secure_filename(file.filename)
                filename = f"{uuid.uuid4().hex}_{original_filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                try:
                    # 엑셀 파일 처리 (가정: 첫 번째 열이 필수 필드)
                    df = pd.read_excel(filepath)
                    
                    # 데이터프레임의 열 이름 확인
                    if len(df.columns) == 0:
                        flash('파일에 데이터가 없습니다. (The file does not contain any data.)', 'danger')
                        return render_template('shopping.html')
                    
                    # 필수 필드 매핑 (첫 번째 열을 제품명으로 가정)
                    required_field = df.columns[0]
                    
                    # 데이터 변환 및 저장
                    success_count = 0
                    error_count = 0
                    
                    for idx, row in df.iterrows():
                        try:
                            # 엑셀에서 읽은 데이터를 딕셔너리로 변환
                            product_name = str(row[required_field])
                            if pd.isna(product_name) or not product_name.strip():
                                continue  # 필수 필드가 비어있으면 건너뛰기
                            
                            # 기본 필드 설정
                            data = {
                                'product_name': product_name,
                                'price': int(row.get('price', 0)) if not pd.isna(row.get('price', 0)) else 0,
                                'category': str(row.get('category', '기타')) if not pd.isna(row.get('category', '기타')) else '기타',
                                'brand': str(row.get('brand', '')) if not pd.isna(row.get('brand', '')) else '',
                                'description': str(row.get('description', '')) if not pd.isna(row.get('description', '')) else '',
                                'features': str(row.get('features', '')) if not pd.isna(row.get('features', '')) else '',
                                'specifications': str(row.get('specifications', '')) if not pd.isna(row.get('specifications', '')) else '',
                                'shipping_info': str(row.get('shipping_info', '')) if not pd.isna(row.get('shipping_info', '')) else ''
                            }
                            
                            # 데이터베이스에 저장
                            shopping_data = ShoppingData.from_dict(data, filename=filename, original_filename=original_filename)
                            db.session.add(shopping_data)
                            success_count += 1
                        except Exception as e:
                            logger.error(f"Error processing row {idx}: {e}")
                            error_count += 1
                    
                    db.session.commit()
                    flash(f'{success_count}개의 항목이 성공적으로 저장되었습니다. ({error_count}개 실패) | {success_count} items saved successfully ({error_count} failed).', 'success')
                    return redirect(url_for('success'))
                    
                except Exception as e:
                    logger.error(f"Error processing Excel file: {e}")
                    flash(f'엑셀 파일 처리 중 오류가 발생했습니다: {str(e)} | Error processing Excel file: {str(e)}', 'danger')
                    return render_template('shopping.html')
            else:
                flash('허용되지 않는 파일 형식입니다. .xlsx 또는 .xls 파일을 업로드하세요. | Invalid file format. Please upload .xlsx or .xls file.', 'danger')
                return render_template('shopping.html')
        
        # 일반 폼 제출 처리
        else:
            # Process the form data
            product_name = request.form.get('product_name')
            price = request.form.get('price')
            category = request.form.get('category')
            brand = request.form.get('brand')
            description = request.form.get('description')
            features = request.form.get('features')
            specifications = request.form.get('specifications')
            shipping_info = request.form.get('shipping_info')
            
            # Validate required fields
            if not product_name or not price or not category:
                flash('필수 필드를 모두 입력해주세요. (Please fill all required fields.)', 'danger')
                return render_template('shopping.html', form_data=request.form)
            
            # Create a new ShoppingData object
            shopping_data = ShoppingData(
                product_name=product_name,
                price=int(price),
                category=category,
                brand=brand,
                description=description,
                features=features,
                specifications=specifications,
                shipping_info=shipping_info
            )
            
            # Save to database
            db.session.add(shopping_data)
            db.session.commit()
            
            logger.info(f"Shopping form submitted and saved: {product_name}")
            
            # Store submission in session for confirmation page
            session['submission_type'] = 'shopping'
            session['submission_data'] = {
                'product_name': product_name,
                'price': price,
                'category': category,
                'brand': brand,
                'description': description,
                'features': features,
                'specifications': specifications,
                'shipping_info': shipping_info
            }
            
            flash('네이버 쇼핑 정보가 성공적으로 제출되었습니다. (Naver Shopping information submitted successfully.)', 'success')
            return redirect(url_for('success'))
    
    # 쇼핑 데이터 목록 가져오기
    shopping_data_list = ShoppingData.query.order_by(ShoppingData.created_at.desc()).limit(10).all()
    return render_template('shopping.html', shopping_data_list=shopping_data_list)

@app.route('/place', methods=['GET', 'POST'])
def place():
    """Handle Naver Place form submission."""
    if request.method == 'POST':
        # 파일 업로드 처리
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                # 안전한 파일명 생성 및 저장
                original_filename = secure_filename(file.filename)
                filename = f"{uuid.uuid4().hex}_{original_filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                try:
                    # 엑셀 파일 처리 (가정: 첫 번째 열이 필수 필드)
                    df = pd.read_excel(filepath)
                    
                    # 데이터프레임의 열 이름 확인
                    if len(df.columns) == 0:
                        flash('파일에 데이터가 없습니다. (The file does not contain any data.)', 'danger')
                        return render_template('place.html')
                    
                    # 필수 필드 매핑 (첫 번째 열을 장소명으로 가정)
                    required_field = df.columns[0]
                    
                    # 데이터 변환 및 저장
                    success_count = 0
                    error_count = 0
                    
                    for idx, row in df.iterrows():
                        try:
                            # 엑셀에서 읽은 데이터를 딕셔너리로 변환
                            place_name = str(row[required_field])
                            if pd.isna(place_name) or not place_name.strip():
                                continue  # 필수 필드가 비어있으면 건너뛰기
                            
                            # 기본 필드 설정
                            data = {
                                'place_name': place_name,
                                'category': str(row.get('category', '기타')) if not pd.isna(row.get('category', '기타')) else '기타',
                                'address': str(row.get('address', '')) if not pd.isna(row.get('address', '')) else '',
                                'phone': str(row.get('phone', '')) if not pd.isna(row.get('phone', '')) else '',
                                'business_hours': str(row.get('business_hours', '')) if not pd.isna(row.get('business_hours', '')) else '',
                                'description': str(row.get('description', '')) if not pd.isna(row.get('description', '')) else '',
                                'website': str(row.get('website', '')) if not pd.isna(row.get('website', '')) else '',
                                'parking_info': str(row.get('parking_info', '')) if not pd.isna(row.get('parking_info', '')) else ''
                            }
                            
                            # 주소가 필수 필드인데 비어있는지 확인
                            if not data['address'].strip():
                                data['address'] = '주소 미지정'  # 기본값 설정
                            
                            # 데이터베이스에 저장
                            place_data = PlaceData.from_dict(data, filename=filename, original_filename=original_filename)
                            db.session.add(place_data)
                            success_count += 1
                        except Exception as e:
                            logger.error(f"Error processing row {idx}: {e}")
                            error_count += 1
                    
                    db.session.commit()
                    flash(f'{success_count}개의 항목이 성공적으로 저장되었습니다. ({error_count}개 실패) | {success_count} items saved successfully ({error_count} failed).', 'success')
                    return redirect(url_for('success'))
                    
                except Exception as e:
                    logger.error(f"Error processing Excel file: {e}")
                    flash(f'엑셀 파일 처리 중 오류가 발생했습니다: {str(e)} | Error processing Excel file: {str(e)}', 'danger')
                    return render_template('place.html')
            else:
                flash('허용되지 않는 파일 형식입니다. .xlsx 또는 .xls 파일을 업로드하세요. | Invalid file format. Please upload .xlsx or .xls file.', 'danger')
                return render_template('place.html')
        
        # 일반 폼 제출 처리
        else:
            # Process the form data
            place_name = request.form.get('place_name')
            category = request.form.get('category')
            address = request.form.get('address')
            phone = request.form.get('phone')
            business_hours = request.form.get('business_hours')
            description = request.form.get('description')
            website = request.form.get('website')
            parking_info = request.form.get('parking_info')
            
            # Validate required fields
            if not place_name or not category or not address:
                flash('필수 필드를 모두 입력해주세요. (Please fill all required fields.)', 'danger')
                return render_template('place.html', form_data=request.form)
            
            # Create a new PlaceData object
            place_data = PlaceData(
                place_name=place_name,
                category=category,
                address=address,
                phone=phone,
                business_hours=business_hours,
                description=description,
                website=website,
                parking_info=parking_info
            )
            
            # Save to database
            db.session.add(place_data)
            db.session.commit()
            
            logger.info(f"Place form submitted and saved: {place_name}")
            
            # Store submission in session for confirmation page
            session['submission_type'] = 'place'
            session['submission_data'] = {
                'place_name': place_name,
                'category': category,
                'address': address,
                'phone': phone,
                'business_hours': business_hours,
                'description': description,
                'website': website,
                'parking_info': parking_info
            }
            
            flash('네이버 플레이스 정보가 성공적으로 제출되었습니다. (Naver Place information submitted successfully.)', 'success')
            return redirect(url_for('success'))
    
    # 플레이스 데이터 목록 가져오기
    place_data_list = PlaceData.query.order_by(PlaceData.created_at.desc()).limit(10).all()
    return render_template('place.html', place_data_list=place_data_list)

@app.route('/success')
def success():
    """Render success page after form submission."""
    if 'submission_type' not in session:
        return redirect(url_for('index'))
    
    submission_type = session.get('submission_type')
    submission_data = session.get('submission_data', {})
    
    # Clear session data after displaying
    session.pop('submission_type', None)
    session.pop('submission_data', None)
    
    return render_template('success.html', 
                          submission_type=submission_type, 
                          submission_data=submission_data)

# 오류 핸들러는 위에 이미 정의되어 있음
