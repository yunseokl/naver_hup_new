import os
import logging
import uuid
import pandas as pd
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort, send_file, send_from_directory
from flask import g, current_app
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, joinedload, selectinload
from sqlalchemy import or_
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from functools import wraps
from flask_wtf import FlaskForm, CSRFProtect
import locale

# 숫자 포맷팅을 위한 설정
try:
    locale.setlocale(locale.LC_ALL, 'ko_KR.UTF-8')
except:
    # 한국어 로케일을 지원하지 않는 경우 기본 로케일 사용
    locale.setlocale(locale.LC_ALL, '')

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Utility functions
def safe_int(value, default=0, allow_none=False):
    """안전하게 정수로 변환
    
    Args:
        value: 변환할 값
        default: allow_none=True일 때 빈 값에 대한 기본값
        allow_none: True이면 빈 값을 default로 변환, False이면 빈 값도 에러
    
    Returns:
        int: 변환된 정수 값
        
    Raises:
        ValueError: 변환 실패 시 또는 빈 값인데 allow_none=False인 경우
    """
    # 빈 값 처리
    if value is None or value == '':
        if allow_none:
            return default
        else:
            raise ValueError("값이 비어있습니다.")
    
    # 정수 변환
    try:
        return int(value)
    except (ValueError, TypeError):
        raise ValueError(f"'{value}'은(는) 유효한 숫자가 아닙니다.")

def validate_password_complexity(password):
    """비밀번호 복잡도 검증
    
    최소 요구사항:
    - 8자 이상
    - 대문자 1개 이상
    - 소문자 1개 이상
    - 숫자 1개 이상
    
    Returns:
        (bool, str): (유효 여부, 오류 메시지)
    """
    if len(password) < 8:
        return False, '비밀번호는 8자 이상이어야 합니다.'
    
    if not any(c.isupper() for c in password):
        return False, '비밀번호에는 대문자가 최소 1개 포함되어야 합니다.'
    
    if not any(c.islower() for c in password):
        return False, '비밀번호에는 소문자가 최소 1개 포함되어야 합니다.'
    
    if not any(c.isdigit() for c in password):
        return False, '비밀번호에는 숫자가 최소 1개 포함되어야 합니다.'
    
    return True, ''

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

# Initialize CSRF Protection
csrf = CSRFProtect()
csrf.init_app(app)

# CSRF 보호 제외 경로
csrf.exempt("admin_settlement_action")
csrf.exempt("save_slot_api")
csrf.exempt("save_slots_bulk_api")
csrf.exempt("toggle_slot_api")
csrf.exempt("toggle_slot")
csrf.exempt("export_slots")

# Import models after initializing db to avoid circular imports
from models import User, Role, ShoppingSlot, PlaceSlot, SlotApproval, SlotQuota, SlotQuotaRequest, Settlement, SettlementItem, SlotRefundRequest

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

# 템플릿 필터 등록
@app.template_filter('format_number')
def format_number_filter(value):
    """숫자를 포맷팅하는 필터 (예: 10000 -> 10,000)"""
    try:
        return f"{int(value):,}" if value is not None else "0"
    except (ValueError, TypeError):
        return "0"

@app.template_filter('safe_format')
def safe_format_filter(value):
    """안전하게 콤마를 포함한 숫자 포맷팅 (None 값 처리 포함)"""
    if value is None:
        return "0"
    try:
        return f"{int(value):,}"
    except (ValueError, TypeError):
        return "0"

@app.template_filter('nl2br')
def nl2br_filter(text):
    """텍스트의 줄바꿈을 HTML <br> 태그로 변환"""
    if text:
        return text.replace('\n', '<br>')
    return ""

# now 함수를 템플릿에서 사용할 수 있도록 등록
@app.context_processor
def utility_processor():
    def now():
        return datetime.now()
    return dict(now=now)

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
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not current_user.is_admin():
            flash('관리자 권한이 필요합니다.', 'danger')
            return redirect(url_for('dashboard'))
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

def agency_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_agency():
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
    
    form = FlaskForm()
    
    if request.method == 'POST' and form.validate_on_submit():
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
    
    return render_template('auth/login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """사용자 로그아웃 처리"""
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """새 사용자 회원가입 - 관리자 승인 필요"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = FlaskForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        company_name = request.form.get('company_name')
        phone = request.form.get('phone')
        role_id = request.form.get('role_id')
        parent_id = request.form.get('parent_id')
        agree_terms = request.form.get('agree_terms')
        
        # 기본 검증
        if not username or not email or not password or not role_id or not company_name or not phone:
            flash('모든 필수 항목을 입력해주세요.', 'warning')
            return redirect(url_for('register'))
        
        if not agree_terms:
            flash('이용약관에 동의해주세요.', 'warning')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('비밀번호가 일치하지 않습니다.', 'danger')
            return redirect(url_for('register'))
        
        # 비밀번호 복잡도 검증
        is_valid, error_msg = validate_password_complexity(password)
        if not is_valid:
            flash(error_msg, 'danger')
            return redirect(url_for('register'))
        
        # 이메일/사용자명 중복 확인
        if User.query.filter_by(username=username).first():
            flash('이미 사용 중인 아이디입니다.', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('이미 사용 중인 이메일입니다.', 'danger')
            return redirect(url_for('register'))
        
        # 역할 확인
        role = Role.query.get(role_id)
        if not role:
            flash('잘못된 역할입니다.', 'danger')
            return redirect(url_for('register'))
        
        # 관리자는 회원가입을 통해 등록할 수 없음
        if role.name == 'admin':
            flash('관리자 계정은 이 방법으로 등록할 수 없습니다.', 'danger')
            return redirect(url_for('register'))
        
        # 대행사인 경우 총판 필수 체크
        if role.name == 'agency' and not parent_id:
            flash('대행사는 소속 총판을 선택해야 합니다.', 'warning')
            return redirect(url_for('register'))
        
        # 총판인 경우 parent_id를 None으로 설정
        if role.name == 'distributor':
            parent_id = None
        
        # 새 사용자 생성 (초기 상태: 비활성)
        user = User(
            username=username, 
            email=email, 
            company_name=company_name, 
            phone=phone, 
            role_id=role_id, 
            parent_id=parent_id if parent_id else None,
            is_active=False  # 승인 전까지 비활성화
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # 관리자에게 이메일 알림 보내기 (구현 필요)
        # send_admin_notification_email(user)
        
        flash('회원가입이 신청되었습니다. 관리자 승인 후 로그인이 가능합니다.', 'success')
        return redirect(url_for('login'))
    
    # 역할 및 총판 리스트 가져오기 (관리자 역할 제외)
    roles = Role.query.filter(Role.name != 'admin').all()
    distributors = User.query.join(Role).filter(
        Role.name == 'distributor',
        User.is_active == True
    ).all()
    
    return render_template('auth/register.html', form=form, roles=roles, distributors=distributors)

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
    
    # 정산 통계
    pending_settlements = Settlement.query.filter_by(status='pending').count()
    
    # 환불 요청 통계
    pending_refunds = SlotRefundRequest.query.filter_by(status='pending').count()
    
    # 최신 사용자 5명 (role 정보 eager load)
    recent_users = User.query.options(joinedload(User.role)).order_by(User.created_at.desc()).limit(5).all()
    
    # 최근 승인 요청 5개 (requester 정보 eager load)
    recent_approvals = SlotApproval.query.options(
        joinedload(SlotApproval.requester).joinedload(User.role)
    ).order_by(SlotApproval.requested_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html',
                          users_count=users_count,
                          distributors_count=distributors_count,
                          agencies_count=agencies_count,
                          pending_approvals=pending_approvals,
                          shopping_slots=shopping_slots,
                          place_slots=place_slots,
                          pending_settlements=pending_settlements,
                          pending_refunds=pending_refunds,
                          recent_users=recent_users,
                          recent_approvals=recent_approvals)

@app.route('/admin/users')
@admin_required
def users():
    """사용자 관리 페이지"""
    # 모든 활성화된 사용자 조회 (role과 distributor 정보 eager load)
    users = User.query.options(
        joinedload(User.role),
        joinedload(User.distributor)
    ).filter_by(is_active=True).all()
    
    # 승인 대기 중인 사용자 조회 (role과 distributor 정보 eager load)
    pending_users = User.query.options(
        joinedload(User.role),
        joinedload(User.distributor)
    ).filter_by(is_active=False).all()
    
    return render_template('admin/users.html', users=users, pending_users=pending_users)

@app.route('/admin/register', methods=['GET', 'POST'])
@admin_required
def admin_register():
    """관리자용 사용자 등록 페이지"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        company_name = request.form.get('company_name')
        phone = request.form.get('phone')
        role_id = request.form.get('role_id')
        parent_id = request.form.get('parent_id')
        is_active = request.form.get('is_active') == 'on'
        
        # 유효성 검사
        if not all([username, email, password, company_name, role_id]):
            flash('필수 정보를 모두 입력해주세요.', 'danger')
            return redirect(url_for('admin_register'))
        
        if password != password_confirm:
            flash('비밀번호가 일치하지 않습니다.', 'danger')
            return redirect(url_for('admin_register'))
        
        # 비밀번호 복잡도 검증
        is_valid, error_msg = validate_password_complexity(password)
        if not is_valid:
            flash(error_msg, 'danger')
            return redirect(url_for('admin_register'))
        
        # 이메일/사용자명 중복 확인
        if User.query.filter_by(username=username).first():
            flash('이미 사용 중인 아이디입니다.', 'danger')
            return redirect(url_for('admin_register'))
        
        if User.query.filter_by(email=email).first():
            flash('이미 사용 중인 이메일입니다.', 'danger')
            return redirect(url_for('admin_register'))
        
        # 역할 확인
        role = Role.query.get(role_id)
        if not role:
            flash('잘못된 역할입니다.', 'danger')
            return redirect(url_for('admin_register'))
        
        # 대행사인 경우 총판 필수 체크
        if role.name == 'agency' and not parent_id:
            flash('대행사는 소속 총판을 선택해야 합니다.', 'warning')
            return redirect(url_for('admin_register'))
        
        # 총판인 경우 parent_id를 None으로 설정
        if role.name == 'distributor':
            parent_id = None
        
        # 새 사용자 생성
        user = User(
            username=username, 
            email=email, 
            company_name=company_name, 
            phone=phone, 
            role_id=role_id, 
            parent_id=parent_id if parent_id else None,
            is_active=is_active  # 관리자는 즉시 활성화 가능
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash(f'{username} 사용자가 성공적으로 등록되었습니다.', 'success')
        return redirect(url_for('users'))
    
    # 역할 및 총판 리스트 가져오기 (관리자 역할 제외)
    roles = Role.query.filter(Role.name != 'admin').all()
    distributors = User.query.join(Role).filter(
        Role.name == 'distributor',
        User.is_active == True
    ).all()
    
    form = FlaskForm()
    return render_template('admin/register.html', form=form, roles=roles, distributors=distributors)

@app.route('/admin/approve-user/<int:user_id>/<action>')
@admin_required
def approve_user(user_id, action):
    """사용자 승인 요청 처리"""
    user = User.query.get_or_404(user_id)
    
    if action == 'approve':
        user.is_active = True
        db.session.commit()
        flash(f'{user.username} 사용자가 승인되었습니다.', 'success')
    elif action == 'reject':
        db.session.delete(user)
        db.session.commit()
        flash(f'{user.username} 사용자의 가입 요청이 거부되었습니다.', 'danger')
    
    return redirect(url_for('users'))

@app.route('/admin/approvals')
@admin_required
def admin_approvals():
    """관리자용 승인 요청 관리 페이지"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    pagination = SlotApproval.query.options(
        joinedload(SlotApproval.requester).joinedload(User.role),
        joinedload(SlotApproval.shopping_slot),
        joinedload(SlotApproval.place_slot)
    ).filter_by(status='pending').order_by(
        SlotApproval.requested_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    approvals = pagination.items
    
    return render_template('admin/approvals.html', 
                          approvals=approvals, 
                          pagination=pagination)

@app.route('/admin/shopping_slots')
@admin_required
def admin_shopping_slots():
    """관리자 쇼핑 슬롯 관리"""
    # 필터 파라미터
    owner_type = request.args.get('owner_type', '')
    status = request.args.get('status', '')
    slot_type = request.args.get('slot_type', '')
    search = request.args.get('search', '')
    
    # 기본 쿼리 (user 정보 eager load)
    query = ShoppingSlot.query.options(
        joinedload(ShoppingSlot.user).joinedload(User.role)
    ).join(User)
    
    # 필터 적용
    if owner_type:
        if owner_type == 'distributor':
            # 총판 소유 슬롯
            distributor_ids = [u.id for u in User.query.join(Role).filter(Role.name == 'distributor')]
            query = query.filter(ShoppingSlot.user_id.in_(distributor_ids))
        elif owner_type == 'agency':
            # 대행사 소유 슬롯
            agency_ids = [u.id for u in User.query.join(Role).filter(Role.name == 'agency')]
            query = query.filter(ShoppingSlot.user_id.in_(agency_ids))
    
    if status:
        query = query.filter(ShoppingSlot.status == status)
    
    if slot_type:
        query = query.filter(ShoppingSlot.slot_type == slot_type)
    
    if search:
        query = query.filter(
            or_(
                ShoppingSlot.slot_name.ilike(f'%{search}%'),
                ShoppingSlot.product_name.ilike(f'%{search}%'),
                User.company_name.ilike(f'%{search}%')
            )
        )
    
    # 페이지네이션
    page = request.args.get('page', 1, type=int)
    per_page = 20
    pagination = query.order_by(ShoppingSlot.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    slots = pagination.items
    
    # 총판 및 대행사 목록 (슬롯 추가 모달용)
    distributors = User.query.join(Role).filter(Role.name == 'distributor').all()
    agencies = User.query.join(Role).filter(Role.name == 'agency').all()
    
    return render_template('admin/shopping_slots.html',
                          slots=slots,
                          pagination=pagination,
                          distributors=distributors,
                          agencies=agencies,
                          owner_type=owner_type,
                          status=status,
                          slot_type=slot_type,
                          search=search)

@app.route('/admin/place_slots')
@admin_required
def admin_place_slots():
    """관리자 플레이스 슬롯 관리"""
    # 필터 파라미터
    owner_type = request.args.get('owner_type', '')
    status = request.args.get('status', '')
    slot_type = request.args.get('slot_type', '')
    search = request.args.get('search', '')
    
    # 기본 쿼리 (user 정보 eager load)
    query = PlaceSlot.query.options(
        joinedload(PlaceSlot.user).joinedload(User.role)
    ).join(User)
    
    # 필터 적용
    if owner_type:
        if owner_type == 'distributor':
            # 총판 소유 슬롯
            distributor_ids = [u.id for u in User.query.join(Role).filter(Role.name == 'distributor')]
            query = query.filter(PlaceSlot.user_id.in_(distributor_ids))
        elif owner_type == 'agency':
            # 대행사 소유 슬롯
            agency_ids = [u.id for u in User.query.join(Role).filter(Role.name == 'agency')]
            query = query.filter(PlaceSlot.user_id.in_(agency_ids))
    
    if status:
        query = query.filter(PlaceSlot.status == status)
    
    if slot_type:
        query = query.filter(PlaceSlot.slot_type == slot_type)
    
    if search:
        query = query.filter(
            or_(
                PlaceSlot.slot_name.ilike(f'%{search}%'),
                PlaceSlot.place_name.ilike(f'%{search}%'),
                User.company_name.ilike(f'%{search}%')
            )
        )
    
    # 페이지네이션
    page = request.args.get('page', 1, type=int)
    per_page = 20
    pagination = query.order_by(PlaceSlot.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    slots = pagination.items
    
    # 총판 및 대행사 목록 (슬롯 추가 모달용)
    distributors = User.query.join(Role).filter(Role.name == 'distributor').all()
    agencies = User.query.join(Role).filter(Role.name == 'agency').all()
    
    return render_template('admin/place_slots.html',
                          slots=slots,
                          pagination=pagination,
                          distributors=distributors,
                          agencies=agencies,
                          owner_type=owner_type,
                          status=status,
                          slot_type=slot_type,
                          search=search)

@app.route('/admin/shopping_slots/create', methods=['POST'])
@admin_required
def admin_create_shopping_slot():
    """관리자가 쇼핑 슬롯 생성"""
    try:
        # 폼 데이터 가져오기
        user_id = request.form.get('user_id')
        slot_name = request.form.get('slot_name')
        slot_type = request.form.get('slot_type', 'standard')
        status = request.form.get('status', 'empty')
        
        try:
            slot_price = safe_int(request.form.get('slot_price'), 0)
        except ValueError as e:
            flash(f'슬롯 단가 입력 오류: {str(e)}', 'danger')
            return redirect(url_for('admin_shopping_slots'))
        
        notes = request.form.get('notes', '')
        
        # 날짜 처리
        start_date = None
        start_date_str = request.form.get('start_date')
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            
        end_date = None
        end_date_str = request.form.get('end_date')
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        
        # 쇼핑 슬롯 생성
        slot = ShoppingSlot(
            user_id=user_id,
            slot_name=slot_name,
            start_date=start_date,
            end_date=end_date,
            status=status,
            slot_price=slot_price,
            slot_type=slot_type,
            notes=notes,
            admin_price=slot_price  # 관리자가 생성한 슬롯은 기본적으로 단가와 정산가가 동일
        )
        
        db.session.add(slot)
        db.session.commit()
        
        flash(f'쇼핑 슬롯 "{slot_name}"이(가) 성공적으로 생성되었습니다.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'슬롯 생성 중 오류가 발생했습니다: {str(e)}', 'danger')
    
    return redirect(url_for('admin_shopping_slots'))

@app.route('/admin/place_slots/create', methods=['POST'])
@admin_required
def admin_create_place_slot():
    """관리자가 플레이스 슬롯 생성"""
    try:
        # 폼 데이터 가져오기
        user_id = request.form.get('user_id')
        slot_name = request.form.get('slot_name')
        slot_type = request.form.get('slot_type', 'search')
        status = request.form.get('status', 'empty')
        
        try:
            slot_price = safe_int(request.form.get('slot_price'), 0)
        except ValueError as e:
            flash(f'슬롯 단가 입력 오류: {str(e)}', 'danger')
            return redirect(url_for('admin_place_slots'))
        
        notes = request.form.get('notes', '')
        
        # 날짜 처리
        start_date = None
        start_date_str = request.form.get('start_date')
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            
        end_date = None
        end_date_str = request.form.get('end_date')
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        
        # 플레이스 슬롯 생성
        slot = PlaceSlot(
            user_id=user_id,
            slot_name=slot_name,
            start_date=start_date,
            end_date=end_date,
            status=status,
            slot_price=slot_price,
            slot_type=slot_type,
            notes=notes,
            admin_price=slot_price  # 관리자가 생성한 슬롯은 기본적으로 단가와 정산가가 동일
        )
        
        db.session.add(slot)
        db.session.commit()
        
        flash(f'플레이스 슬롯 "{slot_name}"이(가) 성공적으로 생성되었습니다.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'슬롯 생성 중 오류가 발생했습니다: {str(e)}', 'danger')
    
    return redirect(url_for('admin_place_slots'))

@app.route('/admin/shopping_slots/edit/<int:slot_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_shopping_slot(slot_id):
    """관리자가 쇼핑 슬롯 편집"""
    slot = ShoppingSlot.query.get_or_404(slot_id)
    
    if request.method == 'POST':
        try:
            # 기본 정보 업데이트
            slot.slot_name = request.form.get('slot_name')
            slot.status = request.form.get('status')
            slot.slot_type = request.form.get('slot_type')
            try:
                slot.slot_price = safe_int(request.form.get('slot_price'), 0)
                slot.admin_price = safe_int(request.form.get('admin_price'), 0)
            except ValueError as e:
                flash(f'가격 입력 오류: {str(e)}', 'danger')
                return redirect(url_for('admin_edit_shopping_slot', slot_id=slot.id))
            
            slot.notes = request.form.get('notes', '')
            
            # 날짜 처리
            start_date_str = request.form.get('start_date')
            if start_date_str:
                slot.start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
                
            end_date_str = request.form.get('end_date')
            if end_date_str:
                slot.end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            
            # 슬롯 상세 정보 업데이트
            if request.form.get('product_name'):
                slot.product_name = request.form.get('product_name')
                
            if request.form.get('product_id'):
                slot.product_id = request.form.get('product_id')
                
            if request.form.get('store_name'):
                slot.store_name = request.form.get('store_name')
                
            if request.form.get('keywords'):
                slot.keywords = request.form.get('keywords')
                
            if request.form.get('price'):
                slot.price = int(request.form.get('price', 0))
                
            if request.form.get('sale_price'):
                slot.sale_price = int(request.form.get('sale_price', 0))
                
            if request.form.get('shopping_campaign_id'):
                slot.shopping_campaign_id = request.form.get('shopping_campaign_id')
                
            if request.form.get('product_image_url'):
                slot.product_image_url = request.form.get('product_image_url')
            
            db.session.commit()
            flash('쇼핑 슬롯이 성공적으로 업데이트 되었습니다.', 'success')
            return redirect(url_for('admin_shopping_slots'))
        except Exception as e:
            db.session.rollback()
            flash(f'슬롯 업데이트 중 오류가 발생했습니다: {str(e)}', 'danger')
    
    # 총판 및 대행사 목록
    distributors = User.query.join(Role).filter(Role.name == 'distributor').all()
    agencies = User.query.join(Role).filter(Role.name == 'agency').all()
    
    return render_template('admin/edit_shopping_slot.html', slot=slot, distributors=distributors, agencies=agencies)

@app.route('/admin/place_slots/edit/<int:slot_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_place_slot(slot_id):
    """관리자가 플레이스 슬롯 편집"""
    slot = PlaceSlot.query.get_or_404(slot_id)
    
    if request.method == 'POST':
        try:
            # 기본 정보 업데이트
            slot.slot_name = request.form.get('slot_name')
            slot.status = request.form.get('status')
            slot.slot_type = request.form.get('slot_type')
            try:
                slot.slot_price = safe_int(request.form.get('slot_price'), 0)
                slot.admin_price = safe_int(request.form.get('admin_price'), 0)
            except ValueError as e:
                flash(f'가격 입력 오류: {str(e)}', 'danger')
                return redirect(url_for('admin_edit_shopping_slot', slot_id=slot.id))
            
            slot.notes = request.form.get('notes', '')
            
            # 날짜 처리
            start_date_str = request.form.get('start_date')
            if start_date_str:
                slot.start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
                
            end_date_str = request.form.get('end_date')
            if end_date_str:
                slot.end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
                
            deadline_date_str = request.form.get('deadline_date')
            if deadline_date_str:
                slot.deadline_date = datetime.strptime(deadline_date_str, '%Y-%m-%d').date()
            
            # 슬롯 상세 정보 업데이트
            if request.form.get('place_name'):
                slot.place_name = request.form.get('place_name')
                
            if request.form.get('place_id'):
                slot.place_id = request.form.get('place_id')
                
            if request.form.get('business_category'):
                slot.business_category = request.form.get('business_category')
                
            if request.form.get('business_type'):
                slot.business_type = request.form.get('business_type')
                
            if request.form.get('address'):
                slot.address = request.form.get('address')
                
            if request.form.get('operation_status'):
                slot.operation_status = request.form.get('operation_status')
                
            if request.form.get('status_reason'):
                slot.status_reason = request.form.get('status_reason')
                
            if request.form.get('status_detail'):
                slot.status_detail = request.form.get('status_detail')
            
            db.session.commit()
            flash('플레이스 슬롯이 성공적으로 업데이트 되었습니다.', 'success')
            return redirect(url_for('admin_place_slots'))
        except Exception as e:
            db.session.rollback()
            flash(f'슬롯 업데이트 중 오류가 발생했습니다: {str(e)}', 'danger')
    
    # 총판 및 대행사 목록
    distributors = User.query.join(Role).filter(Role.name == 'distributor').all()
    agencies = User.query.join(Role).filter(Role.name == 'agency').all()
    
    return render_template('admin/edit_place_slot.html', slot=slot, distributors=distributors, agencies=agencies)

@app.route('/admin/shopping_slots/delete/<int:slot_id>')
@admin_required
def admin_delete_shopping_slot(slot_id):
    """관리자가 쇼핑 슬롯 삭제"""
    slot = ShoppingSlot.query.get_or_404(slot_id)
    slot_name = slot.slot_name
    
    try:
        # 슬롯 관련 승인 요청 삭제
        SlotApproval.query.filter_by(shopping_slot_id=slot_id).delete()
        
        # 슬롯 관련 정산 항목 삭제
        SettlementItem.query.filter_by(shopping_slot_id=slot_id).delete()
        
        # 슬롯 삭제
        db.session.delete(slot)
        db.session.commit()
        
        flash(f'쇼핑 슬롯 "{slot_name}"이(가) 성공적으로 삭제되었습니다.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'슬롯 삭제 중 오류가 발생했습니다: {str(e)}', 'danger')
    
    return redirect(url_for('admin_shopping_slots'))

@app.route('/admin/place_slots/delete/<int:slot_id>')
@admin_required
def admin_delete_place_slot(slot_id):
    """관리자가 플레이스 슬롯 삭제"""
    slot = PlaceSlot.query.get_or_404(slot_id)
    slot_name = slot.slot_name
    
    try:
        # 슬롯 관련 승인 요청 삭제
        SlotApproval.query.filter_by(place_slot_id=slot_id).delete()
        
        # 슬롯 관련 정산 항목 삭제
        SettlementItem.query.filter_by(place_slot_id=slot_id).delete()
        
        # 슬롯 삭제
        db.session.delete(slot)
        db.session.commit()
        
        flash(f'플레이스 슬롯 "{slot_name}"이(가) 성공적으로 삭제되었습니다.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'슬롯 삭제 중 오류가 발생했습니다: {str(e)}', 'danger')
    
    return redirect(url_for('admin_place_slots'))

@app.route('/admin/bulk-approve', methods=['POST'])
@login_required
@admin_required
def admin_bulk_approve():
    """일괄 승인/거절 처리"""
    # 요청 데이터 가져오기
    data = request.json
    if not data:
        return jsonify({'success': False, 'message': '요청 데이터가 없습니다.'}), 400
        
    approval_ids = data.get('approval_ids', [])
    action = data.get('action', 'approve')  # 'approve' 또는 'reject'
    
    if not approval_ids:
        return jsonify({'success': False, 'message': '선택된 항목이 없습니다.'}), 400
    
    # 승인 요청 조회
    approvals = SlotApproval.query.filter(
        SlotApproval.id.in_(approval_ids),
        SlotApproval.status == 'pending'  # 대기 중인 요청만 처리
    ).all()
    
    if not approvals:
        return jsonify({'success': False, 'message': '처리할 승인 요청을 찾을 수 없습니다.'}), 404
    
    # 일괄 처리
    processed_count = 0
    for approval in approvals:
        # 승인 또는 거절 처리
        if action == 'approve':
            approval.status = 'approved'
            approval.approver_id = current_user.id
            approval.processed_at = datetime.utcnow()
            
            # 슬롯 상태 업데이트 ('approved'에서 'live'로 변경)
            if approval.slot_type == 'shopping':
                approval.shopping_slot.status = 'live'
            else:
                approval.place_slot.status = 'live'
        else:
            approval.status = 'rejected'
            approval.approver_id = current_user.id
            approval.processed_at = datetime.utcnow()
            
            # 슬롯 상태 업데이트
            if approval.slot_type == 'shopping':
                approval.shopping_slot.status = 'rejected'
            else:
                approval.place_slot.status = 'rejected'
                
        processed_count += 1
    
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'count': processed_count,
        'message': f"{processed_count}개의 요청이 {'승인' if action == 'approve' else '거절'}되었습니다."
    })

@app.route('/admin/approve/<int:approval_id>/<action>')
@admin_required
def admin_approve_request(approval_id, action):
    """승인 요청 처리 및 정산 자동 처리"""
    approval = SlotApproval.query.get_or_404(approval_id)
    
    if action == 'approve':
        approval.status = 'approved'
        approval.approver_id = current_user.id
        approval.processed_at = datetime.utcnow()
        
        # 슬롯 상태 업데이트 ('approved'에서 'live'로 변경)
        if approval.slot_type == 'shopping':
            slot = approval.shopping_slot
            slot.status = 'live'
            
            # 정산 자동 처리 - 슬롯 가격 × 100유입 × 기간
            if slot.start_date and slot.end_date:
                # 시작일과 종료일 사이의 일수 계산 (양 끝 포함)
                days = (slot.end_date - slot.start_date).days + 1
                
                # 30원 × 슬롯1개(100유입) × 기간으로 계산
                daily_visitors = 100  # 일일 100유입
                unit_price = 30  # 고정 단가 (30원)
                total_price = days * daily_visitors * unit_price
                total_admin_price = 0  # 어드민 정산가 불필요
                
                # 기본 정보 로깅
                app.logger.info(f"자동 정산 처리 - 쇼핑 슬롯 #{slot.id}: {days}일 × {unit_price}원 × {daily_visitors}유입 = {total_price}원")
                
                # 정산 자동 생성
                today = datetime.now().date()
                
                # 자동 정산 생성 (일별 정산)
                day_start = today
                day_end = today
                
                # 슬롯 정산 상태 먼저 업데이트
                slot.settlement_status = 'in_progress'
                
                # 기존 정산이 있는지 확인 (사용자, 정산 타입, 기간)
                existing_settlement = Settlement.query.filter(
                    Settlement.user_id == slot.user_id,
                    Settlement.settlement_type == 'shopping',
                    Settlement.period_start <= today,
                    Settlement.period_end >= today,
                    Settlement.status == 'pending'
                ).first()
                
                if existing_settlement:
                    # 기존 정산에 항목 추가
                    settlement_item = SettlementItem(
                        settlement_id=existing_settlement.id,
                        shopping_slot_id=slot.id,
                        slot_price=total_price,  # 계산된 총 가격
                        admin_price=slot.admin_price or 0,
                        settlement_price=total_price
                    )
                    db.session.add(settlement_item)
                    
                    # 정산 합계 업데이트
                    existing_settlement.total_price += total_price
                    existing_settlement.admin_price += total_admin_price
                    existing_settlement.agency_price = existing_settlement.total_price - existing_settlement.admin_price
                    
                    # 변경사항 저장
                    db.session.flush()
                    
                    app.logger.info(f"기존 정산 #{existing_settlement.id}에 슬롯 #{slot.id} 추가됨")
                else:
                    # 새 정산 생성
                    new_settlement = Settlement(
                        user_id=slot.user_id,
                        admin_id=current_user.id,
                        settlement_type='shopping',
                        period_start=day_start,
                        period_end=day_end,
                        status='pending',
                        total_price=total_price,
                        admin_price=total_admin_price,
                        agency_price=total_price - total_admin_price,
                        notes=f"슬롯 승인 시 자동 생성된 정산 ({today} 생성)"
                    )
                    db.session.add(new_settlement)
                    db.session.flush()  # ID 생성
                    
                    # 정산 항목 추가
                    settlement_item = SettlementItem(
                        settlement_id=new_settlement.id,
                        shopping_slot_id=slot.id,
                        slot_price=total_price,  # 계산된 총 가격
                        admin_price=slot.admin_price or 0,
                        settlement_price=total_price
                    )
                    db.session.add(settlement_item)
                    
                    # 변경사항 저장
                    db.session.flush()
                    
                    app.logger.info(f"새 정산 #{new_settlement.id} 생성됨 (슬롯 #{slot.id})")
            
        else:
            slot = approval.place_slot
            slot.status = 'live'
            
            # 정산 자동 처리 - 슬롯당 100유입 리워드로 고정
            if slot.start_date and slot.end_date:
                # 시작일과 종료일 사이의 일수 계산 (양 끝 포함)
                days = (slot.end_date - slot.start_date).days + 1
                
                # 30원 × 슬롯1개(100유입) × 기간으로 계산
                daily_visitors = 100  # 일일 100유입
                unit_price = 30  # 고정 단가 (30원)
                total_price = days * daily_visitors * unit_price
                total_admin_price = 0  # 어드민 정산가 불필요
                
                # 기본 정보 로깅
                app.logger.info(f"자동 정산 처리 - 플레이스 슬롯 #{slot.id}: {days}일 × {unit_price}원 × {daily_visitors}유입 = {total_price}원")
                
                # 정산 자동 생성
                today = datetime.now().date()
                
                # 자동 정산 생성 (일별 정산)
                day_start = today
                day_end = today
                
                # 슬롯 정산 상태 먼저 업데이트
                slot.settlement_status = 'in_progress'
                
                # 기존 정산이 있는지 확인 (사용자, 정산 타입, 기간)
                existing_settlement = Settlement.query.filter(
                    Settlement.user_id == slot.user_id,
                    Settlement.settlement_type == 'place',
                    Settlement.period_start <= today,
                    Settlement.period_end >= today,
                    Settlement.status == 'pending'
                ).first()
                
                if existing_settlement:
                    # 기존 정산에 항목 추가
                    settlement_item = SettlementItem(
                        settlement_id=existing_settlement.id,
                        place_slot_id=slot.id,
                        slot_price=total_price,  # 계산된 총 가격
                        admin_price=slot.admin_price or 0,
                        settlement_price=total_price
                    )
                    db.session.add(settlement_item)
                    
                    # 정산 합계 업데이트
                    existing_settlement.total_price += total_price
                    existing_settlement.admin_price += total_admin_price
                    existing_settlement.agency_price = existing_settlement.total_price - existing_settlement.admin_price
                    
                    # 변경사항 저장
                    db.session.flush()
                    
                    app.logger.info(f"기존 정산 #{existing_settlement.id}에 슬롯 #{slot.id} 추가됨")
                else:
                    # 새 정산 생성
                    new_settlement = Settlement(
                        user_id=slot.user_id,
                        admin_id=current_user.id,
                        settlement_type='place',
                        period_start=day_start,
                        period_end=day_end,
                        status='pending',
                        total_price=total_price,
                        admin_price=total_admin_price,
                        agency_price=total_price - total_admin_price,
                        notes=f"슬롯 승인 시 자동 생성된 정산 ({today} 생성)"
                    )
                    db.session.add(new_settlement)
                    db.session.flush()  # ID 생성
                    
                    # 정산 항목 추가
                    settlement_item = SettlementItem(
                        settlement_id=new_settlement.id,
                        place_slot_id=slot.id,
                        slot_price=total_price,  # 계산된 총 가격
                        admin_price=slot.admin_price or 0,
                        settlement_price=total_price
                    )
                    db.session.add(settlement_item)
                    
                    # 변경사항 저장
                    db.session.flush()
                    
                    app.logger.info(f"새 정산 #{new_settlement.id} 생성됨 (슬롯 #{slot.id})")
            
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
    
    # 모든 변경사항 커밋
    db.session.commit()
    
    app.logger.info(f"슬롯 승인/거절 처리 완료: approval_id={approval_id}, action={action}")
    return redirect(url_for('admin_approvals'))

# 총판 라우트
@app.route('/distributor/dashboard')
@distributor_required
def distributor_dashboard():
    """총판 대시보드"""
    # agencies는 lazy='dynamic'이므로 직접 조회
    agencies_count = current_user.agencies.count()
    
    # 이 총판에 속한 대행사들의 ID 리스트 (총판 자신 포함) - 한 번만 조회
    agencies_list = current_user.agencies.all()
    agency_ids = [agency.id for agency in agencies_list]
    user_ids = agency_ids + [current_user.id]  # 총판 자신의 ID도 포함
    
    # 이 총판과 소속 대행사들의 슬롯 통계
    shopping_slots = ShoppingSlot.query.filter(ShoppingSlot.user_id.in_(user_ids)).count() if user_ids else 0
    place_slots = PlaceSlot.query.filter(PlaceSlot.user_id.in_(user_ids)).count() if user_ids else 0
    
    # 총판 자신의 슬롯 통계
    distributor_shopping_slots = current_user.shopping_slots.count()
    distributor_place_slots = current_user.place_slots.count()
    
    # 승인 상태별 슬롯 통계 (총판+대행사)
    shopping_pending = ShoppingSlot.query.filter(
        ShoppingSlot.user_id.in_(user_ids), 
        ShoppingSlot.status == 'pending'
    ).count() if user_ids else 0
    
    shopping_approved = ShoppingSlot.query.filter(
        ShoppingSlot.user_id.in_(user_ids), 
        ShoppingSlot.status == 'approved'
    ).count() if user_ids else 0
    
    shopping_rejected = ShoppingSlot.query.filter(
        ShoppingSlot.user_id.in_(user_ids), 
        ShoppingSlot.status == 'rejected'
    ).count() if user_ids else 0
    
    place_pending = PlaceSlot.query.filter(
        PlaceSlot.user_id.in_(user_ids), 
        PlaceSlot.status == 'pending'
    ).count() if user_ids else 0
    
    place_approved = PlaceSlot.query.filter(
        PlaceSlot.user_id.in_(user_ids), 
        PlaceSlot.status == 'approved'
    ).count() if user_ids else 0
    
    place_rejected = PlaceSlot.query.filter(
        PlaceSlot.user_id.in_(user_ids), 
        PlaceSlot.status == 'rejected'
    ).count() if user_ids else 0
    
    # 이 총판에게 온 승인 요청 (소속 대행사들의 요청) + 자신이 제출한 승인 요청
    agency_requests = SlotApproval.query.filter(
        SlotApproval.status == 'pending',
        SlotApproval.requester_id.in_(agency_ids)
    ).count() if agency_ids else 0
    
    # 총판 자신이 제출한 승인 요청 (관리자에게 보냄)
    distributor_requests = SlotApproval.query.filter(
        SlotApproval.status == 'pending',
        SlotApproval.requester_id == current_user.id
    ).count()
    
    # 총 승인 요청 수
    pending_approvals = agency_requests + distributor_requests
    
    # 최신 승인 요청 5개 가져오기 (대행사 요청 + 본인 요청)
    # 대행사 요청
    agency_approval_list = SlotApproval.query.filter(
        SlotApproval.status == 'pending',
        SlotApproval.requester_id.in_(agency_ids)
    ).order_by(SlotApproval.requested_at.desc()).limit(3).all() if agency_ids else []
    
    # 본인 요청
    distributor_approval_list = SlotApproval.query.filter(
        SlotApproval.status == 'pending',
        SlotApproval.requester_id == current_user.id
    ).order_by(SlotApproval.requested_at.desc()).limit(3).all()
    
    # 두 목록 합치기
    recent_agency_approvals = agency_approval_list + distributor_approval_list
    # 날짜순 정렬
    recent_agency_approvals.sort(key=lambda x: x.requested_at, reverse=True)
    # 최대 5개만 표시
    recent_agency_approvals = recent_agency_approvals[:5]
    
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
                          place_rejected=place_rejected,
                          recent_agency_approvals=recent_agency_approvals,
                          distributor_shopping_slots=distributor_shopping_slots,
                          distributor_place_slots=distributor_place_slots)

@app.route('/distributor/agencies')
@distributor_required
def distributor_agencies():
    """총판의 대행사 관리 페이지"""
    agencies = current_user.agencies.all()
    return render_template('distributor/agencies.html', agencies=agencies)

@app.route('/distributor/toggle-slot/<int:slot_id>', methods=['POST'])
@csrf.exempt
@distributor_required
def toggle_slot(slot_id):
    """슬롯 활성화/비활성화 토글"""
    try:
        data = request.json
        active = data.get('active', False)
        
        # 슬롯 타입 (쇼핑/플레이스) 확인
        shopping_slot = ShoppingSlot.query.get(slot_id)
        if shopping_slot:
            # 슬롯이 현재 사용자 또는 소속 대행사에 속하는지 확인
            agencies = current_user.agencies.all()
            agency_ids = [agency.id for agency in agencies]
            user_ids = agency_ids + [current_user.id]
            
            if shopping_slot.user_id not in user_ids:
                return jsonify({'success': False, 'message': '권한이 없습니다.'}), 403
            
            # 승인된 상태만 토글 가능
            if shopping_slot.status not in ['approved', 'live']:
                return jsonify({'success': False, 'message': '승인된 슬롯만 활성화할 수 있습니다.'}), 400
                
            # 상태 변경
            shopping_slot.status = 'live' if active else 'approved'
            db.session.commit()
            return jsonify({'success': True})
        
        place_slot = PlaceSlot.query.get(slot_id)
        if place_slot:
            # 슬롯이 현재 사용자 또는 소속 대행사에 속하는지 확인
            agencies = current_user.agencies.all()
            agency_ids = [agency.id for agency in agencies]
            user_ids = agency_ids + [current_user.id]
            
            if place_slot.user_id not in user_ids:
                return jsonify({'success': False, 'message': '권한이 없습니다.'}), 403
            
            # 승인된 상태만 토글 가능
            if place_slot.status not in ['approved', 'live']:
                return jsonify({'success': False, 'message': '승인된 슬롯만 활성화할 수 있습니다.'}), 400
                
            # 상태 변경
            place_slot.status = 'live' if active else 'approved'
            db.session.commit()
            return jsonify({'success': True})
            
        return jsonify({'success': False, 'message': '슬롯을 찾을 수 없습니다.'}), 404
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/distributor/slots')
@distributor_required
def distributor_slots():
    """총판의 슬롯 관리 페이지"""
    slot_type = request.args.get('type', 'shopping')
    status = request.args.get('status', '')
    agency_id = request.args.get('agency_id', '')
    search = request.args.get('search', '')
    
    # 대행사 목록
    agencies = current_user.agencies.all()
    
    # 기본 쿼리 구성
    if slot_type == 'shopping':
        # 대행사의 슬롯 + 총판 자신의 슬롯 함께 조회
        agency_ids = [agency.id for agency in agencies]
        user_ids = agency_ids + [current_user.id]  # 총판 자신의 ID 추가
        
        # 대행사 + 총판 자신의 슬롯 모두 가져오기
        query = ShoppingSlot.query.filter(ShoppingSlot.user_id.in_(user_ids))
    else:
        # 대행사의 슬롯 + 총판 자신의 슬롯 함께 조회
        agency_ids = [agency.id for agency in agencies]
        user_ids = agency_ids + [current_user.id]  # 총판 자신의 ID 추가
        
        # 대행사 + 총판 자신의 슬롯 모두 가져오기
        query = PlaceSlot.query.filter(PlaceSlot.user_id.in_(user_ids))
    
    # 필터 적용
    if status:
        query = query.filter_by(status=status)
    
    if agency_id:
        if agency_id == 'self':
            # 총판 자신의 슬롯만 필터링
            query = query.filter(ShoppingSlot.user_id == current_user.id if slot_type == 'shopping' else PlaceSlot.user_id == current_user.id)
        else:
            # 특정 대행사의 슬롯만 필터링
            query = query.filter(ShoppingSlot.user_id == agency_id if slot_type == 'shopping' else PlaceSlot.user_id == agency_id)
    
    if search:
        if slot_type == 'shopping':
            query = query.filter(db.or_(
                ShoppingSlot.slot_name.like(f'%{search}%'),
                ShoppingSlot.product_name.like(f'%{search}%'),
                ShoppingSlot.keywords.like(f'%{search}%'),
                ShoppingSlot.store_name.like(f'%{search}%')
            ))
        else:
            query = query.filter(db.or_(
                PlaceSlot.slot_name.like(f'%{search}%'),
                PlaceSlot.place_name.like(f'%{search}%'),
                PlaceSlot.address.like(f'%{search}%'),
                PlaceSlot.business_type.like(f'%{search}%')
            ))
    
    # 결과 조회
    slots = query.all()
    
    return render_template('distributor/slots.html', 
                          slot_type=slot_type,
                          status=status,
                          agency_id=agency_id,
                          search=search,
                          agencies=agencies,
                          slots=slots)

@app.route('/distributor/slots/create', methods=['POST'])
@distributor_required
def create_distributor_slot():
    """총판의 슬롯 할당 (수량, 가격, 기간만 지정)"""
    slot_type = request.form.get('slot_type')
    agency_id = request.form.get('agency_id')
    slot_quantity = int(request.form.get('slot_quantity', 1))
    # 슬롯 단가는 0원에서 1000원으로 제한
    slot_price = min(max(int(request.form.get('slot_price', 0)), 0), 1000)
    slot_sub_type = request.form.get('slot_sub_type')
    notes = request.form.get('notes', '')
    
    # 대행사 또는 총판 자신용 슬롯 구분
    is_for_distributor = False  # 총판 자신용 슬롯인지 여부
    if agency_id and agency_id.strip():
        # 대행사 확인
        agency = User.query.get_or_404(agency_id)
        if agency.parent_id != current_user.id:
            abort(403)  # 자신의 대행사가 아닌 경우 접근 불가
        assigned_user_id = agency.id
    else:
        # 총판 자신용 슬롯
        assigned_user_id = current_user.id
        is_for_distributor = True
    
    # 날짜 처리
    start_date = request.form.get('start_date')
    if start_date:
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
    
    end_date = request.form.get('end_date')
    if end_date:
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
    
    try:
        # 할당된 슬롯 수 만큼 빈 슬롯 생성
        created_slots = 0
        created_approvals = 0
        
        for i in range(slot_quantity):
            # 슬롯 이름 설정
            user = User.query.get(assigned_user_id)
            owner_name = user.company_name if user else current_user.company_name
                
            slot_name = f"{owner_name} {slot_type.capitalize()} 슬롯 {datetime.now().strftime('%Y%m%d')}-{i+1}"
            
            # 총판용 슬롯 상태: 바로 'empty'가 아니라 'pending'으로 생성
            slot_status = 'pending' if is_for_distributor else 'empty'
            
            if slot_type == 'shopping':
                # 쇼핑 슬롯 생성
                slot = ShoppingSlot(
                    user_id=assigned_user_id,
                    slot_name=slot_name,
                    start_date=start_date,
                    end_date=end_date,
                    status=slot_status,  # 총판용은 pending으로, 대행사용은 empty로
                    slot_price=slot_price,
                    slot_type=slot_sub_type or 'standard',  # standard 또는 premium
                    notes=notes
                )
            else:
                # 플레이스 슬롯 생성
                slot = PlaceSlot(
                    user_id=assigned_user_id,
                    slot_name=slot_name,
                    start_date=start_date,
                    end_date=end_date,
                    status=slot_status,  # 총판용은 pending으로, 대행사용은 empty로
                    slot_price=slot_price,
                    slot_type=slot_sub_type or 'search',  # search 또는 save
                    notes=notes
                )
            
            db.session.add(slot)
            db.session.flush()  # ID 생성을 위한 플러시
            created_slots += 1
            
            # 총판 자신용 슬롯이면 승인 요청 생성 (어드민에게 요청)
            if is_for_distributor:
                approval = SlotApproval(
                    requester_id=current_user.id,
                    shopping_slot_id=slot.id if slot_type == 'shopping' else None,
                    place_slot_id=slot.id if slot_type == 'place' else None,
                    approval_type='create'
                )
                db.session.add(approval)
                created_approvals += 1
        
        # 슬롯 저장
        db.session.commit()
        
        if is_for_distributor:
            flash(f'{created_slots}개의 {slot_type} 슬롯 요청이 생성되었고, 관리자 승인 대기 중입니다.', 'success')
        else:
            flash(f'{created_slots}개의 {slot_type} 슬롯이 성공적으로 생성되었습니다.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'슬롯 생성 중 오류가 발생했습니다: {str(e)}', 'danger')
    
    return redirect(url_for('distributor_slots', type=slot_type))

# 위에서 정의된 edit_shopping_slot 함수와 중복되어 제거했습니다

# 다른 위치에 정의된 edit_place_slot 함수와 중복되어 제거했습니다

@app.route('/distributor/slots/delete/<int:slot_id>')
@distributor_required
def delete_distributor_slot(slot_id):
    """총판이 슬롯을 삭제"""
    slot_type = request.args.get('type', 'shopping')
    
    try:
        if slot_type == 'shopping':
            # 쇼핑 슬롯 삭제
            slot = ShoppingSlot.query.get_or_404(slot_id)
        else:
            # 플레이스 슬롯 삭제
            slot = PlaceSlot.query.get_or_404(slot_id)
        
        # 슬롯이 본인 소유이거나 자신의 대행사의 슬롯인지 확인
        if slot.user_id == current_user.id or slot.user.parent_id == current_user.id:
            db.session.delete(slot)
            db.session.commit()
            flash('슬롯이 성공적으로 삭제되었습니다.', 'success')
        else:
            flash('이 슬롯을 삭제할 권한이 없습니다.', 'danger')
            
    except Exception as e:
        db.session.rollback()
        flash(f'슬롯 삭제 중 오류가 발생했습니다: {str(e)}', 'danger')
    
    return redirect(url_for('distributor_slots', type=slot_type))

@app.route('/distributor/slots/upload', methods=['POST'])
@distributor_required
def upload_distributor_slots():
    """총판의 슬롯 일괄 업로드"""
    slot_type = request.form.get('slot_type')
    agency_id = request.form.get('agency_id')
    # 슬롯 단가는 0원에서 1000원으로 제한
    try:
        slot_price = min(max(int(request.form.get('slot_price', 0)), 0), 1000)
    except (ValueError, TypeError):
        slot_price = 0
    
    # 대행사 또는 총판 자신용 슬롯 구분
    is_for_distributor = False  # 총판 자신용 슬롯인지 여부
    if agency_id and agency_id.strip():
        # 대행사 확인
        agency = User.query.get_or_404(agency_id)
        if agency.parent_id != current_user.id:
            abort(403)  # 자신의 대행사가 아닌 경우 접근 불가
        assigned_user_id = agency.id
    else:
        # 총판 자신용 슬롯
        assigned_user_id = current_user.id
        is_for_distributor = True
    
    if 'file' not in request.files:
        flash('파일이 제공되지 않았습니다.', 'danger')
        return redirect(url_for('distributor_slots', type=slot_type))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('선택된 파일이 없습니다.', 'danger')
        return redirect(url_for('distributor_slots', type=slot_type))
    
    if not allowed_file(file.filename):
        flash('허용되지 않는 파일 형식입니다. Excel 파일(.xlsx, .xls)만 업로드 가능합니다.', 'danger')
        return redirect(url_for('distributor_slots', type=slot_type))
    
    try:
        # 파일 저장
        if not file.filename:
            flash('파일명이 유효하지 않습니다.', 'danger')
            return redirect(url_for('distributor_slots', type=slot_type))
            
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # 엑셀 파일 처리
        df = pd.read_excel(file_path)
        
        success_count = 0
        error_count = 0
        approval_count = 0
        
        # 총판용 슬롯 상태: 바로 'approved'가 아니라 'pending'으로 생성
        slot_status = 'pending' if is_for_distributor else 'approved'
        
        for _, row in df.iterrows():
            try:
                if slot_type == 'shopping':
                    # 쇼핑 슬롯 생성
                    slot = ShoppingSlot(
                        user_id=assigned_user_id,
                        slot_name=row.get('슬롯명', ''),
                        store_type=row.get('스토어 타입', ''),
                        product_id=row.get('상품 ID', ''),
                        product_name=row.get('상품명', ''),
                        keywords=row.get('키워드', ''),
                        price=row.get('가격', None),
                        sale_price=row.get('할인가', None),
                        start_date=pd.to_datetime(row.get('시작일')).date() if pd.notna(row.get('시작일')) else None,
                        end_date=pd.to_datetime(row.get('종료일')).date() if pd.notna(row.get('종료일')) else None,
                        bid_type=row.get('입찰방식', ''),
                        status=slot_status,  # 총판용은 pending으로, 대행사용은 approved로
                        slot_price=row.get('슬롯 단가', slot_price)
                    )
                else:
                    # 플레이스 슬롯 생성
                    slot = PlaceSlot(
                        user_id=assigned_user_id,
                        slot_name=row.get('슬롯명', ''),
                        place_name=row.get('장소명', ''),
                        address=row.get('주소', ''),
                        business_type=row.get('업종분류', ''),
                        place_id=row.get('장소 ID', ''),
                        start_date=pd.to_datetime(row.get('시작일')).date() if pd.notna(row.get('시작일')) else None,
                        end_date=pd.to_datetime(row.get('종료일')).date() if pd.notna(row.get('종료일')) else None,
                        deadline_date=pd.to_datetime(row.get('마감일')).date() if pd.notna(row.get('마감일')) else None,
                        status=slot_status,  # 총판용은 pending으로, 대행사용은 approved로
                        slot_price=row.get('슬롯 단가', slot_price)
                    )
                
                db.session.add(slot)
                db.session.flush()  # ID 생성을 위한 플러시
                success_count += 1
                
                # 총판 자신용 슬롯이면 승인 요청 생성 (어드민에게 요청)
                if is_for_distributor:
                    approval = SlotApproval(
                        requester_id=current_user.id,
                        shopping_slot_id=slot.id if slot_type == 'shopping' else None,
                        place_slot_id=slot.id if slot_type == 'place' else None,
                        approval_type='create'
                    )
                    db.session.add(approval)
                    approval_count += 1
                
            except Exception as e:
                error_count += 1
                logger.error(f"Error processing row: {e}")
        
        db.session.commit()
        
        if is_for_distributor:
            flash(f'{success_count}개의 {slot_type} 슬롯 요청이 생성되었고, {approval_count}개의 승인 요청이 관리자에게 제출되었습니다.', 'success')
        else:
            flash(f'{success_count}개의 {slot_type} 슬롯이 성공적으로 등록되었습니다.', 'success')
        
        if error_count > 0:
            flash(f'{error_count}개의 슬롯을 처리하는 중 오류가 발생했습니다.', 'warning')
        
    except Exception as e:
        db.session.rollback()
        flash(f'엑셀 파일 처리 중 오류가 발생했습니다: {str(e)}', 'danger')
        logger.error(f"Error processing Excel file: {e}")
    
    return redirect(url_for('distributor_slots', type=slot_type))

@app.route('/export-slots')
@login_required
def export_slots():
    """슬롯 엑셀 양식 내보내기"""
    slot_type = request.args.get('type', 'shopping')
    is_template = request.args.get('template', 'false') == 'true'
    
    if is_template:
        # 양식만 제공
        if slot_type == 'shopping':
            data = {
                '슬롯명': ['샘플 슬롯 1', '샘플 슬롯 2'],
                '스토어 타입': ['스마트스토어', '브랜드몰'],
                '상품 ID': ['P12345', 'P67890'],
                '상품명': ['샘플 상품 1', '샘플 상품 2'],
                '키워드': ['키워드1,키워드2', '키워드3,키워드4'],
                '가격': [10000, 20000],
                '할인가': [8000, 18000],
                '시작일': [pd.Timestamp('2025-05-01'), pd.Timestamp('2025-05-15')],
                '종료일': [pd.Timestamp('2025-05-31'), pd.Timestamp('2025-06-15')],
                '입찰방식': ['CPC', 'CPM'],
                '슬롯 단가': [500, 800]
            }
        else:
            data = {
                '슬롯명': ['샘플 슬롯 1', '샘플 슬롯 2'],
                '장소명': ['샘플 장소 1', '샘플 장소 2'],
                '주소': ['서울시 강남구...', '서울시 송파구...'],
                '업종분류': ['음식점', '카페'],
                '장소 ID': ['PL12345', 'PL67890'],
                '시작일': [pd.Timestamp('2025-05-01'), pd.Timestamp('2025-05-15')],
                '종료일': [pd.Timestamp('2025-05-31'), pd.Timestamp('2025-06-15')],
                '마감일': [pd.Timestamp('2025-06-15'), pd.Timestamp('2025-07-01')],
                '슬롯 단가': [700, 900]
            }
    else:
        # 실제 데이터 추출
        if current_user.is_admin():
            # 관리자는 모든 슬롯을 볼 수 있음
            if slot_type == 'shopping':
                slots = ShoppingSlot.query.all()
            elif slot_type == 'place':
                slots = PlaceSlot.query.all()
            else:  # 'all'인 경우
                shopping_slots = ShoppingSlot.query.all()
                place_slots = PlaceSlot.query.all()
        elif current_user.is_distributor():
            # 총판은 자신의 대행사 슬롯만 볼 수 있음
            agency_ids = [agency.id for agency in current_user.agencies]
            
            if slot_type == 'shopping':
                slots = ShoppingSlot.query.filter(ShoppingSlot.user_id.in_(agency_ids)).all() if agency_ids else []
            elif slot_type == 'place':
                slots = PlaceSlot.query.filter(PlaceSlot.user_id.in_(agency_ids)).all() if agency_ids else []
            else:  # 'all'인 경우
                shopping_slots = ShoppingSlot.query.filter(ShoppingSlot.user_id.in_(agency_ids)).all() if agency_ids else []
                place_slots = PlaceSlot.query.filter(PlaceSlot.user_id.in_(agency_ids)).all() if agency_ids else []
        else:
            # 대행사는 자신의 슬롯만 볼 수 있음
            if slot_type == 'shopping':
                slots = current_user.shopping_slots.all()
            elif slot_type == 'place':
                slots = current_user.place_slots.all()
            else:  # 'all'인 경우
                shopping_slots = current_user.shopping_slots.all()
                place_slots = current_user.place_slots.all()
        
        # 데이터프레임 생성
        if slot_type == 'shopping':
            data = {
                '슬롯명': [slot.slot_name for slot in slots],
                '대행사': [slot.user.company_name for slot in slots],
                '스토어 타입': [slot.store_type for slot in slots],
                '상품 ID': [slot.product_id for slot in slots],
                '상품명': [slot.product_name for slot in slots],
                '키워드': [slot.keywords for slot in slots],
                '가격': [slot.price for slot in slots],
                '할인가': [slot.sale_price for slot in slots],
                '시작일': [slot.start_date for slot in slots],
                '종료일': [slot.end_date for slot in slots],
                '입찰방식': [slot.bid_type for slot in slots],
                '상태': [slot.status for slot in slots],
                '슬롯 단가': [getattr(slot, 'slot_price', None) for slot in slots]
            }
        elif slot_type == 'place':
            data = {
                '슬롯명': [slot.slot_name for slot in slots],
                '대행사': [slot.user.company_name for slot in slots],
                '장소명': [slot.place_name for slot in slots],
                '주소': [slot.address for slot in slots],
                '업종분류': [slot.business_type for slot in slots],
                '장소 ID': [slot.place_id for slot in slots],
                '시작일': [slot.start_date for slot in slots],
                '종료일': [slot.end_date for slot in slots],
                '마감일': [slot.deadline_date for slot in slots],
                '상태': [slot.status for slot in slots],
                '슬롯 단가': [getattr(slot, 'slot_price', None) for slot in slots]
            }
        else:  # 'all'인 경우
            # 쇼핑과 플레이스 데이터를 모두 포함하는 엑셀 생성 (시트를 나눠서)
            writer = pd.ExcelWriter(os.path.join(app.config['UPLOAD_FOLDER'], 'slots_export.xlsx'), engine='openpyxl')
            
            # 쇼핑 슬롯 시트
            shopping_data = {
                '슬롯명': [slot.slot_name for slot in shopping_slots],
                '대행사': [slot.user.company_name for slot in shopping_slots],
                '스토어 타입': [slot.store_type for slot in shopping_slots],
                '상품 ID': [slot.product_id for slot in shopping_slots],
                '상품명': [slot.product_name for slot in shopping_slots],
                '키워드': [slot.keywords for slot in shopping_slots],
                '가격': [slot.price for slot in shopping_slots],
                '할인가': [slot.sale_price for slot in shopping_slots],
                '시작일': [slot.start_date for slot in shopping_slots],
                '종료일': [slot.end_date for slot in shopping_slots],
                '입찰방식': [slot.bid_type for slot in shopping_slots],
                '상태': [slot.status for slot in shopping_slots],
                '슬롯 단가': [getattr(slot, 'slot_price', None) for slot in shopping_slots]
            }
            
            # 플레이스 슬롯 시트
            place_data = {
                '슬롯명': [slot.slot_name for slot in place_slots],
                '대행사': [slot.user.company_name for slot in place_slots],
                '장소명': [slot.place_name for slot in place_slots],
                '주소': [slot.address for slot in place_slots],
                '업종분류': [slot.business_type for slot in place_slots],
                '장소 ID': [slot.place_id for slot in place_slots],
                '시작일': [slot.start_date for slot in place_slots],
                '종료일': [slot.end_date for slot in place_slots],
                '마감일': [slot.deadline_date for slot in place_slots],
                '상태': [slot.status for slot in place_slots],
                '슬롯 단가': [getattr(slot, 'slot_price', None) for slot in place_slots]
            }
            
            pd.DataFrame(shopping_data).to_excel(writer, sheet_name='쇼핑 슬롯', index=False)
            pd.DataFrame(place_data).to_excel(writer, sheet_name='플레이스 슬롯', index=False)
            
            writer.close()
            
            # 다운로드 제공
            return send_file(
                os.path.join(app.config['UPLOAD_FOLDER'], 'slots_export.xlsx'),
                as_attachment=True,
                download_name=f'전체_슬롯_목록_{datetime.now().strftime("%Y%m%d")}.xlsx',
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            )
    
    # 데이터프레임 생성 및 엑셀 파일 제공
    df = pd.DataFrame(data)
    
    # 임시 파일로 저장
    temp_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{slot_type}_slots_export.xlsx')
    df.to_excel(temp_file_path, index=False)
    
    # 다운로드 제공
    file_name = f'{slot_type}_슬롯_{"양식" if is_template else "목록"}_{datetime.now().strftime("%Y%m%d")}.xlsx'
    
    return send_file(
        temp_file_path,
        as_attachment=True,
        download_name=file_name,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

@app.route('/distributor/approvals')
@distributor_required
def distributor_approvals():
    """총판용 승인 요청 관리 페이지"""
    # agencies는 lazy='dynamic'이므로 직접 조회 - 한 번만 조회
    agencies_list = current_user.agencies.all()
    
    # 이 총판에 속한 대행사들의 ID 리스트
    agency_ids = [agency.id for agency in agencies_list]
    
    # 1. 대행사들로부터의 승인 요청 (requester, shopping_slot, place_slot eager load)
    agency_approvals = SlotApproval.query.options(
        joinedload(SlotApproval.requester),
        joinedload(SlotApproval.shopping_slot),
        joinedload(SlotApproval.place_slot)
    ).filter(
        SlotApproval.status == 'pending',
        SlotApproval.requester_id.in_(agency_ids)
    ).all() if agency_ids else []
    
    # 2. 총판 자신의 슬롯에 대한 승인 요청 (관리자만 승인 가능)
    distributor_approvals = SlotApproval.query.options(
        joinedload(SlotApproval.shopping_slot),
        joinedload(SlotApproval.place_slot)
    ).filter(
        SlotApproval.status == 'pending',
        SlotApproval.requester_id == current_user.id  # 총판 본인이 요청자
    ).all()
    
    # 3. 슬롯 할당량 요청 정보 (requester eager load)
    quota_requests = SlotQuotaRequest.query.options(
        joinedload(SlotQuotaRequest.requester)
    ).filter(
        SlotQuotaRequest.status == 'pending',
        SlotQuotaRequest.requester_id.in_(agency_ids)
    ).all() if agency_ids else []
    
    return render_template('distributor/approvals.html', 
                          agency_approvals=agency_approvals,
                          distributor_approvals=distributor_approvals,
                          quota_requests=quota_requests)

@app.route('/distributor/approve-quota/<int:request_id>', methods=['POST'])
@distributor_required
def distributor_approve_quota(request_id):
    """총판의 슬롯 할당량 요청 승인/거절 처리"""
    quota_request = SlotQuotaRequest.query.get_or_404(request_id)
    
    # agencies는 lazy='dynamic'이므로 직접 조회 - 한 번만 조회
    agencies_list = current_user.agencies.all()
    
    # 이 승인 요청이 자신의 대행사에서 온 것인지 확인
    agency_ids = [agency.id for agency in agencies_list]
    if quota_request.requester_id not in agency_ids:
        flash('이 요청을 처리할 권한이 없습니다.', 'danger')
        return redirect(url_for('distributor_approvals'))
    
    action = request.form.get('action')
    shopping_slot_price = request.form.get('shopping_slot_price', 0)
    place_slot_price = request.form.get('place_slot_price', 0)
    comment = request.form.get('comment', '')
    
    if action == 'approve':
        # 요청 승인
        quota_request.status = 'approved'
        quota_request.approver_id = current_user.id
        quota_request.processed_at = datetime.utcnow()
        quota_request.response_comment = comment
        
        # 슬롯 가격 설정 (0원에서 1000원으로 제한)
        if quota_request.shopping_slots_requested > 0 and shopping_slot_price:
            try:
                quota_request.shopping_slot_price = min(max(int(shopping_slot_price), 0), 1000)
            except (ValueError, TypeError):
                quota_request.shopping_slot_price = 0
        
        if quota_request.place_slots_requested > 0 and place_slot_price:
            try:
                quota_request.place_slot_price = min(max(int(place_slot_price), 0), 1000)
            except (ValueError, TypeError):
                quota_request.place_slot_price = 0
        
        # 대행사의 할당량 업데이트
        agency = User.query.get(quota_request.requester_id)
        if agency and agency.quota:
            agency.quota.shopping_slots_limit += quota_request.shopping_slots_requested
            agency.quota.place_slots_limit += quota_request.place_slots_requested
            
            # 승인된 수량만큼 빈 슬롯 자동 생성
            # 쇼핑 슬롯 생성
            for i in range(quota_request.shopping_slots_requested):
                shopping_slot = ShoppingSlot(
                    user_id=agency.id,
                    slot_name=f'빈 쇼핑 슬롯 #{i+1} ({quota_request.shopping_slot_type})',
                    start_date=quota_request.start_date,
                    end_date=quota_request.end_date,
                    slot_type=quota_request.shopping_slot_type,
                    slot_price=quota_request.shopping_slot_price,
                    status='empty'  # 빈 슬롯으로 생성
                )
                db.session.add(shopping_slot)
                
                # 사용된 슬롯 카운트 증가
                agency.quota.shopping_slots_used += 1
            
            # 플레이스 슬롯 생성
            for i in range(quota_request.place_slots_requested):
                place_slot = PlaceSlot(
                    user_id=agency.id,
                    slot_name=f'빈 플레이스 슬롯 #{i+1} ({quota_request.place_slot_type})',
                    start_date=quota_request.start_date,
                    end_date=quota_request.end_date,
                    slot_type=quota_request.place_slot_type,
                    slot_price=quota_request.place_slot_price,
                    status='empty'  # 빈 슬롯으로 생성
                )
                db.session.add(place_slot)
                
                # 사용된 슬롯 카운트 증가
                agency.quota.place_slots_used += 1
            
        flash('슬롯 할당량 요청이 승인되었고, 요청된 빈 슬롯이 생성되었습니다.', 'success')
    
    elif action == 'reject':
        # 요청 거절
        quota_request.status = 'rejected'
        quota_request.approver_id = current_user.id
        quota_request.processed_at = datetime.utcnow()
        quota_request.response_comment = comment
        
        flash('슬롯 할당량 요청이 거절되었습니다.', 'warning')
    
    db.session.commit()
    return redirect(url_for('distributor_approvals'))

@app.route('/distributor/approve/<int:approval_id>/<action>')
@distributor_required
def distributor_approve_request(approval_id, action):
    """총판의 승인 요청 처리 및 정산 자동 처리"""
    approval = SlotApproval.query.get_or_404(approval_id)
    
    # 이 승인 요청이 자신의 대행사에서 온 것인지 확인
    if approval.requester.parent_id != current_user.id:
        abort(403)
    
    if action == 'approve':
        approval.status = 'approved'
        approval.approver_id = current_user.id
        approval.processed_at = datetime.utcnow()
        
        # 슬롯 상태 업데이트 ('approved'에서 'live'로 변경)
        if approval.slot_type == 'shopping':
            slot = approval.shopping_slot
            slot.status = 'live'
            
            # 정산 자동 처리 - 슬롯당 100유입 리워드로 고정
            if slot.start_date and slot.end_date:
                # 30원 × 슬롯1개(100유입) × 기간으로 계산
                days = (slot.end_date - slot.start_date).days + 1
                daily_visitors = 100  # 일일 100유입
                unit_price = 30  # 고정 단가 (30원)
                total_price = days * daily_visitors * unit_price
                total_admin_price = 0  # 어드민 정산가 불필요
                
                # 기본 정보 로깅
                app.logger.info(f"자동 정산 처리 - 쇼핑 슬롯 #{slot.id}: {days}일 × {unit_price}원 × {daily_visitors}유입 = {total_price}원")
                
                # 정산 자동 생성
                today = datetime.now().date()
                
                # 자동 정산 생성 (일별 정산)
                day_start = today
                day_end = today
                
                # 슬롯 정산 상태 먼저 업데이트
                slot.settlement_status = 'in_progress'
                
                # 기존 정산이 있는지 확인 (사용자, 정산 타입, 기간)
                existing_settlement = Settlement.query.filter(
                    Settlement.user_id == slot.user_id,
                    Settlement.settlement_type == 'shopping',
                    Settlement.period_start <= today,
                    Settlement.period_end >= today,
                    Settlement.status == 'pending'
                ).first()
                
                if existing_settlement:
                    # 기존 정산에 항목 추가
                    settlement_item = SettlementItem(
                        settlement_id=existing_settlement.id,
                        shopping_slot_id=slot.id,
                        slot_price=total_price,  # 계산된 총 가격
                        admin_price=slot.admin_price or 0,
                        settlement_price=total_price
                    )
                    db.session.add(settlement_item)
                    
                    # 정산 합계 업데이트
                    existing_settlement.total_price += total_price
                    existing_settlement.admin_price += total_admin_price
                    existing_settlement.agency_price = existing_settlement.total_price - existing_settlement.admin_price
                    
                    # 변경사항 저장
                    db.session.flush()
                    
                    app.logger.info(f"기존 정산 #{existing_settlement.id}에 슬롯 #{slot.id} 추가됨")
                else:
                    # 새 정산 생성
                    new_settlement = Settlement(
                        user_id=slot.user_id,
                        admin_id=None,  # 총판 승인일 경우 admin_id는 None
                        settlement_type='shopping',
                        period_start=day_start,
                        period_end=day_end,
                        status='pending',
                        total_price=total_price,
                        admin_price=total_admin_price,
                        agency_price=total_price - total_admin_price,
                        notes=f"슬롯 승인 시 자동 생성된 정산 ({today} 생성)"
                    )
                    db.session.add(new_settlement)
                    db.session.flush()  # ID 생성
                    
                    # 정산 항목 추가
                    settlement_item = SettlementItem(
                        settlement_id=new_settlement.id,
                        shopping_slot_id=slot.id,
                        slot_price=slot.slot_price,
                        admin_price=slot.admin_price,
                        settlement_price=total_price
                    )
                    db.session.add(settlement_item)
                    
                    # 변경사항 저장
                    db.session.flush()
                    
                    app.logger.info(f"새 정산 #{new_settlement.id} 생성됨 (슬롯 #{slot.id})")
            
        else:
            slot = approval.place_slot
            slot.status = 'live'
            
            # 정산 자동 처리 - 슬롯당 100유입 리워드로 고정
            if slot.start_date and slot.end_date:
                # 30원 × 슬롯1개(100유입) × 기간으로 계산
                days = (slot.end_date - slot.start_date).days + 1
                daily_visitors = 100  # 일일 100유입
                unit_price = 30  # 고정 단가 (30원)
                total_price = days * daily_visitors * unit_price
                total_admin_price = 0  # 어드민 정산가 불필요
                
                # 기본 정보 로깅
                app.logger.info(f"자동 정산 처리 - 플레이스 슬롯 #{slot.id}: {days}일 × {unit_price}원 × {daily_visitors}유입 = {total_price}원")
                
                # 정산 자동 생성
                today = datetime.now().date()
                
                # 자동 정산 생성 (일별 정산)
                day_start = today
                day_end = today
                
                # 슬롯 정산 상태 먼저 업데이트
                slot.settlement_status = 'in_progress'
                
                # 기존 정산이 있는지 확인 (사용자, 정산 타입, 기간)
                existing_settlement = Settlement.query.filter(
                    Settlement.user_id == slot.user_id,
                    Settlement.settlement_type == 'place',
                    Settlement.period_start <= today,
                    Settlement.period_end >= today,
                    Settlement.status == 'pending'
                ).first()
                
                if existing_settlement:
                    # 기존 정산에 항목 추가
                    settlement_item = SettlementItem(
                        settlement_id=existing_settlement.id,
                        place_slot_id=slot.id,
                        slot_price=total_price,  # 계산된 총 가격
                        admin_price=slot.admin_price or 0,
                        settlement_price=total_price
                    )
                    db.session.add(settlement_item)
                    
                    # 정산 합계 업데이트
                    existing_settlement.total_price += total_price
                    existing_settlement.admin_price += total_admin_price
                    existing_settlement.agency_price = existing_settlement.total_price - existing_settlement.admin_price
                    
                    # 변경사항 저장
                    db.session.flush()
                    
                    app.logger.info(f"기존 정산 #{existing_settlement.id}에 슬롯 #{slot.id} 추가됨")
                else:
                    # 새 정산 생성
                    new_settlement = Settlement(
                        user_id=slot.user_id,
                        admin_id=None,  # 총판 승인일 경우 admin_id는 None
                        settlement_type='place',
                        period_start=day_start,
                        period_end=day_end,
                        status='pending',
                        total_price=total_price,
                        admin_price=total_admin_price,
                        agency_price=total_price - total_admin_price,
                        notes=f"슬롯 승인 시 자동 생성된 정산 ({today} 생성)"
                    )
                    db.session.add(new_settlement)
                    db.session.flush()  # ID 생성
                    
                    # 정산 항목 추가
                    settlement_item = SettlementItem(
                        settlement_id=new_settlement.id,
                        place_slot_id=slot.id,
                        slot_price=total_price,  # 계산된 총 가격
                        admin_price=slot.admin_price or 0,
                        settlement_price=total_price
                    )
                    db.session.add(settlement_item)
                    
                    # 변경사항 저장
                    db.session.flush()
                    
                    app.logger.info(f"새 정산 #{new_settlement.id} 생성됨 (슬롯 #{slot.id})")
            
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
    live_shopping_slots = current_user.shopping_slots.filter_by(status='live').count()
    
    pending_place_slots = current_user.place_slots.filter_by(status='pending').count()
    approved_place_slots = current_user.place_slots.filter_by(status='approved').count()
    rejected_place_slots = current_user.place_slots.filter_by(status='rejected').count()
    live_place_slots = current_user.place_slots.filter_by(status='live').count()
    
    # 슬롯 할당량 정보
    slot_quota = current_user.quota
    if not slot_quota:
        # 할당량 정보가 없으면 새로 생성
        slot_quota = SlotQuota(
            user_id=current_user.id,
            shopping_slots_limit=0,
            place_slots_limit=0,
            shopping_slots_used=0,
            place_slots_used=0
        )
        db.session.add(slot_quota)
        db.session.commit()
    
    # 슬롯 할당량 요청 정보
    quota_requests = SlotQuotaRequest.query.filter_by(requester_id=current_user.id).order_by(SlotQuotaRequest.requested_at.desc()).limit(5).all()
    pending_quota_requests = SlotQuotaRequest.query.filter_by(requester_id=current_user.id, status='pending').count()
    
    return render_template('agency/dashboard.html',
                          shopping_slots_count=shopping_slots_count,
                          place_slots_count=place_slots_count,
                          pending_shopping_slots=pending_shopping_slots,
                          approved_shopping_slots=approved_shopping_slots,
                          rejected_shopping_slots=rejected_shopping_slots,
                          live_shopping_slots=live_shopping_slots,
                          pending_place_slots=pending_place_slots,
                          approved_place_slots=approved_place_slots,
                          rejected_place_slots=rejected_place_slots,
                          live_place_slots=live_place_slots,
                          slot_quota=slot_quota,
                          quota_requests=quota_requests,
                          pending_quota_requests=pending_quota_requests)

@app.route('/agency/shopping-slots')
@login_required
def agency_shopping_slots():
    """대행사 쇼핑 슬롯 관리 페이지"""
    if not current_user.is_agency():
        abort(403)
    
    # 사용자의 슬롯 할당량 정보 가져오기
    slot_quota = current_user.quota
    if not slot_quota:
        # 할당량 정보가 없으면 새로 생성
        slot_quota = SlotQuota(
            user_id=current_user.id,
            shopping_slots_limit=0,
            place_slots_limit=0,
            shopping_slots_used=0,
            place_slots_used=0
        )
        db.session.add(slot_quota)
        db.session.commit()
    
    # 빈 슬롯과 일반 슬롯 구분해서 가져오기
    empty_slots = current_user.shopping_slots.filter_by(status='empty').order_by(ShoppingSlot.created_at.desc()).all()
    filled_slots = current_user.shopping_slots.filter(ShoppingSlot.status != 'empty').order_by(ShoppingSlot.created_at.desc()).all()
    
    # 새 슬롯을 추가할 수 있는지 확인
    can_add_slot = slot_quota.can_use_shopping_slot()
    
    return render_template('agency/shopping_slots.html', 
                          empty_slots=empty_slots,
                          shopping_slots=filled_slots, 
                          slot_quota=slot_quota,
                          can_add_slot=can_add_slot)

@app.route('/agency/place-slots')
@login_required
def agency_place_slots():
    """대행사 플레이스 슬롯 관리 페이지"""
    if not current_user.is_agency():
        abort(403)
    
    # 사용자의 슬롯 할당량 정보 가져오기
    slot_quota = current_user.quota
    if not slot_quota:
        # 할당량 정보가 없으면 새로 생성
        slot_quota = SlotQuota(
            user_id=current_user.id,
            shopping_slots_limit=0,
            place_slots_limit=0,
            shopping_slots_used=0,
            place_slots_used=0
        )
        db.session.add(slot_quota)
        db.session.commit()
    
    # 빈 슬롯과 일반 슬롯 구분해서 가져오기
    empty_slots = current_user.place_slots.filter_by(status='empty').order_by(PlaceSlot.created_at.desc()).all()
    filled_slots = current_user.place_slots.filter(PlaceSlot.status != 'empty').order_by(PlaceSlot.created_at.desc()).all()
    
    # 새 슬롯을 추가할 수 있는지 확인
    can_add_slot = slot_quota.can_use_place_slot()
    
    return render_template('agency/place_slots.html', 
                          empty_slots=empty_slots,
                          place_slots=filled_slots, 
                          slot_quota=slot_quota,
                          can_add_slot=can_add_slot)

# 쇼핑 슬롯 관련 라우트
@app.route('/shopping-slots/select/<int:slot_id>', methods=['POST'])
@login_required
@agency_required
def select_shopping_slot(slot_id):
    """쇼핑 슬롯 선택 상태 변경"""
    shopping_slot = ShoppingSlot.query.get_or_404(slot_id)
    
    # 슬롯 소유권 확인
    if shopping_slot.user_id != current_user.id:
        return jsonify({'success': False, 'message': '권한이 없습니다.'}), 403
    
    # 슬롯 상태 확인 (승인된 상태만 선택 가능)
    if shopping_slot.status != 'approved':
        return jsonify({'success': False, 'message': '승인된 슬롯만 선택할 수 있습니다.'}), 400
    
    # JSON 데이터 가져오기
    data = request.json
    is_selected = data.get('is_selected', False)
    
    # 선택 상태 변경
    shopping_slot.is_selected = is_selected
    db.session.commit()
    
    return jsonify({'success': True})


# 환불 요청 라우트
@app.route('/refund/shopping-slot/<int:slot_id>', methods=['GET', 'POST'])
@login_required
def request_shopping_slot_refund(slot_id):
    """쇼핑 슬롯 환불 요청"""
    # 슬롯 정보 가져오기
    slot = ShoppingSlot.query.get_or_404(slot_id)
    
    # 슬롯 소유자 또는 소유자의 총판만 접근 가능
    if slot.user_id != current_user.id and not (current_user.is_distributor() and slot.user.parent_id == current_user.id):
        flash('이 슬롯에 대한 환불 요청 권한이 없습니다.', 'danger')
        return redirect(url_for('dashboard'))
    
    # 라이브 상태인 슬롯만 환불 가능
    if slot.status != 'live':
        flash('라이브 상태인 슬롯만 환불 요청할 수 있습니다.', 'danger')
        return redirect(url_for('dashboard'))
    
    form = FlaskForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        # 요청 정보 가져오기
        refund_reason = request.form.get('refund_reason')
        
        # 환불 금액 계산
        today = datetime.now().date()
        start_date = slot.start_date or today
        end_date = slot.end_date or today
        
        # 전체 일수
        total_days = (end_date - start_date).days + 1
        
        # 남은 일수 계산 (오늘부터 종료일까지)
        remaining_days = (end_date - today).days + 1 if end_date >= today else 0
        
        # 환불 금액 계산 (일별 비례)
        refund_amount = 0
        if total_days > 0 and remaining_days > 0:
            refund_amount = int((slot.slot_price / total_days) * remaining_days)
        
        # 환불 요청 생성
        refund_request = SlotRefundRequest(
            requester_id=current_user.id,
            shopping_slot_id=slot.id,
            refund_reason=refund_reason,
            refund_amount=refund_amount,
            remaining_days=remaining_days,
            total_days=total_days,
            status='pending'
        )
        
        # 슬롯 상태 변경
        slot.status = 'refund_requested'
        
        db.session.add(refund_request)
        db.session.commit()
        
        flash('환불 요청이 등록되었습니다. 관리자 검토 후 처리됩니다.', 'success')
        
        # 요청자 타입에 따른 리다이렉트
        if current_user.is_distributor():
            return redirect(url_for('distributor_slots', type='shopping'))
        else:  # 대행사
            return redirect(url_for('agency_shopping_slots'))
    
    return render_template('refund/request_shopping_refund.html', form=form, slot=slot)


@app.route('/refund/place-slot/<int:slot_id>', methods=['GET', 'POST'])
@login_required
def request_place_slot_refund(slot_id):
    """플레이스 슬롯 환불 요청"""
    # 슬롯 정보 가져오기
    slot = PlaceSlot.query.get_or_404(slot_id)
    
    # 슬롯 소유자 또는 소유자의 총판만 접근 가능
    if slot.user_id != current_user.id and not (current_user.is_distributor() and slot.user.parent_id == current_user.id):
        flash('이 슬롯에 대한 환불 요청 권한이 없습니다.', 'danger')
        return redirect(url_for('dashboard'))
    
    # 라이브 상태인 슬롯만 환불 가능
    if slot.status != 'live':
        flash('라이브 상태인 슬롯만 환불 요청할 수 있습니다.', 'danger')
        return redirect(url_for('dashboard'))
    
    form = FlaskForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        # 요청 정보 가져오기
        refund_reason = request.form.get('refund_reason')
        
        # 환불 금액 계산
        today = datetime.now().date()
        start_date = slot.start_date or today
        end_date = slot.end_date or today
        
        # 전체 일수
        total_days = (end_date - start_date).days + 1
        
        # 남은 일수 계산 (오늘부터 종료일까지)
        remaining_days = (end_date - today).days + 1 if end_date >= today else 0
        
        # 환불 금액 계산 (일별 비례)
        refund_amount = 0
        if total_days > 0 and remaining_days > 0:
            refund_amount = int((slot.slot_price / total_days) * remaining_days)
        
        # 환불 요청 생성
        refund_request = SlotRefundRequest(
            requester_id=current_user.id,
            place_slot_id=slot.id,
            refund_reason=refund_reason,
            refund_amount=refund_amount,
            remaining_days=remaining_days,
            total_days=total_days,
            status='pending'
        )
        
        # 슬롯 상태 변경
        slot.status = 'refund_requested'
        
        db.session.add(refund_request)
        db.session.commit()
        
        flash('환불 요청이 등록되었습니다. 관리자 검토 후 처리됩니다.', 'success')
        
        # 요청자 타입에 따른 리다이렉트
        if current_user.is_distributor():
            return redirect(url_for('distributor_slots', type='place'))
        else:  # 대행사
            return redirect(url_for('agency_place_slots'))
    
    return render_template('refund/request_place_refund.html', form=form, slot=slot)


# 어드민 환불 관리
@app.route('/admin/refunds')
@admin_required
def admin_refunds():
    """관리자 환불 요청 관리 페이지"""
    # 대기 중인 환불 요청
    pending_refunds = SlotRefundRequest.query.filter_by(status='pending').all()
    
    # 처리된 환불 요청 (승인/거절)
    processed_refunds = SlotRefundRequest.query.filter(
        SlotRefundRequest.status.in_(['approved', 'rejected'])
    ).order_by(SlotRefundRequest.processed_at.desc()).limit(30).all()
    
    return render_template('admin/refunds.html', 
                         pending_refunds=pending_refunds, 
                         processed_refunds=processed_refunds)


@app.route('/admin/approve-refund/<int:refund_id>/<action>')
@admin_required
def admin_approve_refund(refund_id, action):
    """관리자의 환불 요청 승인/거절 처리"""
    # 환불 요청 정보 가져오기
    refund = SlotRefundRequest.query.get_or_404(refund_id)
    
    # 이미 처리된 요청인지 확인
    if refund.status != 'pending':
        flash('이미 처리된 환불 요청입니다.', 'warning')
        return redirect(url_for('admin_refunds'))
    
    # 슬롯 정보 가져오기
    slot = refund.slot
    
    if action == 'approve':
        # 환불 승인 처리
        refund.status = 'approved'
        refund.approver_id = current_user.id
        refund.processed_at = datetime.utcnow()
        
        # 슬롯 상태 변경
        slot.status = 'refunded'
        
        # 정산 처리 (환불금액을 정산 입력으로 추가)
        # 환불 자동 생성 (이번 달 기준)
        today = datetime.now().date()
        month_start = today.replace(day=1)
        if today.month == 12:
            next_month = today.replace(year=today.year + 1, month=1, day=1)
        else:
            next_month = today.replace(month=today.month + 1, day=1)
        month_end = next_month - timedelta(days=1)
        
        # 환불 정산 생성
        refund_settlement = Settlement(
            user_id=slot.user_id,
            admin_id=current_user.id,
            settlement_type='refund',
            period_start=month_start,
            period_end=month_end,
            status='pending',
            notes=f"환불 요청 승인 ({today} 생성)"
        )
        db.session.add(refund_settlement)
        db.session.flush()  # ID 생성
        
        # 환불 정산 항목 추가
        if refund.shopping_slot_id:
            settlement_item = SettlementItem(
                settlement_id=refund_settlement.id,
                shopping_slot_id=refund.shopping_slot_id,
                slot_price=slot.slot_price,
                admin_price=slot.admin_price,
                settlement_price=-refund.refund_amount,  # 음수로 저장 (환불)
                is_refund=True,
                refund_amount=refund.refund_amount
            )
        else:
            settlement_item = SettlementItem(
                settlement_id=refund_settlement.id,
                place_slot_id=refund.place_slot_id,
                slot_price=slot.slot_price,
                admin_price=slot.admin_price,
                settlement_price=-refund.refund_amount,  # 음수로 저장 (환불)
                is_refund=True,
                refund_amount=refund.refund_amount
            )
        
        db.session.add(settlement_item)
        
        # 환불 요청과 정산 연결
        refund.settlement_id = refund_settlement.id
        
        # 정산 금액 업데이트
        refund_settlement.total_price = -refund.refund_amount
        
        # 어드민/에이전시 비율에 따른 가격 분배
        if slot.admin_price:
            admin_ratio = slot.admin_price / slot.slot_price
            refund_settlement.admin_price = -int(refund.refund_amount * admin_ratio)
            refund_settlement.agency_price = -int(refund.refund_amount * (1 - admin_ratio))
        else:
            refund_settlement.admin_price = 0
            refund_settlement.agency_price = -refund.refund_amount
        
        flash(f'환불 요청이 승인되었습니다. 환불 금액: {refund.refund_amount:,}원', 'success')
    
    elif action == 'reject':
        # 환불 거절 처리
        refund.status = 'rejected'
        refund.approver_id = current_user.id
        refund.processed_at = datetime.utcnow()
        
        # 슬롯 상태 원복
        slot.status = 'live'
        
        flash('환불 요청이 거절되었습니다.', 'success')
    
    db.session.commit()
    return redirect(url_for('admin_refunds'))

@app.route('/shopping-slots/edit/<int:slot_id>', methods=['POST'])
@login_required
def edit_shopping_slot(slot_id):
    """쇼핑 슬롯 수정 (총판/대행사 공통)"""
    shopping_slot = ShoppingSlot.query.get_or_404(slot_id)
    
    # 권한 검사: 슬롯 소유자이거나 소유자의 총판인 경우만 접근 가능
    if not (shopping_slot.user_id == current_user.id or 
            (current_user.is_distributor() and shopping_slot.user.parent_id == current_user.id)):
        flash('권한이 없습니다.', 'danger')
        if current_user.is_distributor():
            return redirect(url_for('distributor_slots', type='shopping'))
        else:
            return redirect(url_for('agency_shopping_slots'))
    
    try:
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
        impressions = request.form.get('impressions')
        clicks = request.form.get('clicks')
        amount = request.form.get('amount')
        product_image_url = request.form.get('product_image_url')
        notes = request.form.get('notes')
        
        # 날짜 처리
        start_date = request.form.get('start_date')
        if start_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        
        end_date = request.form.get('end_date')
        if end_date:
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        
        bid_type = request.form.get('bid_type')
        targeting = request.form.get('targeting')
        
        # 슬롯 정보 업데이트
        shopping_slot.slot_name = slot_name
        shopping_slot.store_type = store_type
        shopping_slot.product_id = product_id
        shopping_slot.shopping_campaign_id = shopping_campaign_id
        shopping_slot.product_name = product_name
        shopping_slot.keywords = keywords
        shopping_slot.store_name = store_name
        shopping_slot.price = price if price else None
        shopping_slot.sale_price = sale_price if sale_price else None
        shopping_slot.start_date = start_date
        shopping_slot.end_date = end_date
        shopping_slot.bid_type = bid_type
        shopping_slot.targeting = targeting
        shopping_slot.impressions = impressions
        shopping_slot.clicks = clicks
        shopping_slot.amount = amount
        shopping_slot.product_image_url = product_image_url
        shopping_slot.notes = notes
        
        # 상태 업데이트 (pending으로 변경)
        # 총판이 자신의 슬롯을 수정하는 경우에는 바로 approved로 변경
        if current_user.is_distributor() and shopping_slot.user_id == current_user.id:
            shopping_slot.status = 'approved'
            flash('쇼핑 슬롯 정보가 수정되었습니다.', 'success')
        elif shopping_slot.status == 'empty':
            shopping_slot.status = 'pending'  # 빈 슬롯 -> 승인 대기
            
            # 승인 요청 생성
            approval = SlotApproval(
                requester_id=current_user.id,
                shopping_slot_id=shopping_slot.id,
                approval_type='create'
            )
            
            db.session.add(approval)
            flash('빈 슬롯 정보가 등록되었고, 승인 요청이 제출되었습니다.', 'success')
        elif shopping_slot.status == 'approved' and current_user.is_agency():
            shopping_slot.status = 'pending'  # 승인됨 -> 변경사항 대기
            
            # 승인 요청 생성
            approval = SlotApproval(
                requester_id=current_user.id,
                shopping_slot_id=shopping_slot.id,
                approval_type='update'
            )
            
            db.session.add(approval)
            flash('쇼핑 슬롯 정보가 수정되었고, 변경사항에 대한 승인 요청이 제출되었습니다.', 'success')
        else:
            flash('쇼핑 슬롯 정보가 수정되었습니다.', 'success')
            
        # 수정 내용 저장
        db.session.commit()
        
        # 리디렉션 처리
        if current_user.is_distributor():
            return redirect(url_for('distributor_slots', type='shopping'))
        else:
            return redirect(url_for('agency_shopping_slots'))
            
    except Exception as e:
        db.session.rollback()
        flash(f'슬롯 수정 중 오류가 발생했습니다: {str(e)}', 'danger')
        
        if current_user.is_distributor():
            return redirect(url_for('distributor_slots', type='shopping'))
        else:
            return redirect(url_for('agency_shopping_slots'))
    
    # 이 코드는 접근되지 않습니다(위에서 이미 리턴됨)
    # return redirect(url_for('agency_shopping_slots'))

@app.route('/shopping-slots/delete/<int:slot_id>')
@login_required
@agency_required
def delete_shopping_slot(slot_id):
    """쇼핑 슬롯 삭제"""
    shopping_slot = ShoppingSlot.query.get_or_404(slot_id)
    
    # 슬롯 소유권 확인
    if shopping_slot.user_id != current_user.id:
        flash('권한이 없습니다.', 'danger')
        return redirect(url_for('agency_shopping_slots'))
    
    # 슬롯이 정산에 포함된 경우 삭제 불가
    if SettlementItem.query.filter_by(shopping_slot_id=slot_id).first():
        flash('이 슬롯은 정산 항목에 포함되어 있어 삭제할 수 없습니다.', 'danger')
        return redirect(url_for('agency_shopping_slots'))
    
    # 승인된 슬롯인 경우 삭제 요청
    if shopping_slot.status == 'approved':
        # 승인 요청 생성
        approval = SlotApproval(
            requester_id=current_user.id,
            shopping_slot_id=shopping_slot.id,
            approval_type='delete'
        )
        
        db.session.add(approval)
        db.session.commit()
        
        flash('슬롯 삭제 요청이 제출되었습니다. 승인 후 삭제가 완료됩니다.', 'success')
    else:
        # 관련 승인 요청 삭제
        SlotApproval.query.filter_by(shopping_slot_id=slot_id).delete()
        
        # 슬롯 삭제
        db.session.delete(shopping_slot)
        db.session.commit()
        
        # 할당량 업데이트
        slot_quota = current_user.quota
        if slot_quota and slot_quota.shopping_slots_used > 0:
            slot_quota.shopping_slots_used -= 1
            db.session.commit()
        
        flash('쇼핑 슬롯이 삭제되었습니다.', 'success')
    
    return redirect(url_for('agency_shopping_slots'))

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
        product_name = request.form.get('product_name')
        keywords = request.form.get('keywords')
        price = request.form.get('price')
        sale_price = request.form.get('sale_price')
        bid_type = request.form.get('bid_type')
        slot_price = request.form.get('slot_price')
        notes = request.form.get('notes')
        
        # 날짜 처리
        start_date = request.form.get('start_date')
        if start_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        
        end_date = request.form.get('end_date')
        if end_date:
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        
        # 할당량 확인
        if not current_user.quota or not current_user.quota.can_use_shopping_slot():
            flash('사용 가능한 쇼핑 슬롯 할당량이 없습니다. 총판에게 추가 할당량을 요청하세요.', 'danger')
            return redirect(url_for('agency_shopping_slots'))
        
        # 슬롯 생성
        shopping_slot = ShoppingSlot(
            user_id=current_user.id,
            slot_name=slot_name,
            store_type=store_type,
            product_id=product_id,
            product_name=product_name,
            keywords=keywords,
            price=price if price else None,
            sale_price=sale_price if sale_price else None,
            start_date=start_date,
            end_date=end_date,
            bid_type=bid_type,
            slot_price=slot_price if slot_price else None,
            notes=notes,
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
        
        # 사용된 슬롯 카운트 증가
        if current_user.quota:
            current_user.quota.shopping_slots_used += 1
        
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

# 슬롯 할당량 요청 관련 라우트
@app.route('/request-slot-quota', methods=['GET', 'POST'])
@login_required
def request_slot_quota():
    """사용자(어드민, 총판, 대행사)의 슬롯 할당량 요청 페이지"""
    # 사용자 역할에 따른 리다이렉트 URL과 대시보드 설정
    if current_user.is_admin():
        dashboard_url = url_for('admin_dashboard')
        approver_id = None  # 어드민은 자체 승인으로 처리
    elif current_user.is_distributor():
        dashboard_url = url_for('distributor_dashboard')
        approver_id = None  # 총판은 자체 승인으로 처리
    elif current_user.is_agency():
        dashboard_url = url_for('agency_dashboard')
        # 대행사는 소속 총판에게 요청
        if not current_user.parent_id:
            flash('소속된 총판이 없어 슬롯 할당량을 요청할 수 없습니다.', 'danger')
            return redirect(dashboard_url)
        approver_id = current_user.parent_id
    else:
        flash('슬롯 할당량을 요청할 권한이 없습니다.', 'danger')
        return redirect(url_for('index'))
    
    # 폼 생성 (CSRF 토큰 포함)
    class SlotQuotaRequestForm(FlaskForm):
        pass  # CSRF 토큰만 필요
    
    form = SlotQuotaRequestForm()
    
    if request.method == 'POST':
        # 폼 데이터 처리
        shopping_slots_requested = request.form.get('shopping_slots_requested', 0)
        place_slots_requested = request.form.get('place_slots_requested', 0)
        shopping_slot_type = request.form.get('shopping_slot_type')
        place_slot_type = request.form.get('place_slot_type')
        shopping_slot_price = request.form.get('shopping_slot_price', 0)
        place_slot_price = request.form.get('place_slot_price', 0)
        
        # 날짜 처리
        start_date = request.form.get('start_date')
        if start_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        
        end_date = request.form.get('end_date')
        if end_date:
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        
        request_reason = request.form.get('request_reason')
        
        # 요청 슬롯 수 확인
        shopping_slots_requested = int(shopping_slots_requested) if shopping_slots_requested else 0
        place_slots_requested = int(place_slots_requested) if place_slots_requested else 0
        shopping_slot_price = int(shopping_slot_price) if shopping_slot_price else 0
        place_slot_price = int(place_slot_price) if place_slot_price else 0
        
        if shopping_slots_requested <= 0 and place_slots_requested <= 0:
            flash('최소 1개 이상의 슬롯을 요청해야 합니다.', 'danger')
            return redirect(url_for('request_slot_quota'))
        
        # 가격 검증
        if shopping_slots_requested > 0 and shopping_slot_price <= 0:
            flash('쇼핑 슬롯 단가를 입력해주세요.', 'danger')
            return redirect(url_for('request_slot_quota'))
            
        if place_slots_requested > 0 and place_slot_price <= 0:
            flash('플레이스 슬롯 단가를 입력해주세요.', 'danger')
            return redirect(url_for('request_slot_quota'))
        
        # 날짜 검증
        if start_date and end_date and end_date <= start_date:
            flash('종료일은 시작일 이후여야 합니다.', 'danger')
            return redirect(url_for('request_slot_quota'))
        
        # 사용자 역할에 따른 처리
        if current_user.is_admin() or current_user.is_distributor():
            # 어드민이나 총판은 자체 승인 처리 (즉시 슬롯 할당)
            status = 'approved'
            processed_at = datetime.utcnow()
            
            # 슬롯 할당량 확인 및 생성
            quota = current_user.quota
            if not quota:
                quota = SlotQuota(
                    user_id=current_user.id,
                    shopping_slots_limit=0,
                    place_slots_limit=0,
                    shopping_slots_used=0,
                    place_slots_used=0
                )
                db.session.add(quota)
            
            # 슬롯 할당량 업데이트
            if shopping_slots_requested > 0:
                quota.shopping_slots_limit += shopping_slots_requested
            if place_slots_requested > 0:
                quota.place_slots_limit += place_slots_requested
            
            # 요청 생성 (기록용)
            quota_request = SlotQuotaRequest(
                requester_id=current_user.id,
                approver_id=current_user.id,  # 자체 승인
                shopping_slots_requested=shopping_slots_requested,
                place_slots_requested=place_slots_requested,
                shopping_slot_type=shopping_slot_type if shopping_slots_requested > 0 else None,
                place_slot_type=place_slot_type if place_slots_requested > 0 else None,
                shopping_slot_price=shopping_slot_price if shopping_slots_requested > 0 else None,
                place_slot_price=place_slot_price if place_slots_requested > 0 else None,
                start_date=start_date,
                end_date=end_date,
                request_reason=request_reason,
                status=status,
                processed_at=processed_at,
                response_comment="자체 승인 처리"
            )
            
            db.session.add(quota_request)
            db.session.commit()
            
            flash('슬롯 할당량이 성공적으로 추가되었습니다.', 'success')
            return redirect(dashboard_url)
            
        elif current_user.is_agency():
            # 대행사의 경우 소속 총판에게 요청
            if not current_user.parent_id:
                flash('소속된 총판이 없어 슬롯 할당량을 요청할 수 없습니다.', 'danger')
                return redirect(dashboard_url)
            
            # 총판 정보 가져오기
            distributor = User.query.get(current_user.parent_id)
            if not distributor:
                flash('소속 총판 정보를 찾을 수 없습니다.', 'danger')
                return redirect(dashboard_url)
            
            # 요청 생성
            quota_request = SlotQuotaRequest(
                requester_id=current_user.id,
                approver_id=distributor.id,  # 승인자는 소속 총판
                shopping_slots_requested=shopping_slots_requested,
                place_slots_requested=place_slots_requested,
                shopping_slot_type=shopping_slot_type if shopping_slots_requested > 0 else None,
                place_slot_type=place_slot_type if place_slots_requested > 0 else None,
                shopping_slot_price=shopping_slot_price if shopping_slots_requested > 0 else None,
                place_slot_price=place_slot_price if place_slots_requested > 0 else None,
                start_date=start_date,
                end_date=end_date,
                request_reason=request_reason,
                status='pending'
            )
            
            db.session.add(quota_request)
            db.session.commit()
            
            flash('슬롯 할당량 요청이 성공적으로 제출되었습니다. 총판의 승인을 기다려주세요.', 'success')
            return redirect(dashboard_url)
        
        # 그 외의 경우 (비정상 접근)
        flash('슬롯 할당량을 요청할 권한이 없습니다.', 'danger')
        return redirect(url_for('index'))
    
    return render_template('request_slot_quota.html', form=form)

# 플레이스 슬롯 관련 라우트
@app.route('/place-slots/edit/<int:slot_id>', methods=['POST'])
@login_required
@agency_required
def edit_place_slot(slot_id):
    """플레이스 슬롯 수정"""
    place_slot = PlaceSlot.query.get_or_404(slot_id)
    
    # 슬롯 소유권 확인
    if place_slot.user_id != current_user.id:
        flash('권한이 없습니다.', 'danger')
        return redirect(url_for('agency_place_slots'))
    
    # 폼 데이터 처리
    slot_name = request.form.get('slot_name')
    place_id = request.form.get('place_id')
    business_category = request.form.get('business_category')
    business_type = request.form.get('business_type')
    place_name = request.form.get('place_name')
    address = request.form.get('address')
    operation_status = request.form.get('operation_status')
    status_reason = request.form.get('status_reason')
    
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
    
    # 슬롯 정보 업데이트
    place_slot.slot_name = slot_name
    place_slot.place_id = place_id
    place_slot.business_category = business_category
    place_slot.business_type = business_type
    place_slot.place_name = place_name
    place_slot.address = address
    place_slot.operation_status = operation_status
    place_slot.status_reason = status_reason
    place_slot.start_date = start_date
    place_slot.end_date = end_date
    place_slot.deadline_date = deadline_date
    
    # 빈 슬롯인 경우 승인 요청 상태로 변경
    if place_slot.status == 'empty':
        place_slot.status = 'pending'
        
        # 승인 요청 생성
        approval = SlotApproval(
            requester_id=current_user.id,
            place_slot_id=place_slot.id,
            approval_type='create'
        )
        
        db.session.add(approval)
        flash('빈 슬롯 정보가 등록되었고, 승인 요청이 제출되었습니다.', 'success')
    # 이미 승인된 슬롯인 경우 업데이트 요청 생성
    elif place_slot.status == 'approved':
        # 승인 요청 생성
        approval = SlotApproval(
            requester_id=current_user.id,
            place_slot_id=place_slot.id,
            approval_type='update'
        )
        
        db.session.add(approval)
        flash('플레이스 슬롯 정보가 수정되었고, 변경사항에 대한 승인 요청이 제출되었습니다.', 'success')
    else:
        flash('플레이스 슬롯 정보가 수정되었습니다.', 'success')
    
    # 수정 내용 저장
    db.session.commit()
    
    return redirect(url_for('agency_place_slots'))

@app.route('/place-slots/delete/<int:slot_id>')
@login_required
@agency_required
def delete_place_slot(slot_id):
    """플레이스 슬롯 삭제"""
    place_slot = PlaceSlot.query.get_or_404(slot_id)
    
    # 슬롯 소유권 확인
    if place_slot.user_id != current_user.id:
        flash('권한이 없습니다.', 'danger')
        return redirect(url_for('agency_place_slots'))
    
    # 슬롯이 정산에 포함된 경우 삭제 불가
    if SettlementItem.query.filter_by(place_slot_id=slot_id).first():
        flash('이 슬롯은 정산 항목에 포함되어 있어 삭제할 수 없습니다.', 'danger')
        return redirect(url_for('agency_place_slots'))
    
    # 승인된 슬롯인 경우 삭제 요청
    if place_slot.status == 'approved':
        # 승인 요청 생성
        approval = SlotApproval(
            requester_id=current_user.id,
            place_slot_id=place_slot.id,
            approval_type='delete'
        )
        
        db.session.add(approval)
        db.session.commit()
        
        flash('슬롯 삭제 요청이 제출되었습니다. 승인 후 삭제가 완료됩니다.', 'success')
    else:
        # 관련 승인 요청 삭제
        SlotApproval.query.filter_by(place_slot_id=slot_id).delete()
        
        # 슬롯 삭제
        db.session.delete(place_slot)
        db.session.commit()
        
        # 할당량 업데이트
        slot_quota = current_user.quota
        if slot_quota and slot_quota.place_slots_used > 0:
            slot_quota.place_slots_used -= 1
            db.session.commit()
        
        flash('플레이스 슬롯이 삭제되었습니다.', 'success')
    
    return redirect(url_for('agency_place_slots'))

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
        slot_type = request.form.get('slot_type', 'search')  # search 또는 save
        slot_price = request.form.get('slot_price')
        notes = request.form.get('notes')
        
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
        
        # 할당량 확인
        if not current_user.quota or not current_user.quota.can_use_place_slot():
            flash('사용 가능한 플레이스 슬롯 할당량이 없습니다. 총판에게 추가 할당량을 요청하세요.', 'danger')
            return redirect(url_for('agency_place_slots'))
        
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
            slot_type=slot_type,
            slot_price=slot_price if slot_price else None,
            notes=notes,
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
        
        # 사용된 슬롯 카운트 증가
        if current_user.quota:
            current_user.quota.place_slots_used += 1
            
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

# 슬롯 인라인 편집 및 일괄 저장 API 엔드포인트
@app.route('/api/save-slot', methods=['POST'])
@login_required
def save_slot_api():
    """슬롯 단일 저장 API"""
    try:
        data = request.json
        slot_id = data.get('id')
        fields = data.get('fields', {})
        
        # 쇼핑 슬롯 가져오기
        shopping_slot = ShoppingSlot.query.get_or_404(slot_id)
        
        # 슬롯 소유권 확인
        if shopping_slot.user_id != current_user.id and not current_user.is_admin():
            return jsonify({
                'success': False,
                'message': '권한이 없습니다.'
            }), 403
        
        # 각 필드 업데이트
        for field, value in fields.items():
            if hasattr(shopping_slot, field):
                # 날짜 필드 처리
                if field in ['start_date', 'end_date'] and value:
                    setattr(shopping_slot, field, datetime.strptime(value, '%Y-%m-%d').date())
                # 숫자 필드 처리
                elif field == 'slot_price':
                    # 슬롯 가격은 0-1000원 범위로 제한
                    price = int(value) if value else 0
                    setattr(shopping_slot, field, min(max(price, 0), 1000))
                # 기타 일반 필드
                else:
                    setattr(shopping_slot, field, value)
        
        # 승인 상태 처리
        # 총판이 자신의 슬롯을 수정하는 경우에는 바로 approved로 변경
        if current_user.is_distributor() and shopping_slot.user_id == current_user.id:
            shopping_slot.status = 'approved'
        elif shopping_slot.status == 'empty':
            shopping_slot.status = 'pending'  # 빈 슬롯 -> 승인 대기
            
            # 승인 요청 생성
            approval = SlotApproval(
                requester_id=current_user.id,
                shopping_slot_id=shopping_slot.id,
                approval_type='create'
            )
            
            db.session.add(approval)
        elif shopping_slot.status == 'approved' and current_user.is_agency():
            shopping_slot.status = 'pending'  # 승인됨 -> 변경사항 대기
            
            # 승인 요청 생성
            approval = SlotApproval(
                requester_id=current_user.id,
                shopping_slot_id=shopping_slot.id,
                approval_type='update'
            )
            
            db.session.add(approval)
        
        # 데이터베이스에 변경사항 저장
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '슬롯이 성공적으로 저장되었습니다.'
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving slot: {e}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/save-slots-bulk', methods=['POST'])
@login_required
def save_slots_bulk_api():
    """슬롯 일괄 저장 API"""
    try:
        data = request.json
        slots_data = data.get('slots', [])
        
        success_count = 0
        error_messages = []
        
        for slot_data in slots_data:
            try:
                slot_id = slot_data.get('id')
                fields = slot_data.get('fields', {})
                
                # 쇼핑 슬롯 가져오기
                shopping_slot = ShoppingSlot.query.get(slot_id)
                if not shopping_slot:
                    error_messages.append(f"슬롯 ID {slot_id}을 찾을 수 없습니다.")
                    continue
                
                # 슬롯 소유권 확인
                if shopping_slot.user_id != current_user.id and not current_user.is_admin():
                    error_messages.append(f"슬롯 ID {slot_id}에 대한 권한이 없습니다.")
                    continue
                
                # 각 필드 업데이트
                for field, value in fields.items():
                    if hasattr(shopping_slot, field):
                        # 날짜 필드 처리
                        if field in ['start_date', 'end_date'] and value:
                            setattr(shopping_slot, field, datetime.strptime(value, '%Y-%m-%d').date())
                        # 숫자 필드 처리
                        elif field == 'slot_price':
                            # 슬롯 가격은 0-1000원 범위로 제한
                            price = int(value) if value else 0
                            setattr(shopping_slot, field, min(max(price, 0), 1000))
                        # 기타 일반 필드
                        else:
                            setattr(shopping_slot, field, value)
                
                # 승인 상태 처리
                # 총판이 자신의 슬롯을 수정하는 경우에는 바로 approved로 변경
                if current_user.is_distributor() and shopping_slot.user_id == current_user.id:
                    shopping_slot.status = 'approved'
                elif shopping_slot.status == 'empty':
                    shopping_slot.status = 'pending'  # 빈 슬롯 -> 승인 대기
                    
                    # 승인 요청 생성
                    approval = SlotApproval(
                        requester_id=current_user.id,
                        shopping_slot_id=shopping_slot.id,
                        approval_type='create'
                    )
                    
                    db.session.add(approval)
                elif shopping_slot.status == 'approved' and current_user.is_agency():
                    shopping_slot.status = 'pending'  # 승인됨 -> 변경사항 대기
                    
                    # 승인 요청 생성
                    approval = SlotApproval(
                        requester_id=current_user.id,
                        shopping_slot_id=shopping_slot.id,
                        approval_type='update'
                    )
                    
                    db.session.add(approval)
                
                success_count += 1
            except Exception as e:
                error_messages.append(f"슬롯 ID {slot_id} 처리 중 오류: {str(e)}")
                logger.error(f"Error processing slot {slot_id}: {e}")
        
        # 데이터베이스에 변경사항 저장
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'{success_count}개의 슬롯이 성공적으로 저장되었습니다.',
            'errors': error_messages if error_messages else None
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error bulk saving slots: {e}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/toggle-slot', methods=['POST'])
@login_required
def toggle_slot_api():
    """슬롯 활성화/비활성화 토글 API"""
    try:
        data = request.json
        slot_id = data.get('slot_id')
        is_active = data.get('is_active', False)
        
        # 쇼핑 슬롯 가져오기
        shopping_slot = ShoppingSlot.query.get_or_404(slot_id)
        
        # 슬롯 소유권 확인
        if shopping_slot.user_id != current_user.id and not current_user.is_admin():
            return jsonify({
                'success': False,
                'message': '권한이 없습니다.'
            }), 403
        
        # 슬롯 상태가 approved인 경우에만 토글 가능
        if shopping_slot.status not in ['approved', 'live']:
            return jsonify({
                'success': False,
                'message': '승인된 슬롯만 활성화/비활성화할 수 있습니다.'
            }), 400
        
        # 상태 토글
        shopping_slot.status = 'live' if is_active else 'approved'
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '슬롯 상태가 변경되었습니다.'
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error toggling slot: {e}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

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

# 정산 관련 페이지

@app.route('/admin/settlements')
@login_required
@admin_required
def admin_settlements():
    """관리자 정산 관리 페이지"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    pagination = Settlement.query.options(
        joinedload(Settlement.user).joinedload(User.role),
        joinedload(Settlement.admin)
    ).order_by(Settlement.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    settlements = pagination.items
    pending_settlements = Settlement.query.filter_by(status='pending').count()
    
    return render_template('admin/settlements.html', 
                          settlements=settlements,
                          pagination=pagination,
                          pending_settlements=pending_settlements)


@app.route('/admin/create_settlement', methods=['GET', 'POST'])
@login_required
@admin_required
def create_settlement():
    """관리자 정산 생성 페이지"""
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        settlement_type = request.form.get('settlement_type')
        
        # 날짜 파싱
        period_start_str = request.form.get('period_start')
        period_end_str = request.form.get('period_end')
        
        if not period_start_str or not period_end_str:
            flash('정산 기간을 입력해주세요.', 'danger')
            return redirect(url_for('create_settlement'))
        
        period_start = datetime.strptime(period_start_str, '%Y-%m-%d').date()
        period_end = datetime.strptime(period_end_str, '%Y-%m-%d').date()
        notes = request.form.get('notes')
        
        # 정산 생성
        settlement = Settlement(
            user_id=user_id,
            admin_id=current_user.id,
            settlement_type=settlement_type,
            period_start=period_start,
            period_end=period_end,
            status='pending',
            notes=notes
        )
        db.session.add(settlement)
        db.session.commit()  # ID를 생성하기 위해 먼저 커밋
        
        # 정산 항목 추가
        if settlement_type == 'shopping':
            slots = ShoppingSlot.query.filter(
                ShoppingSlot.user_id == user_id,
                ShoppingSlot.settlement_status == 'pending',
                ShoppingSlot.status == 'live',  # 라이브 상태인 슬롯만 정산
                ShoppingSlot.start_date >= period_start,
                ShoppingSlot.end_date <= period_end
            ).all()
            
            total_price = 0
            admin_price = 0
            
            for slot in slots:
                # 라이브 기간에 따른 정산 금액 계산
                today = datetime.now().date()
                start_date = slot.start_date or today
                end_date = slot.end_date or today
                
                # 라이브 시작일은 start_date와 period_start 중 더 늦은 날짜
                effective_start = max(start_date, period_start)
                # 라이브 종료일은 end_date와 period_end 중 더 이른 날짜, 오늘보다 늦을 수 없음
                effective_end = min(end_date, period_end, today)
                
                # 라이브 일수 계산 (양 끝 날짜 포함)
                live_days = (effective_end - effective_start).days + 1
                total_days = (end_date - start_date).days + 1
                
                # 일별 슬롯 단가 계산
                daily_price = (slot.slot_price or 0) / total_days if total_days > 0 else 0
                daily_admin_price = (slot.admin_price or 0) / total_days if total_days > 0 else 0
                
                # 라이브 기간에 따른 정산 금액 계산
                slot_settlement_price = int(daily_price * live_days)
                slot_admin_settlement_price = int(daily_admin_price * live_days)
                
                settlement_item = SettlementItem(
                    settlement_id=settlement.id,
                    shopping_slot_id=slot.id,
                    slot_price=slot.slot_price or 0,
                    admin_price=slot.admin_price or 0,
                    settlement_price=slot_settlement_price
                )
                db.session.add(settlement_item)
                
                # 슬롯 정산 상태 업데이트
                slot.settlement_status = 'in_progress'
                
                # 합계 계산
                total_price += slot_settlement_price
                admin_price += slot_admin_settlement_price
                
            settlement.total_price = total_price
            settlement.admin_price = admin_price
            settlement.agency_price = total_price - admin_price
            
        elif settlement_type == 'place':
            slots = PlaceSlot.query.filter(
                PlaceSlot.user_id == user_id,
                PlaceSlot.settlement_status == 'pending',
                PlaceSlot.status == 'live',  # 라이브 상태인 슬롯만 정산
                PlaceSlot.start_date >= period_start,
                PlaceSlot.end_date <= period_end
            ).all()
            
            total_price = 0
            admin_price = 0
            
            for slot in slots:
                # 라이브 기간에 따른 정산 금액 계산
                today = datetime.now().date()
                start_date = slot.start_date or today
                end_date = slot.end_date or today
                
                # 라이브 시작일은 start_date와 period_start 중 더 늦은 날짜
                effective_start = max(start_date, period_start)
                # 라이브 종료일은 end_date와 period_end 중 더 이른 날짜, 오늘보다 늦을 수 없음
                effective_end = min(end_date, period_end, today)
                
                # 라이브 일수 계산 (양 끝 날짜 포함)
                live_days = (effective_end - effective_start).days + 1
                total_days = (end_date - start_date).days + 1
                
                # 일별 슬롯 단가 계산
                daily_price = (slot.slot_price or 0) / total_days if total_days > 0 else 0
                daily_admin_price = (slot.admin_price or 0) / total_days if total_days > 0 else 0
                
                # 라이브 기간에 따른 정산 금액 계산
                slot_settlement_price = int(daily_price * live_days)
                slot_admin_settlement_price = int(daily_admin_price * live_days)
                
                settlement_item = SettlementItem(
                    settlement_id=settlement.id,
                    place_slot_id=slot.id,
                    slot_price=slot.slot_price or 0,
                    admin_price=slot.admin_price or 0,
                    settlement_price=slot_settlement_price
                )
                db.session.add(settlement_item)
                
                # 슬롯 정산 상태 업데이트
                slot.settlement_status = 'in_progress'
                
                # 합계 계산
                total_price += slot_settlement_price
                admin_price += slot_admin_settlement_price
                
            settlement.total_price = total_price
            settlement.admin_price = admin_price
            settlement.agency_price = total_price - admin_price
            
        db.session.commit()
        flash('정산이 생성되었습니다.', 'success')
        return redirect(url_for('admin_settlements'))
        
    # GET 요청 처리
    distributors = User.query.filter(User.role_id == 2).all()  # 총판 목록
    agencies = User.query.filter(User.role_id == 3).all()      # 대행사 목록
    
    return render_template('admin/create_settlement.html',
                          distributors=distributors,
                          agencies=agencies)


@app.route('/admin/settlement/<int:settlement_id>')
@login_required
@admin_required
def admin_settlement_detail(settlement_id):
    """관리자 정산 상세 페이지"""
    settlement = Settlement.query.options(
        joinedload(Settlement.user),
        joinedload(Settlement.admin)
    ).get_or_404(settlement_id)
    
    # 정산 항목 조회 (처리된 데이터 준비) - eager loading으로 N+1 쿼리 방지
    processed_items = []
    
    # 쇼핑 슬롯 정산 항목 (shopping_slot eager load)
    shopping_items = SettlementItem.query.options(
        joinedload(SettlementItem.shopping_slot)
    ).filter_by(settlement_id=settlement_id).filter(SettlementItem.shopping_slot_id != None).all()
    for item in shopping_items:
        slot = item.shopping_slot
        if slot:
            # 데이터를 딕셔너리로 구성
            processed_item = {
                'id': item.id,
                'settlement_id': item.settlement_id,
                'slot_id': item.shopping_slot_id,
                'slot_name': slot.slot_name,
                'slot_type': 'shopping',
                'slot_subtype': slot.slot_type,
                'start_date': slot.start_date,
                'end_date': slot.end_date,
                'slot_price': item.slot_price,
                'admin_price': item.admin_price,
                'settlement_price': item.settlement_price,
                'is_refund': getattr(item, 'is_refund', False),
                'refund_amount': getattr(item, 'refund_amount', 0)
            }
            processed_items.append(processed_item)
    
    # 플레이스 슬롯 정산 항목 (place_slot eager load)
    place_items = SettlementItem.query.options(
        joinedload(SettlementItem.place_slot)
    ).filter_by(settlement_id=settlement_id).filter(SettlementItem.place_slot_id != None).all()
    for item in place_items:
        slot = item.place_slot
        if slot:
            # 데이터를 딕셔너리로 구성
            processed_item = {
                'id': item.id,
                'settlement_id': item.settlement_id,
                'slot_id': item.place_slot_id,
                'slot_name': slot.slot_name,
                'slot_type': 'place',
                'slot_subtype': slot.slot_type,
                'start_date': slot.start_date,
                'end_date': slot.end_date,
                'slot_price': item.slot_price,
                'admin_price': item.admin_price,
                'settlement_price': item.settlement_price,
                'is_refund': getattr(item, 'is_refund', False),
                'refund_amount': getattr(item, 'refund_amount', 0)
            }
            processed_items.append(processed_item)
    
    return render_template('admin/settlement_detail.html',
                          settlement=settlement,
                          items=processed_items)


@app.route('/admin/settlement/<int:settlement_id>/action', methods=['POST'])
@login_required
@admin_required
def admin_settlement_action(settlement_id):
    """관리자 정산 처리 액션"""
    settlement = Settlement.query.get_or_404(settlement_id)
    action = request.form.get('action')
    
    if action == 'complete':
        # 정산 완료 처리
        settlement.status = 'completed'
        settlement.completed_at = datetime.utcnow()
        
        # 관련 슬롯들 정산 상태 업데이트
        if settlement.settlement_type == 'shopping':
            items = SettlementItem.query.filter_by(settlement_id=settlement_id).all()
            for item in items:
                if item.shopping_slot_id:
                    slot = ShoppingSlot.query.get(item.shopping_slot_id)
                    if slot:
                        slot.settlement_status = 'completed'
        else:
            items = SettlementItem.query.filter_by(settlement_id=settlement_id).all()
            for item in items:
                if item.place_slot_id:
                    slot = PlaceSlot.query.get(item.place_slot_id)
                    if slot:
                        slot.settlement_status = 'completed'
                        
        db.session.commit()
        flash('정산이 완료 처리되었습니다.', 'success')
        
    elif action == 'cancel':
        # 정산 취소 처리
        settlement.status = 'cancelled'
        
        # 관련 슬롯들 정산 상태 원복
        if settlement.settlement_type == 'shopping':
            items = SettlementItem.query.filter_by(settlement_id=settlement_id).all()
            for item in items:
                if item.shopping_slot_id:
                    slot = ShoppingSlot.query.get(item.shopping_slot_id)
                    if slot:
                        slot.settlement_status = 'pending'
        else:
            items = SettlementItem.query.filter_by(settlement_id=settlement_id).all()
            for item in items:
                if item.place_slot_id:
                    slot = PlaceSlot.query.get(item.place_slot_id)
                    if slot:
                        slot.settlement_status = 'pending'
                        
        db.session.commit()
        flash('정산이 취소되었습니다.', 'success')
        
    return redirect(url_for('admin_settlement_detail', settlement_id=settlement_id))


@app.route('/distributor/settlements')
@login_required
@distributor_required
def distributor_settlements():
    """총판 정산 관리 페이지"""
    # 총판에게 직접 관련된 정산
    own_settlements = Settlement.query.filter_by(user_id=current_user.id).order_by(Settlement.created_at.desc()).all()
    
    # 총판이 관리하는 대행사에 관련된 정산들
    agency_ids = [agency.id for agency in current_user.agencies]
    agency_settlements = Settlement.query.filter(Settlement.user_id.in_(agency_ids)).order_by(Settlement.created_at.desc()).all()
    
    return render_template('distributor/settlements.html', 
                          own_settlements=own_settlements,
                          agency_settlements=agency_settlements)


@app.route('/distributor/settlement/<int:settlement_id>')
@login_required
@distributor_required
def distributor_settlement_detail(settlement_id):
    """총판 정산 상세 페이지"""
    settlement = Settlement.query.options(
        joinedload(Settlement.user),
        joinedload(Settlement.admin)
    ).get_or_404(settlement_id)
    
    # 접근 권한 검증 (본인 또는 관리 중인 대행사의 정산만 볼 수 있음)
    if settlement.user_id != current_user.id and settlement.user.parent_id != current_user.id:
        abort(403)
    
    # 정산 항목 조회 (처리된 데이터 준비) - eager loading으로 N+1 쿼리 방지
    processed_items = []
    
    # 쇼핑 슬롯 정산 항목 (shopping_slot eager load)
    shopping_items = SettlementItem.query.options(
        joinedload(SettlementItem.shopping_slot)
    ).filter_by(settlement_id=settlement_id).filter(SettlementItem.shopping_slot_id != None).all()
    for item in shopping_items:
        slot = item.shopping_slot
        if slot:
            # 데이터를 딕셔너리로 구성
            processed_item = {
                'id': item.id,
                'settlement_id': item.settlement_id,
                'slot_id': item.shopping_slot_id,
                'slot_name': slot.slot_name,
                'slot_type': 'shopping',
                'slot_subtype': slot.slot_type,
                'start_date': slot.start_date,
                'end_date': slot.end_date,
                'slot_price': item.slot_price,
                'admin_price': item.admin_price,
                'settlement_price': item.settlement_price,
                'is_refund': getattr(item, 'is_refund', False),
                'refund_amount': getattr(item, 'refund_amount', 0)
            }
            processed_items.append(processed_item)
    
    # 플레이스 슬롯 정산 항목 (place_slot eager load)
    place_items = SettlementItem.query.options(
        joinedload(SettlementItem.place_slot)
    ).filter_by(settlement_id=settlement_id).filter(SettlementItem.place_slot_id != None).all()
    for item in place_items:
        slot = item.place_slot
        if slot:
            # 데이터를 딕셔너리로 구성
            processed_item = {
                'id': item.id,
                'settlement_id': item.settlement_id,
                'slot_id': item.place_slot_id,
                'slot_name': slot.slot_name,
                'slot_type': 'place',
                'slot_subtype': slot.slot_type,
                'start_date': slot.start_date,
                'end_date': slot.end_date,
                'slot_price': item.slot_price,
                'admin_price': item.admin_price,
                'settlement_price': item.settlement_price,
                'is_refund': getattr(item, 'is_refund', False),
                'refund_amount': getattr(item, 'refund_amount', 0)
            }
            processed_items.append(processed_item)
    
    return render_template('distributor/settlement_detail.html',
                          settlement=settlement,
                          items=processed_items)


@app.route('/agency/settlements')
@login_required
@agency_required
def agency_settlements():
    """대행사 정산 페이지"""
    settlements = Settlement.query.filter_by(user_id=current_user.id).order_by(Settlement.created_at.desc()).all()
    
    # 정산 통계
    completed_count = Settlement.query.filter_by(user_id=current_user.id, status='completed').count()
    pending_count = Settlement.query.filter_by(user_id=current_user.id, status='pending').count()
    
    return render_template('agency/settlements.html', 
                          settlements=settlements,
                          completed_count=completed_count,
                          pending_count=pending_count)


@app.route('/agency/settlement/<int:settlement_id>')
@login_required
@agency_required
def agency_settlement_detail(settlement_id):
    """대행사 정산 상세 페이지"""
    settlement = Settlement.query.options(
        joinedload(Settlement.user),
        joinedload(Settlement.admin)
    ).get_or_404(settlement_id)
    
    # 접근 권한 검증 (본인의 정산만 볼 수 있음)
    if settlement.user_id != current_user.id:
        abort(403)
    
    # 정산 항목 조회 (처리된 데이터 준비) - eager loading으로 N+1 쿼리 방지
    processed_items = []
    
    # 쇼핑 슬롯 정산 항목 (shopping_slot eager load)
    shopping_items = SettlementItem.query.options(
        joinedload(SettlementItem.shopping_slot)
    ).filter_by(settlement_id=settlement_id).filter(SettlementItem.shopping_slot_id != None).all()
    for item in shopping_items:
        slot = item.shopping_slot
        if slot:
            # 데이터를 딕셔너리로 구성
            processed_item = {
                'id': item.id,
                'settlement_id': item.settlement_id,
                'slot_id': item.shopping_slot_id,
                'slot_name': slot.slot_name,
                'slot_type': 'shopping',
                'slot_subtype': slot.slot_type,
                'start_date': slot.start_date,
                'end_date': slot.end_date,
                'slot_price': item.slot_price,
                'admin_price': item.admin_price,
                'settlement_price': item.settlement_price,
                'is_refund': getattr(item, 'is_refund', False),
                'refund_amount': getattr(item, 'refund_amount', 0)
            }
            processed_items.append(processed_item)
    
    # 플레이스 슬롯 정산 항목 (place_slot eager load)
    place_items = SettlementItem.query.options(
        joinedload(SettlementItem.place_slot)
    ).filter_by(settlement_id=settlement_id).filter(SettlementItem.place_slot_id != None).all()
    for item in place_items:
        slot = item.place_slot
        if slot:
            # 데이터를 딕셔너리로 구성
            processed_item = {
                'id': item.id,
                'settlement_id': item.settlement_id,
                'slot_id': item.place_slot_id,
                'slot_name': slot.slot_name,
                'slot_type': 'place',
                'slot_subtype': slot.slot_type,
                'start_date': slot.start_date,
                'end_date': slot.end_date,
                'slot_price': item.slot_price,
                'admin_price': item.admin_price,
                'settlement_price': item.settlement_price,
                'is_refund': getattr(item, 'is_refund', False),
                'refund_amount': getattr(item, 'refund_amount', 0)
            }
            processed_items.append(processed_item)
    
    return render_template('agency/settlement_detail.html',
                          settlement=settlement,
                          items=processed_items)


@app.route('/bulk-save-shopping-slots', methods=['POST'])
@csrf.exempt
@login_required
@distributor_required
def bulk_save_shopping_slots():
    """쇼핑 슬롯 일괄 저장"""
    data = request.json
    slot_ids = data.get('slot_ids', [])
    
    if not slot_ids:
        return jsonify({'success': False, 'message': "저장할 슬롯을 선택해주세요."}), 400
    
    # 대행사의 슬롯 + 총판 자신의 슬롯 함께 조회 가능하도록 수정
    agency_ids = [agency.id for agency in current_user.agencies.all()]
    user_ids = agency_ids + [current_user.id]  # 총판 자신의 ID 추가
    
    # 선택된 슬롯 조회 - 총판 관리 하위의 슬롯들만 가능
    slots = ShoppingSlot.query.filter(
        ShoppingSlot.id.in_(slot_ids),
        ShoppingSlot.user_id.in_(user_ids),
        ShoppingSlot.status == 'approved'  # 승인된 슬롯만 처리
    ).all()
    
    if not slots:
        return jsonify({'success': False, 'message': "선택한 슬롯을 찾을 수 없거나 저장할 수 없는 상태입니다."}), 404
    
    # 슬롯 상태를 'live'로 변경 (사용 중 상태로 변경)
    for slot in slots:
        slot.status = 'live'
    
    db.session.commit()
    
    return jsonify({'success': True, 'count': len(slots)})


@app.route('/bulk-save-place-slots', methods=['POST'])
@csrf.exempt
@login_required
@distributor_required
def bulk_save_place_slots():
    """플레이스 슬롯 일괄 저장"""
    data = request.json
    slot_ids = data.get('slot_ids', [])
    
    if not slot_ids:
        return jsonify({'success': False, 'message': "저장할 슬롯을 선택해주세요."}), 400
    
    # 대행사의 슬롯 + 총판 자신의 슬롯 함께 조회 가능하도록 수정
    agency_ids = [agency.id for agency in current_user.agencies.all()]
    user_ids = agency_ids + [current_user.id]  # 총판 자신의 ID 추가
    
    # 선택된 슬롯 조회 - 총판 관리 하위의 슬롯들만 가능
    slots = PlaceSlot.query.filter(
        PlaceSlot.id.in_(slot_ids),
        PlaceSlot.user_id.in_(user_ids),
        PlaceSlot.status == 'approved'  # 승인된 슬롯만 처리
    ).all()
    
    if not slots:
        return jsonify({'success': False, 'message': "선택한 슬롯을 찾을 수 없거나 저장할 수 없는 상태입니다."}), 404
    
    # 슬롯 상태를 'live'로 변경 (사용 중 상태로 변경)
    for slot in slots:
        slot.status = 'live'
    
    db.session.commit()
    
    return jsonify({'success': True, 'count': len(slots)})


@app.route('/bulk-delete-shopping-slots', methods=['POST'])
@csrf.exempt
@login_required
@distributor_required
def bulk_delete_shopping_slots():
    """쇼핑 슬롯 전체 삭제"""
    # 대행사의 슬롯 + 총판 자신의 슬롯 함께 조회 가능하도록 수정
    agency_ids = [agency.id for agency in current_user.agencies.all()]
    user_ids = agency_ids + [current_user.id]  # 총판 자신의 ID 추가
    
    # 필터 적용
    slots = ShoppingSlot.query.filter(ShoppingSlot.user_id.in_(user_ids)).all()
    
    if not slots:
        return jsonify({'success': False, 'message': "삭제할 슬롯이 없습니다."}), 404
    
    count = len(slots)
    
    # 슬롯 상태에 따라 다르게 처리
    pending_slots = []
    other_slots = []
    
    for slot in slots:
        if slot.status == 'pending':
            # 승인 대기 중인 슬롯은 승인 요청도 함께 삭제
            pending_slots.append(slot)
        else:
            other_slots.append(slot)
    
    # 승인 대기 중인 슬롯의 승인 요청 삭제
    for slot in pending_slots:
        approvals = SlotApproval.query.filter_by(shopping_slot_id=slot.id).all()
        for approval in approvals:
            db.session.delete(approval)
    
    # 모든 슬롯 삭제
    for slot in slots:
        db.session.delete(slot)
    
    # 할당량 사용 업데이트
    quota = SlotQuota.query.filter_by(user_id=current_user.id).first()
    if quota:
        quota.shopping_slots_used = 0
        
    db.session.commit()
    
    return jsonify({'success': True, 'count': count})


@app.route('/bulk-delete-place-slots', methods=['POST'])
@csrf.exempt
@login_required
@distributor_required
def bulk_delete_place_slots():
    """플레이스 슬롯 전체 삭제"""
    # 대행사의 슬롯 + 총판 자신의 슬롯 함께 조회 가능하도록 수정
    agency_ids = [agency.id for agency in current_user.agencies.all()]
    user_ids = agency_ids + [current_user.id]  # 총판 자신의 ID 추가
    
    # 필터 적용
    slots = PlaceSlot.query.filter(PlaceSlot.user_id.in_(user_ids)).all()
    
    if not slots:
        return jsonify({'success': False, 'message': "삭제할 슬롯이 없습니다."}), 404
    
    count = len(slots)
    
    # 슬롯 상태에 따라 다르게 처리
    pending_slots = []
    other_slots = []
    
    for slot in slots:
        if slot.status == 'pending':
            # 승인 대기 중인 슬롯은 승인 요청도 함께 삭제
            pending_slots.append(slot)
        else:
            other_slots.append(slot)
    
    # 승인 대기 중인 슬롯의 승인 요청 삭제
    for slot in pending_slots:
        approvals = SlotApproval.query.filter_by(place_slot_id=slot.id).all()
        for approval in approvals:
            db.session.delete(approval)
    
    # 모든 슬롯 삭제
    for slot in slots:
        db.session.delete(slot)
    
    # 할당량 사용 업데이트
    quota = SlotQuota.query.filter_by(user_id=current_user.id).first()
    if quota:
        quota.place_slots_used = 0
        
    db.session.commit()
    
    return jsonify({'success': True, 'count': count})


@app.route('/selected-delete-shopping-slots', methods=['POST'])
@csrf.exempt
@login_required
@distributor_required
def selected_delete_shopping_slots():
    """선택한 쇼핑 슬롯만 삭제"""
    data = request.get_json()
    slot_ids = data.get('slot_ids', [])
    
    if not slot_ids:
        return jsonify({'success': False, 'message': "삭제할 슬롯을 선택해주세요."}), 400
    
    # 대행사의 슬롯 + 총판 자신의 슬롯 함께 조회 가능하도록 수정
    agency_ids = [agency.id for agency in current_user.agencies.all()]
    user_ids = agency_ids + [current_user.id]  # 총판 자신의 ID 추가
    
    # 선택된 슬롯만 조회
    slots = ShoppingSlot.query.filter(
        ShoppingSlot.id.in_(slot_ids),
        ShoppingSlot.user_id.in_(user_ids)
    ).all()
    
    if not slots:
        return jsonify({'success': False, 'message': "삭제할 슬롯이 없습니다."}), 404
    
    count = len(slots)
    
    # 슬롯 상태에 따라 다르게 처리
    pending_slots = []
    
    for slot in slots:
        if slot.status == 'pending':
            # 승인 대기 중인 슬롯은 승인 요청도 함께 삭제
            pending_slots.append(slot)
    
    # 승인 대기 중인 슬롯의 승인 요청 삭제
    for slot in pending_slots:
        approvals = SlotApproval.query.filter_by(shopping_slot_id=slot.id).all()
        for approval in approvals:
            db.session.delete(approval)
    
    # 선택된 슬롯 삭제
    for slot in slots:
        db.session.delete(slot)
    
    # 할당량 사용 업데이트
    quota = SlotQuota.query.filter_by(user_id=current_user.id).first()
    if quota:
        quota.shopping_slots_used = max(0, quota.shopping_slots_used - count)
        
    db.session.commit()
    
    return jsonify({'success': True, 'count': count})


@app.route('/selected-delete-place-slots', methods=['POST'])
@csrf.exempt
@login_required
@distributor_required
def selected_delete_place_slots():
    """선택한 플레이스 슬롯만 삭제"""
    data = request.get_json()
    slot_ids = data.get('slot_ids', [])
    
    if not slot_ids:
        return jsonify({'success': False, 'message': "삭제할 슬롯을 선택해주세요."}), 400
    
    # 대행사의 슬롯 + 총판 자신의 슬롯 함께 조회 가능하도록 수정
    agency_ids = [agency.id for agency in current_user.agencies.all()]
    user_ids = agency_ids + [current_user.id]  # 총판 자신의 ID 추가
    
    # 선택된 슬롯만 조회
    slots = PlaceSlot.query.filter(
        PlaceSlot.id.in_(slot_ids),
        PlaceSlot.user_id.in_(user_ids)
    ).all()
    
    if not slots:
        return jsonify({'success': False, 'message': "삭제할 슬롯이 없습니다."}), 404
    
    count = len(slots)
    
    # 슬롯 상태에 따라 다르게 처리
    pending_slots = []
    
    for slot in slots:
        if slot.status == 'pending':
            # 승인 대기 중인 슬롯은 승인 요청도 함께 삭제
            pending_slots.append(slot)
    
    # 승인 대기 중인 슬롯의 승인 요청 삭제
    for slot in pending_slots:
        approvals = SlotApproval.query.filter_by(place_slot_id=slot.id).all()
        for approval in approvals:
            db.session.delete(approval)
    
    # 선택된 슬롯 삭제
    for slot in slots:
        db.session.delete(slot)
    
    # 할당량 사용 업데이트
    quota = SlotQuota.query.filter_by(user_id=current_user.id).first()
    if quota:
        quota.place_slots_used = max(0, quota.place_slots_used - count)
        
    db.session.commit()
    
    return jsonify({'success': True, 'count': count})


