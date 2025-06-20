import logging
import os
import re
from datetime import datetime, date, timedelta
import pandas as pd
from io import StringIO
from werkzeug.utils import secure_filename
from werkzeug.exceptions import BadRequest, NotFound
import json
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort, send_file
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import or_, and_, func
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField, SelectField, BooleanField, IntegerField, DateField
from wtforms.validators import DataRequired, Email, Length
from email_validator import validate_email, EmailNotValidError

# 폼 클래스 정의
class RegistrationForm(FlaskForm):
    username = StringField('사용자명', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('이메일', validators=[DataRequired(), Email()])
    company_name = StringField('회사명', validators=[DataRequired(), Length(max=100)])
    password = PasswordField('비밀번호', validators=[DataRequired(), Length(min=6)])
    role_id = SelectField('역할', coerce=int, validators=[DataRequired()])

# 로깅 설정
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Class & DB initialization
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Flask app 초기화
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET', 'default-secret-key')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB 파일 업로드 제한
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# CSRF 보호 설정
csrf = CSRFProtect(app)

# 로그인 매니저 설정
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 일부 API 엔드포인트는 CSRF 검증에서 제외
csrf_exempt_routes = ['save_slot_api', 'save_slots_bulk_api', 'toggle_slot_api']

@csrf.exempt
def csrf_exempt_rule():
    if request.endpoint in csrf_exempt_routes:
        return True
    return False

# 데이터베이스 모델 정의
from models import Role, User, SlotQuota, SlotQuotaRequest
from models import ShoppingSlot, PlaceSlot, SlotApproval, Settlement, SettlementItem
from models import SlotRefundRequest

# 데이터베이스 초기화
db.init_app(app)

# 애플리케이션 초기 설정 함수
def create_tables_and_defaults():
    """애플리케이션 초기 설정 - 테이블 생성 및 기본 사용자/역할 설정"""
    with app.app_context():
        db.create_all()
        
        # 기본 역할 생성 (관리자, 총판, 대행사)
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            admin_role = Role(name='admin', description='관리자')
            db.session.add(admin_role)
        
        distributor_role = Role.query.filter_by(name='distributor').first()
        if not distributor_role:
            distributor_role = Role(name='distributor', description='총판')
            db.session.add(distributor_role)
        
        agency_role = Role.query.filter_by(name='agency').first()
        if not agency_role:
            agency_role = Role(name='agency', description='대행사')
            db.session.add(agency_role)
        
        db.session.flush()
        
        # 기본 관리자 사용자 생성 (아직 없는 경우)
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                email='admin@example.com',
                company_name='관리자',
                password_hash=generate_password_hash('adminpassword'),
                role_id=admin_role.id,
                approved=True
            )
            db.session.add(admin_user)
        
        # 변경사항 저장
        db.session.commit()
        
        app.logger.info("데이터베이스 테이블 및 기본 사용자/역할이 생성되었습니다.")

# 애플리케이션 시작 시 초기 설정 호출
create_tables_and_defaults()

# 템플릿 필터 등록
@app.template_filter('format_number')
def format_number_filter(value):
    """숫자를 포맷팅하는 필터 (예: 10000 -> 10,000)"""
    if value is None:
        return '0'
    return "{:,}".format(value)

@app.template_filter('safe_format')
def safe_format_filter(value):
    """안전하게 콤마를 포함한 숫자 포맷팅 (None 값 처리 포함)"""
    if value is None:
        return '0'
    return "{:,}".format(value)

@app.template_filter('nl2br')
def nl2br_filter(text):
    """텍스트의 줄바꿈을 HTML <br> 태그로 변환"""
    if not text:
        return ''
    return text.replace('\n', '<br>')

# 템플릿 컨텍스트 프로세서
@app.context_processor
def utility_processor():
    def now():
        return datetime.now()
    return dict(now=now)

# 로그인 관리자 설정
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 데코레이터 - 관리자 권한 필요
def admin_required(f):
    """관리자만 접근 가능한 라우트 데코레이터"""
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# 데코레이터 - 총판 권한 필요
def distributor_required(f):
    """총판만 접근 가능한 라우트 데코레이터"""
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_distributor():
            abort(403)
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# 데코레이터 - 대행사 이상 권한 필요
def agency_or_above_required(f):
    """대행사 이상(대행사, 총판, 관리자)만 접근 가능한 라우트 데코레이터"""
    @login_required
    def decorated_function(*args, **kwargs):
        if not (current_user.is_agency() or current_user.is_distributor() or current_user.is_admin()):
            abort(403)
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# 데코레이터 - 대행사 권한 필요
def agency_required(f):
    """대행사만 접근 가능한 라우트 데코레이터"""
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_agency():
            abort(403)
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# 파일 업로드 함수
def allowed_file(filename):
    """허용된 파일 확장자인지 확인"""
    ALLOWED_EXTENSIONS = {'xlsx', 'xls'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 로그인 / 인증 관련 라우트
@app.route('/login', methods=['GET', 'POST'])
def login():
    """사용자 로그인 처리"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            if not user.approved:
                flash('계정이 아직 승인되지 않았습니다. 관리자에게 문의하세요.', 'warning')
                return redirect(url_for('login'))
            
            login_user(user)
            
            # 사용자 역할에 따라 적절한 대시보드로 리다이렉트
            if user.is_admin():
                return redirect(url_for('admin_dashboard'))
            elif user.is_distributor():
                return redirect(url_for('distributor_dashboard'))
            elif user.is_agency():
                return redirect(url_for('agency_dashboard'))
            else:
                return redirect(url_for('index'))
        else:
            flash('로그인에 실패했습니다. 사용자 이름과 비밀번호를 확인하세요.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """사용자 로그아웃 처리"""
    logout_user()
    flash('로그아웃되었습니다.', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """새 사용자 회원가입 - 관리자 승인 필요"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    # 역할 목록 조회 (관리자 제외)
    roles = Role.query.filter(Role.name != 'admin').all()
    
    # 폼 생성
    form = RegistrationForm()
    form.role_id.choices = [(role.id, role.description or role.name) for role in roles]
    
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        company_name = form.company_name.data
        password = form.password.data
        role_id = form.role_id.data
        
        # 중복 사용자 확인
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            flash('이미 사용 중인 사용자 이름 또는 이메일입니다.', 'danger')
            return redirect(url_for('register'))
        
        # 역할 확인 (대행사 또는 총판만 허용)
        role = Role.query.get(role_id)
        if not role or role.name == 'admin':
            flash('유효하지 않은 역할입니다.', 'danger')
            return redirect(url_for('register'))
        
        # 새 사용자 생성 (승인 대기 상태)
        new_user = User(
            username=username,
            email=email,
            company_name=company_name,
            password_hash=generate_password_hash(password),
            role_id=role_id,
            approved=False
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('회원가입이 완료되었습니다. 관리자 승인 후 로그인 가능합니다.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/register.html', form=form)

# 메인 페이지 라우트
@app.route('/')
def index():
    """메인 랜딩 페이지"""
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for('admin_dashboard'))
        elif current_user.is_distributor():
            return redirect(url_for('distributor_dashboard'))
        elif current_user.is_agency():
            return redirect(url_for('agency_dashboard'))
    
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """사용자 대시보드"""
    # 사용자 역할에 따라 적절한 대시보드로 리다이렉트
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    elif current_user.is_distributor():
        return redirect(url_for('distributor_dashboard'))
    elif current_user.is_agency():
        return redirect(url_for('agency_dashboard'))
    else:
        # 기본 대시보드 (역할이 없는 경우)
        return render_template('dashboard.html')

# 관리자 라우트
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    """관리자 대시보드"""
    # 요약 정보
    users_count = User.query.count()
    pending_users = User.query.filter_by(approved=False).count()
    distributors_count = User.query.join(Role).filter(Role.name == 'distributor').count()
    agencies_count = User.query.join(Role).filter(Role.name == 'agency').count()
    
    # 승인 요청 통계
    pending_approvals = SlotApproval.query.filter_by(status='pending').count()
    approved_approvals = SlotApproval.query.filter_by(status='approved').count()
    rejected_approvals = SlotApproval.query.filter_by(status='rejected').count()
    
    # 슬롯 통계
    shopping_slots_count = ShoppingSlot.query.count()
    place_slots_count = PlaceSlot.query.count()
    live_shopping_slots = ShoppingSlot.query.filter_by(status='live').count()
    live_place_slots = PlaceSlot.query.filter_by(status='live').count()
    
    # 환불 요청 통계
    pending_refunds = SlotRefundRequest.query.filter_by(status='pending').count()
    
    # 정산 통계
    pending_settlements = Settlement.query.filter_by(status='pending').count()
    
    return render_template('admin/dashboard.html',
                          users_count=users_count,
                          pending_users=pending_users,
                          distributors_count=distributors_count,
                          agencies_count=agencies_count,
                          pending_approvals=pending_approvals,
                          approved_approvals=approved_approvals,
                          rejected_approvals=rejected_approvals,
                          shopping_slots_count=shopping_slots_count,
                          place_slots_count=place_slots_count,
                          live_shopping_slots=live_shopping_slots,
                          live_place_slots=live_place_slots,
                          pending_refunds=pending_refunds,
                          pending_settlements=pending_settlements)

@app.route('/admin/users')
@login_required
@admin_required
def users():
    """사용자 관리 페이지"""
    # 전체 사용자 목록 조회
    users = User.query.all()
    
    # 승인 대기 중인 사용자 목록
    pending_users = User.query.filter_by(approved=False).all()
    
    # 역할별 사용자 목록
    admin_users = User.query.join(Role).filter(Role.name == 'admin').all()
    distributor_users = User.query.join(Role).filter(Role.name == 'distributor').all()
    agency_users = User.query.join(Role).filter(Role.name == 'agency').all()
    
    return render_template('admin/users.html',
                          users=users,
                          pending_users=pending_users,
                          admin_users=admin_users,
                          distributor_users=distributor_users,
                          agency_users=agency_users)

@app.route('/admin/users/<int:user_id>/<action>')
@login_required
@admin_required
def approve_user(user_id, action):
    """사용자 승인 요청 처리"""
    user = User.query.get_or_404(user_id)
    
    if action == 'approve':
        user.approved = True
        flash(f'{user.username} 사용자가 승인되었습니다.', 'success')
    elif action == 'reject':
        user.approved = False
        flash(f'{user.username} 사용자가 거부되었습니다.', 'success')
    elif action == 'delete':
        db.session.delete(user)
        flash(f'{user.username} 사용자가 삭제되었습니다.', 'success')
    
    db.session.commit()
    return redirect(url_for('users'))

@app.route('/admin/approvals')
@login_required
@admin_required
def admin_approvals():
    """관리자용 승인 요청 관리 페이지"""
    # 전체 승인 요청 목록
    approvals = SlotApproval.query.order_by(SlotApproval.requested_at.desc()).all()
    
    # 필터링 옵션 (상태별)
    status_filter = request.args.get('status', 'all')
    
    if status_filter != 'all':
        approvals = [a for a in approvals if a.status == status_filter]
    
    pending_count = sum(1 for a in approvals if a.status == 'pending')
    
    return render_template('admin/approvals.html',
                          approvals=approvals,
                          pending_count=pending_count,
                          status_filter=status_filter)
                          
@app.route('/admin/settlements')
@login_required
@admin_required
def admin_settlements():
    """관리자용 정산 관리 페이지"""
    # 전체 정산 목록 조회
    settlements = Settlement.query.order_by(Settlement.created_at.desc()).all()
    
    # 필터링 옵션 적용
    period = request.args.get('period', 'all')
    status = request.args.get('status', 'all')
    
    if period != 'all':
        today = date.today()
        if period == 'this_month':
            start_date = date(today.year, today.month, 1)
            settlements = [s for s in settlements if s.created_at.date() >= start_date]
        elif period == 'last_month':
            last_month = today.month - 1 if today.month > 1 else 12
            last_month_year = today.year if today.month > 1 else today.year - 1
            start_date = date(last_month_year, last_month, 1)
            end_date = date(today.year, today.month, 1) - timedelta(days=1)
            settlements = [s for s in settlements if start_date <= s.created_at.date() <= end_date]
        elif period == 'last_3months':
            three_months_ago = today - timedelta(days=90)
            settlements = [s for s in settlements if s.created_at.date() >= three_months_ago]
    
    if status != 'all':
        settlements = [s for s in settlements if s.status == status]
    
    return render_template('admin/settlements.html',
                          settlements=settlements,
                          period=period,
                          status=status)

@app.route('/admin/settlement/<int:settlement_id>')
@login_required
@admin_required
def admin_settlement_detail(settlement_id):
    """관리자용 정산 상세 페이지"""
    settlement = Settlement.query.get_or_404(settlement_id)
    
    # 정산 항목 가져오기
    items = SettlementItem.query.filter_by(settlement_id=settlement_id).all()
    
    return render_template('admin/settlement_detail.html',
                          settlement=settlement,
                          items=items)
                          
@app.route('/admin/settlement/<int:settlement_id>/complete', methods=['POST'])
@login_required
@admin_required
def admin_complete_settlement(settlement_id):
    """관리자용 정산 완료 처리"""
    settlement = Settlement.query.get_or_404(settlement_id)
    
    if settlement.status == 'pending':
        settlement.status = 'completed'
        settlement.completed_at = datetime.now()
        settlement.admin_id = current_user.id
        
        # 관련 슬롯들의 정산 상태도 업데이트
        items = SettlementItem.query.filter_by(settlement_id=settlement_id).all()
        for item in items:
            if item.shopping_slot_id:
                item.shopping_slot.settlement_status = 'completed'
            elif item.place_slot_id:
                item.place_slot.settlement_status = 'completed'
        
        db.session.commit()
        flash('정산이 완료되었습니다.', 'success')
    else:
        flash('이미 처리된 정산입니다.', 'warning')
    
    return redirect(url_for('admin_settlement_detail', settlement_id=settlement_id))

@app.route('/admin/settlement/<int:settlement_id>/cancel', methods=['POST'])
@login_required
@admin_required
def admin_cancel_settlement(settlement_id):
    """관리자용 정산 취소 처리"""
    settlement = Settlement.query.get_or_404(settlement_id)
    
    if settlement.status == 'pending':
        settlement.status = 'cancelled'
        settlement.admin_id = current_user.id
        
        # 관련 슬롯들의 정산 상태도 업데이트
        items = SettlementItem.query.filter_by(settlement_id=settlement_id).all()
        for item in items:
            if item.shopping_slot_id:
                item.shopping_slot.settlement_status = 'pending'
            elif item.place_slot_id:
                item.place_slot.settlement_status = 'pending'
        
        db.session.commit()
        flash('정산이 취소되었습니다.', 'success')
    else:
        flash('이미 처리된 정산입니다.', 'warning')
    
    return redirect(url_for('admin_settlement_detail', settlement_id=settlement_id))

@app.route('/admin/shopping-slots')
@login_required
@admin_required
def admin_shopping_slots():
    """관리자 쇼핑 슬롯 관리"""
    # 전체 쇼핑 슬롯 목록
    slots = ShoppingSlot.query.order_by(ShoppingSlot.created_at.desc()).all()
    
    # 필터링 옵션 (상태별)
    status_filter = request.args.get('status', 'all')
    
    if status_filter != 'all':
        slots = [s for s in slots if s.status == status_filter]
    
    return render_template('admin/shopping_slots.html',
                          slots=slots,
                          status_filter=status_filter)

@app.route('/admin/place-slots')
@login_required
@admin_required
def admin_place_slots():
    """관리자 플레이스 슬롯 관리"""
    # 전체 플레이스 슬롯 목록
    slots = PlaceSlot.query.order_by(PlaceSlot.created_at.desc()).all()
    
    # 필터링 옵션 (상태별)
    status_filter = request.args.get('status', 'all')
    
    if status_filter != 'all':
        slots = [s for s in slots if s.status == status_filter]
    
    return render_template('admin/place_slots.html',
                          slots=slots,
                          status_filter=status_filter)

@app.route('/admin/create-shopping-slot', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_create_shopping_slot():
    """관리자가 쇼핑 슬롯 생성"""
    if request.method == 'POST':
        # 폼 데이터 추출
        user_id = request.form.get('user_id')
        slot_name = request.form.get('slot_name')
        slot_type = request.form.get('slot_type')
        product_name = request.form.get('product_name')
        store_name = request.form.get('store_name')
        store_url = request.form.get('store_url')
        brand_name = request.form.get('brand_name')
        category = request.form.get('category')
        status = request.form.get('status') or 'empty'
        
        # 선택적 필드 처리
        period = request.form.get('period')
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        price = request.form.get('price')
        admin_price = request.form.get('admin_price')
        
        # 날짜 변환
        start_date = None
        end_date = None
        
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        
        # 가격 변환
        slot_price = int(price) if price else 0
        admin_price = int(admin_price) if admin_price else 0
        
        # 새 슬롯 생성
        new_slot = ShoppingSlot(
            user_id=user_id,
            slot_name=slot_name,
            slot_type=slot_type,
            product_name=product_name,
            store_name=store_name,
            store_url=store_url if 'store_url' in locals() else None,
            keywords=brand_name,  # brand_name을 keywords 필드로 매핑
            category=category,
            status=status,
            start_date=start_date,
            end_date=end_date,
            slot_price=slot_price,
            admin_price=admin_price
        )
        
        db.session.add(new_slot)
        db.session.commit()
        
        flash('쇼핑 슬롯이 성공적으로 생성되었습니다.', 'success')
        return redirect(url_for('admin_shopping_slots'))
    
    # 사용자 목록 (대행사 또는 총판)
    users = User.query.join(Role).filter(
        (Role.name == 'agency') | (Role.name == 'distributor')
    ).order_by(User.company_name).all()
    
    return render_template('admin/create_shopping_slot.html', users=users)

@app.route('/admin/create-place-slot', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_create_place_slot():
    """관리자가 플레이스 슬롯 생성"""
    if request.method == 'POST':
        # 폼 데이터 추출
        user_id = request.form.get('user_id')
        slot_name = request.form.get('slot_name')
        slot_type = request.form.get('slot_type')
        place_name = request.form.get('place_name')
        place_address = request.form.get('place_address')
        place_category = request.form.get('place_category')
        place_description = request.form.get('place_description')
        status = request.form.get('status') or 'empty'
        
        # 선택적 필드 처리
        period = request.form.get('period')
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        price = request.form.get('price')
        admin_price = request.form.get('admin_price')
        
        # 날짜 변환
        start_date = None
        end_date = None
        
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        
        # 가격 변환
        slot_price = int(price) if price else 0
        admin_price = int(admin_price) if admin_price else 0
        
        # 새 슬롯 생성
        new_slot = PlaceSlot(
            user_id=user_id,
            slot_name=slot_name,
            slot_type=slot_type,
            place_name=place_name,
            address=place_address,  # place_address를 address 필드로 매핑
            business_category=place_category,  # place_category를 business_category 필드로 매핑
            business_type=place_description if 'place_description' in locals() else None,  # 설명을 업종 필드로 매핑
            status=status,
            start_date=start_date,
            end_date=end_date,
            slot_price=slot_price,
            admin_price=admin_price
        )
        
        db.session.add(new_slot)
        db.session.commit()
        
        flash('플레이스 슬롯이 성공적으로 생성되었습니다.', 'success')
        return redirect(url_for('admin_place_slots'))
    
    # 사용자 목록 (대행사 또는 총판)
    users = User.query.join(Role).filter(
        (Role.name == 'agency') | (Role.name == 'distributor')
    ).order_by(User.company_name).all()
    
    return render_template('admin/create_place_slot.html', users=users)

@app.route('/admin/edit-shopping-slot/<int:slot_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_shopping_slot(slot_id):
    """관리자가 쇼핑 슬롯 편집"""
    slot = ShoppingSlot.query.get_or_404(slot_id)
    
    if request.method == 'POST':
        # 폼 데이터 추출
        slot.user_id = request.form.get('user_id')
        slot.slot_name = request.form.get('slot_name')
        slot.slot_type = request.form.get('slot_type')
        slot.product_name = request.form.get('product_name')
        slot.store_name = request.form.get('store_name')
        slot.store_url = request.form.get('store_url')
        slot.keywords = request.form.get('brand_name')  # brand_name을 keywords 필드로 사용
        slot.category = request.form.get('category')
        slot.status = request.form.get('status')
        
        # 선택적 필드 처리
        slot.period = request.form.get('period')
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        price = request.form.get('price')
        admin_price = request.form.get('admin_price')
        
        # 날짜 변환
        if start_date_str:
            slot.start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        else:
            slot.start_date = None
        
        if end_date_str:
            slot.end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        else:
            slot.end_date = None
        
        # 가격 변환
        slot.slot_price = int(price) if price else 0
        slot.admin_price = int(admin_price) if admin_price else 0
        
        db.session.commit()
        
        flash('쇼핑 슬롯이 성공적으로 수정되었습니다.', 'success')
        return redirect(url_for('admin_shopping_slots'))
    
    # 사용자 목록 (대행사 또는 총판)
    users = User.query.join(Role).filter(
        (Role.name == 'agency') | (Role.name == 'distributor')
    ).order_by(User.company_name).all()
    
    return render_template('admin/edit_shopping_slot.html', slot=slot, users=users)

@app.route('/admin/edit-place-slot/<int:slot_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_place_slot(slot_id):
    """관리자가 플레이스 슬롯 편집"""
    slot = PlaceSlot.query.get_or_404(slot_id)
    
    if request.method == 'POST':
        # 폼 데이터 추출
        slot.user_id = request.form.get('user_id')
        slot.slot_name = request.form.get('slot_name')
        slot.slot_type = request.form.get('slot_type')
        slot.place_name = request.form.get('place_name')
        slot.address = request.form.get('place_address')  # place_address를 address로 매핑
        slot.business_category = request.form.get('place_category')  # place_category를 business_category로 매핑
        slot.business_type = request.form.get('place_description')  # place_description을 business_type으로 매핑
        slot.status = request.form.get('status')
        
        # 선택적 필드 처리
        slot.period = request.form.get('period')
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        price = request.form.get('price')
        admin_price = request.form.get('admin_price')
        
        # 날짜 변환
        if start_date_str:
            slot.start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        else:
            slot.start_date = None
        
        if end_date_str:
            slot.end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        else:
            slot.end_date = None
        
        # 가격 변환
        slot.slot_price = int(price) if price else 0
        slot.admin_price = int(admin_price) if admin_price else 0
        
        db.session.commit()
        
        flash('플레이스 슬롯이 성공적으로 수정되었습니다.', 'success')
        return redirect(url_for('admin_place_slots'))
    
    # 사용자 목록 (대행사 또는 총판)
    users = User.query.join(Role).filter(
        (Role.name == 'agency') | (Role.name == 'distributor')
    ).order_by(User.company_name).all()
    
    return render_template('admin/edit_place_slot.html', slot=slot, users=users)

@app.route('/admin/delete-shopping-slot/<int:slot_id>')
@login_required
@admin_required
def admin_delete_shopping_slot(slot_id):
    """관리자가 쇼핑 슬롯 삭제"""
    slot = ShoppingSlot.query.get_or_404(slot_id)
    
    # 슬롯 삭제
    db.session.delete(slot)
    db.session.commit()
    
    flash('쇼핑 슬롯이 성공적으로 삭제되었습니다.', 'success')
    return redirect(url_for('admin_shopping_slots'))

@app.route('/admin/delete-place-slot/<int:slot_id>')
@login_required
@admin_required
def admin_delete_place_slot(slot_id):
    """관리자가 플레이스 슬롯 삭제"""
    slot = PlaceSlot.query.get_or_404(slot_id)
    
    # 슬롯 삭제
    db.session.delete(slot)
    db.session.commit()
    
    flash('플레이스 슬롯이 성공적으로 삭제되었습니다.', 'success')
    return redirect(url_for('admin_place_slots'))

@app.route('/admin/bulk-approve', methods=['POST'])
@login_required
@admin_required
def admin_bulk_approve():
    """일괄 승인/거절 처리"""
    action = request.form.get('action')
    approval_ids = request.form.getlist('approval_ids')
    
    if not approval_ids:
        flash('선택된 항목이 없습니다.', 'warning')
        return redirect(url_for('admin_approvals'))
    
    processed_count = 0
    
    for approval_id in approval_ids:
        approval = SlotApproval.query.get(approval_id)
        if not approval or approval.status != 'pending':
            continue
        
        if action == 'approve':
            approval.status = 'approved'
            approval.approver_id = current_user.id
            approval.processed_at = datetime.utcnow()
            
            # 슬롯 상태 업데이트
            if approval.slot_type == 'shopping':
                approval.shopping_slot.status = 'live'
                
                # 정산 자동 처리 - 30원 × 슬롯1개(100유입) × 기간
                if approval.shopping_slot.start_date and approval.shopping_slot.end_date:
                    # 시작일과 종료일 사이의 일수 계산 (양 끝 포함)
                    slot = approval.shopping_slot
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
                            slot_price=unit_price,  # 30원 고정 단가
                            admin_price=slot.admin_price,
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
                
                # 정산 자동 처리 - 30원 × 슬롯1개(100유입) × 기간
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
                            slot_price=unit_price,  # 30원 고정 단가
                            admin_price=slot.admin_price,
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
                            slot_price=unit_price,  # 30원 고정 단가
                            admin_price=slot.admin_price,
                            settlement_price=total_price
                        )
                        db.session.add(settlement_item)
                        
                        # 변경사항 저장
                        db.session.flush()
                        
                        app.logger.info(f"새 정산 #{new_settlement.id} 생성됨 (슬롯 #{slot.id})")
            
        elif action == 'reject':
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
    
    flash(f"{processed_count}개의 요청이 {'승인' if action == 'approve' else '거절'}되었습니다.", 'success')
    return redirect(url_for('admin_approvals'))

@app.route('/admin/approve/<int:approval_id>/<action>')
@login_required
@admin_required
def admin_approve_request(approval_id, action):
    """승인 요청 처리 및 정산 자동 처리"""
    approval = SlotApproval.query.get_or_404(approval_id)
    
    if action == 'approve':
        approval.status = 'approved'
        approval.approver_id = current_user.id
        approval.processed_at = datetime.utcnow()
        
        # 슬롯 상태 업데이트
        if approval.slot_type == 'shopping':
            slot = approval.shopping_slot
            slot.status = 'live'
            
            # 정산 자동 처리 - 30원 × 슬롯1개(100유입) × 기간
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
                        slot_price=unit_price,  # 30원 고정 단가
                        admin_price=slot.admin_price,
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
                        slot_price=unit_price,  # 30원 고정 단가
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
            
            # 정산 자동 처리 - 30원 × 슬롯1개(100유입) × 기간
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
                        slot_price=unit_price,  # 30원 고정 단가
                        admin_price=slot.admin_price,
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
                        slot_price=unit_price,  # 30원 고정 단가
                        admin_price=slot.admin_price,
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
    return redirect(url_for('admin_approvals'))
