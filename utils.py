"""
유틸리티 함수 모듈
공통으로 사용되는 헬퍼 함수들을 모아둔 모듈
"""
import os
import logging
from datetime import datetime, date
from functools import wraps
from flask import jsonify, abort, request
from flask_login import current_user
from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)


# API 응답 헬퍼
def api_success(data=None, message=None, status_code=200):
    """표준 성공 응답"""
    response = {
        'success': True,
        'data': data if data is not None else {},
        'message': message
    }
    return jsonify(response), status_code


def api_error(message, status_code=400, error_code=None):
    """표준 오류 응답"""
    response = {
        'success': False,
        'error': message,
        'error_code': error_code
    }
    return jsonify(response), status_code


# 데이터 변환 헬퍼
def safe_int(value, default=0, allow_none=False):
    """안전하게 정수로 변환
    
    Args:
        value: 변환할 값
        default: allow_none=True일 때 빈 값에 대한 기본값
        allow_none: True이면 빈 값을 default로 변환
    
    Returns:
        int: 변환된 정수 값
        
    Raises:
        ValueError: 변환 실패 시
    """
    if value is None or value == '':
        if allow_none:
            return default
        else:
            raise ValueError("값이 비어있습니다.")
    
    try:
        return int(value)
    except (ValueError, TypeError):
        raise ValueError(f"'{value}'은(는) 유효한 숫자가 아닙니다.")


def safe_float(value, default=0.0, allow_none=False):
    """안전하게 실수로 변환"""
    if value is None or value == '':
        if allow_none:
            return default
        else:
            raise ValueError("값이 비어있습니다.")
    
    try:
        return float(value)
    except (ValueError, TypeError):
        raise ValueError(f"'{value}'은(는) 유효한 숫자가 아닙니다.")


def safe_date(value, date_format='%Y-%m-%d'):
    """안전하게 날짜로 변환"""
    if not value:
        return None
    
    if isinstance(value, date):
        return value
    
    try:
        return datetime.strptime(str(value), date_format).date()
    except ValueError:
        raise ValueError(f"'{value}'은(는) 유효한 날짜 형식이 아닙니다. (형식: {date_format})")


# 파일 처리 헬퍼
def allowed_file(filename, allowed_extensions):
    """파일 확장자 확인"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions


def generate_unique_filename(original_filename):
    """고유한 파일명 생성"""
    from uuid import uuid4
    ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
    unique_name = f"{uuid4().hex}"
    return f"{unique_name}.{ext}" if ext else unique_name


# 권한 검사 데코레이터
def role_required(*roles):
    """특정 역할을 가진 사용자만 접근 가능"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            
            user_role = current_user.role.name if current_user.role else None
            if user_role not in roles and 'admin' not in roles:
                logger.warning(f"권한 없는 접근 시도: {current_user.username} ({user_role}) -> {request.path}")
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# 데이터 검증 헬퍼
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


def validate_email(email):
    """이메일 형식 검증"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_phone(phone):
    """전화번호 형식 검증 (한국 형식)"""
    import re
    # 010-1234-5678, 02-123-4567, 031-123-4567 등
    pattern = r'^0\d{1,2}-\d{3,4}-\d{4}$'
    return re.match(pattern, phone) is not None


# 날짜 계산 헬퍼
def calculate_days_between(start_date, end_date):
    """두 날짜 사이의 일수 계산"""
    if not start_date or not end_date:
        return 0
    
    if isinstance(start_date, str):
        start_date = safe_date(start_date)
    if isinstance(end_date, str):
        end_date = safe_date(end_date)
    
    delta = end_date - start_date
    return max(0, delta.days + 1)  # 시작일 포함


def is_date_in_range(check_date, start_date, end_date):
    """날짜가 범위 내에 있는지 확인"""
    if not all([check_date, start_date, end_date]):
        return False
    
    if isinstance(check_date, str):
        check_date = safe_date(check_date)
    if isinstance(start_date, str):
        start_date = safe_date(start_date)
    if isinstance(end_date, str):
        end_date = safe_date(end_date)
    
    return start_date <= check_date <= end_date


# 로깅 헬퍼
def log_user_activity(action, details=None):
    """사용자 활동 로깅"""
    user_info = f"{current_user.username} ({current_user.role.name})" if current_user.is_authenticated else "Anonymous"
    log_message = f"사용자 활동: {user_info} - {action}"
    if details:
        log_message += f" | 상세: {details}"
    logger.info(log_message)


# 숫자 포맷팅
def format_currency(amount):
    """금액을 한국 원화 형식으로 포맷팅"""
    if amount is None:
        return "0원"
    try:
        return f"{int(amount):,}원"
    except (ValueError, TypeError):
        return "0원"


def format_number(number):
    """숫자를 천 단위 구분 형식으로 포맷팅"""
    if number is None:
        return "0"
    try:
        return f"{int(number):,}"
    except (ValueError, TypeError):
        return "0"


# 페이지네이션 헬퍼
def get_pagination_params(request):
    """요청에서 페이지네이션 파라미터 추출"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # 최대값 제한
    page = max(1, page)
    per_page = min(100, max(10, per_page))
    
    return page, per_page


def create_pagination_dict(pagination):
    """페이지네이션 객체를 딕셔너리로 변환"""
    return {
        'page': pagination.page,
        'per_page': pagination.per_page,
        'total': pagination.total,
        'pages': pagination.pages,
        'has_prev': pagination.has_prev,
        'has_next': pagination.has_next,
        'prev_num': pagination.prev_num,
        'next_num': pagination.next_num
    }
