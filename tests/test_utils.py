"""
utils.py 모듈 테스트
"""
import pytest
from datetime import date, datetime
from utils import (
    safe_int, safe_float, safe_date,
    validate_password_complexity,
    validate_email, validate_phone,
    calculate_days_between, is_date_in_range,
    format_currency, format_number,
    api_success, api_error
)


class TestSafeInt:
    """safe_int 함수 테스트"""
    
    def test_valid_int_string(self):
        """유효한 정수 문자열 변환"""
        assert safe_int("123") == 123
        assert safe_int("0") == 0
        assert safe_int("-456") == -456
    
    def test_valid_int(self):
        """정수 타입 그대로 반환"""
        assert safe_int(789) == 789
    
    def test_empty_with_default(self):
        """빈 값과 기본값"""
        assert safe_int("", default=0, allow_none=True) == 0
        assert safe_int(None, default=10, allow_none=True) == 10
        assert safe_int("", default=99, allow_none=True) == 99
    
    def test_empty_without_default(self):
        """빈 값 에러 발생"""
        with pytest.raises(ValueError, match="비어있습니다"):
            safe_int("")
        
        with pytest.raises(ValueError, match="비어있습니다"):
            safe_int(None)
    
    def test_invalid_string(self):
        """유효하지 않은 문자열"""
        with pytest.raises(ValueError, match="유효한 숫자가 아닙니다"):
            safe_int("abc")
        
        with pytest.raises(ValueError, match="유효한 숫자가 아닙니다"):
            safe_int("12.34")


class TestSafeFloat:
    """safe_float 함수 테스트"""
    
    def test_valid_float(self):
        """유효한 실수 변환"""
        assert safe_float("12.34") == 12.34
        assert safe_float("0.5") == 0.5
        assert safe_float(99.99) == 99.99
    
    def test_empty_with_default(self):
        """빈 값과 기본값"""
        assert safe_float("", default=0.0, allow_none=True) == 0.0
        assert safe_float(None, default=1.5, allow_none=True) == 1.5


class TestSafeDate:
    """safe_date 함수 테스트"""
    
    def test_valid_date_string(self):
        """유효한 날짜 문자열"""
        result = safe_date("2024-01-15")
        assert result == date(2024, 1, 15)
    
    def test_date_object(self):
        """date 객체 그대로 반환"""
        test_date = date(2024, 1, 15)
        assert safe_date(test_date) == test_date
    
    def test_none_value(self):
        """None 값 반환"""
        assert safe_date(None) is None
        assert safe_date("") is None
    
    def test_invalid_date_format(self):
        """유효하지 않은 날짜 형식"""
        with pytest.raises(ValueError, match="유효한 날짜 형식이 아닙니다"):
            safe_date("2024/01/15")
        
        with pytest.raises(ValueError):
            safe_date("invalid")


class TestPasswordValidation:
    """비밀번호 검증 테스트"""
    
    def test_valid_password(self):
        """유효한 비밀번호"""
        is_valid, msg = validate_password_complexity("Test1234")
        assert is_valid is True
        assert msg == ""
        
        is_valid, msg = validate_password_complexity("Abcdef123")
        assert is_valid is True
    
    def test_too_short(self):
        """8자 미만"""
        is_valid, msg = validate_password_complexity("Test1")
        assert is_valid is False
        assert "8자 이상" in msg
    
    def test_no_uppercase(self):
        """대문자 없음"""
        is_valid, msg = validate_password_complexity("test1234")
        assert is_valid is False
        assert "대문자" in msg
    
    def test_no_lowercase(self):
        """소문자 없음"""
        is_valid, msg = validate_password_complexity("TEST1234")
        assert is_valid is False
        assert "소문자" in msg
    
    def test_no_digit(self):
        """숫자 없음"""
        is_valid, msg = validate_password_complexity("TestTest")
        assert is_valid is False
        assert "숫자" in msg


class TestEmailValidation:
    """이메일 검증 테스트"""
    
    def test_valid_email(self):
        """유효한 이메일"""
        assert validate_email("test@example.com") is True
        assert validate_email("user.name@domain.co.kr") is True
        assert validate_email("test123@gmail.com") is True
    
    def test_invalid_email(self):
        """유효하지 않은 이메일"""
        assert validate_email("invalid") is False
        assert validate_email("@example.com") is False
        assert validate_email("test@") is False
        assert validate_email("test") is False


class TestPhoneValidation:
    """전화번호 검증 테스트"""
    
    def test_valid_phone(self):
        """유효한 전화번호"""
        assert validate_phone("010-1234-5678") is True
        assert validate_phone("02-123-4567") is True
        assert validate_phone("031-123-4567") is True
    
    def test_invalid_phone(self):
        """유효하지 않은 전화번호"""
        assert validate_phone("01012345678") is False
        assert validate_phone("010-1234-567") is False
        assert validate_phone("invalid") is False


class TestDateCalculation:
    """날짜 계산 테스트"""
    
    def test_calculate_days_between(self):
        """날짜 사이 일수 계산"""
        start = date(2024, 1, 1)
        end = date(2024, 1, 10)
        assert calculate_days_between(start, end) == 10
    
    def test_same_day(self):
        """같은 날짜"""
        start = date(2024, 1, 1)
        end = date(2024, 1, 1)
        assert calculate_days_between(start, end) == 1
    
    def test_with_strings(self):
        """문자열 날짜로 계산"""
        days = calculate_days_between("2024-01-01", "2024-01-10")
        assert days == 10
    
    def test_is_date_in_range(self):
        """날짜 범위 확인"""
        assert is_date_in_range(
            date(2024, 1, 5),
            date(2024, 1, 1),
            date(2024, 1, 10)
        ) is True
        
        assert is_date_in_range(
            date(2024, 1, 15),
            date(2024, 1, 1),
            date(2024, 1, 10)
        ) is False


class TestFormatting:
    """포맷팅 함수 테스트"""
    
    def test_format_currency(self):
        """금액 포맷팅"""
        assert format_currency(10000) == "10,000원"
        assert format_currency(1234567) == "1,234,567원"
        assert format_currency(None) == "0원"
        assert format_currency(0) == "0원"
    
    def test_format_number(self):
        """숫자 포맷팅"""
        assert format_number(1234567) == "1,234,567"
        assert format_number(1000) == "1,000"
        assert format_number(None) == "0"
        assert format_number(0) == "0"


class TestAPIResponse:
    """API 응답 헬퍼 테스트"""
    
    def test_api_success(self):
        """성공 응답"""
        response, status_code = api_success(
            data={'id': 1, 'name': 'test'},
            message='성공'
        )
        
        assert status_code == 200
        json_data = response.get_json()
        assert json_data['success'] is True
        assert json_data['data']['id'] == 1
        assert json_data['message'] == '성공'
    
    def test_api_success_no_data(self):
        """데이터 없는 성공 응답"""
        response, status_code = api_success()
        
        json_data = response.get_json()
        assert json_data['success'] is True
        assert json_data['data'] == {}
    
    def test_api_error(self):
        """에러 응답"""
        response, status_code = api_error(
            message='오류 발생',
            status_code=400,
            error_code='INVALID_INPUT'
        )
        
        assert status_code == 400
        json_data = response.get_json()
        assert json_data['success'] is False
        assert json_data['error'] == '오류 발생'
        assert json_data['error_code'] == 'INVALID_INPUT'
