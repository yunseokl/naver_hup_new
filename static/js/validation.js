/**
 * 네이버 데이터 입력 시스템 유효성 검증 JavaScript
 */

/**
 * 폼 유효성 검증 초기화
 * @param {string} formId - 검증할 폼의 ID
 */
function setupFormValidation(formId) {
    const form = document.getElementById(formId);
    if (!form) return;
    
    // 폼 제출 이벤트에 유효성 검증 로직 추가
    form.addEventListener('submit', function(event) {
        if (!validateForm(form)) {
            event.preventDefault();
            event.stopPropagation();
        }
        
        form.classList.add('was-validated');
    });
    
    // 개별 필드 검증 설정
    setupInputValidation(form);
    
    // 특수 필드 검증 설정
    setupSpecialValidation(form);
}

/**
 * 전체 폼의 유효성 검증
 * @param {HTMLFormElement} form - 검증할 폼 요소
 * @returns {boolean} - 폼이 유효한지 여부
 */
function validateForm(form) {
    let isValid = true;
    
    // 모든 필수 입력 필드 검증
    const requiredInputs = form.querySelectorAll('[required]');
    requiredInputs.forEach(input => {
        if (!validateInput(input)) {
            isValid = false;
        }
    });
    
    return isValid;
}

/**
 * 개별 입력 필드의 유효성 검증 설정
 * @param {HTMLFormElement} form - 유효성 검증을 설정할 폼
 */
function setupInputValidation(form) {
    const inputs = form.querySelectorAll('input, textarea, select');
    
    inputs.forEach(input => {
        // 입력 필드 변경 시 유효성 검증
        input.addEventListener('input', function() {
            validateInput(input);
        });
        
        // 입력 필드 포커스 아웃 시 유효성 검증
        input.addEventListener('blur', function() {
            validateInput(input);
        });
    });
}

/**
 * 개별 입력 필드 검증
 * @param {HTMLInputElement} input - 검증할 입력 필드
 * @returns {boolean} - 입력 필드가 유효한지 여부
 */
function validateInput(input) {
    // 입력 필드가 필수가 아니고 값이 없으면 유효함
    if (!input.hasAttribute('required') && !input.value.trim()) {
        input.classList.remove('is-invalid');
        return true;
    }
    
    // 기본 HTML 유효성 검증
    let isValid = input.checkValidity();
    
    // 특수 필드 유형 검증
    if (input.type === 'tel') {
        isValid = validatePhoneNumber(input.value);
    } else if (input.type === 'url' && input.value.trim()) {
        isValid = validateURL(input.value);
    } else if (input.type === 'number') {
        isValid = !isNaN(input.value) && input.value.trim() !== '';
    }
    
    // 유효성 결과에 따라 클래스 추가/제거
    if (isValid) {
        input.classList.remove('is-invalid');
    } else {
        input.classList.add('is-invalid');
    }
    
    return isValid;
}

/**
 * 특수 필드 유효성 검증 설정
 * @param {HTMLFormElement} form - 유효성 검증을 설정할 폼
 */
function setupSpecialValidation(form) {
    // 가격 필드가 있는 경우 숫자만 입력되도록 제한
    const priceInput = form.querySelector('#price');
    if (priceInput) {
        priceInput.addEventListener('input', function() {
            this.value = this.value.replace(/[^0-9]/g, '');
        });
    }
    
    // 전화번호 필드가 있는 경우 형식 지정
    const phoneInput = form.querySelector('#phone');
    if (phoneInput) {
        phoneInput.addEventListener('input', function() {
            // 숫자와 하이픈만 허용
            this.value = this.value.replace(/[^0-9-]/g, '');
            
            // 자동 하이픈 추가 (한국 번호 형식)
            let value = this.value.replace(/-/g, '');
            if (value.length > 3 && value.length <= 7) {
                this.value = value.substring(0, 3) + '-' + value.substring(3);
            } else if (value.length > 7) {
                this.value = value.substring(0, 3) + '-' + value.substring(3, 7) + '-' + value.substring(7, 11);
            }
        });
    }
}

/**
 * 전화번호 유효성 검증
 * @param {string} phone - 검증할 전화번호
 * @returns {boolean} - 전화번호가 유효한지 여부
 */
function validatePhoneNumber(phone) {
    if (!phone.trim()) return true; // 비어있으면 유효함 (필수가 아닌 경우)
    
    // 한국 전화번호 형식 검증 (고정전화 및 휴대전화)
    const phoneRegex = /^(01[016789]{1}|02|0[3-9]{1}[0-9]{1})-?[0-9]{3,4}-?[0-9]{4}$/;
    return phoneRegex.test(phone);
}

/**
 * URL 유효성 검증
 * @param {string} url - 검증할 URL
 * @returns {boolean} - URL이 유효한지 여부
 */
function validateURL(url) {
    if (!url.trim()) return true; // 비어있으면 유효함 (필수가 아닌 경우)
    
    try {
        new URL(url);
        return true;
    } catch (e) {
        return false;
    }
}