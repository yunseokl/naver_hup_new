/**
 * 네이버 데이터 입력 시스템 메인 JavaScript
 */

/**
 * 현재 페이지에 맞는 네비게이션 링크를 활성화합니다.
 */
function setActiveNavLink() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.navbar-nav .nav-link');
    
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });
}

/**
 * 파일 업로드 시 파일명을 표시합니다.
 */
function setupFileInput() {
    const fileInputs = document.querySelectorAll('input[type="file"]');
    
    fileInputs.forEach(input => {
        input.addEventListener('change', function(e) {
            const fileName = e.target.files[0]?.name;
            const label = input.nextElementSibling;
            
            if (label && label.classList && label.classList.contains('form-text')) {
                if (fileName) {
                    const fileInfo = document.createElement('div');
                    fileInfo.classList.add('mt-2', 'small', 'text-muted');
                    fileInfo.textContent = `선택된 파일: ${fileName}`;
                    
                    // 이전 파일명 정보 삭제
                    const prevInfo = label.nextElementSibling;
                    if (prevInfo && prevInfo.classList && prevInfo.classList.contains('text-muted')) {
                        prevInfo.remove();
                    }
                    
                    label.insertAdjacentElement('afterend', fileInfo);
                }
            }
        });
    });
}

/**
 * 필드 자동 포커스
 */
function setupAutofocus() {
    const autofocusElement = document.querySelector('[autofocus]');
    if (autofocusElement) {
        autofocusElement.focus();
    }
}

/**
 * 경고창을 자동으로 사라지게 합니다.
 */
function setupAlertDismiss() {
    const alerts = document.querySelectorAll('.alert-dismissible');
    
    alerts.forEach(alert => {
        setTimeout(() => {
            const closeButton = alert.querySelector('.btn-close');
            if (closeButton) {
                closeButton.click();
            }
        }, 5000);
    });
}

/**
 * 페이지 로드 시 초기화 함수
 */
document.addEventListener('DOMContentLoaded', function() {
    // 아이콘 초기화
    if (typeof feather !== 'undefined') {
        feather.replace();
    }
    
    // 네비게이션 활성화
    setActiveNavLink();
    
    // 파일 업로드 설정
    setupFileInput();
    
    // 자동 포커스
    setupAutofocus();
    
    // 알림 자동 닫기
    setupAlertDismiss();
});