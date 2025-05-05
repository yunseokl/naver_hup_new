/**
 * Form validation functions for the Naver Data Entry System
 */

/**
 * Sets up client-side validation for a form
 * @param {string} formId - The ID of the form to validate
 */
function setupFormValidation(formId) {
    const form = document.getElementById(formId);
    if (!form) return;
    
    form.addEventListener('submit', function(event) {
        if (!validateForm(form)) {
            event.preventDefault();
            event.stopPropagation();
        }
        
        form.classList.add('was-validated');
    });
    
    // Add input event listeners for real-time validation
    const requiredInputs = form.querySelectorAll('[required]');
    requiredInputs.forEach(function(input) {
        input.addEventListener('input', function() {
            validateInput(input);
        });
        input.addEventListener('blur', function() {
            validateInput(input);
        });
    });
    
    // Add special validation for specific field types
    setupSpecialValidation(form);
}

/**
 * Validates all inputs in a form
 * @param {HTMLFormElement} form - The form to validate
 * @returns {boolean} - Whether the form is valid
 */
function validateForm(form) {
    let isValid = true;
    
    // Validate required fields
    const requiredInputs = form.querySelectorAll('[required]');
    requiredInputs.forEach(function(input) {
        if (!validateInput(input)) {
            isValid = false;
        }
    });
    
    // Validate special fields
    if (form.id === 'shoppingForm') {
        // Specific validation for shopping form
        const price = form.querySelector('#price');
        if (price && (isNaN(price.value) || parseInt(price.value) <= 0)) {
            price.setCustomValidity('유효한 가격을 입력해주세요. | Please enter a valid price.');
            isValid = false;
        } else if (price) {
            price.setCustomValidity('');
        }
    } else if (form.id === 'placeForm') {
        // Specific validation for place form
        const phone = form.querySelector('#phone');
        if (phone && phone.value && !validatePhoneNumber(phone.value)) {
            phone.setCustomValidity('유효한 전화번호 형식이 아닙니다. | Invalid phone number format.');
            isValid = false;
        } else if (phone) {
            phone.setCustomValidity('');
        }
        
        const website = form.querySelector('#website');
        if (website && website.value && !validateURL(website.value)) {
            website.setCustomValidity('유효한 URL 형식이 아닙니다. | Invalid URL format.');
            isValid = false;
        } else if (website) {
            website.setCustomValidity('');
        }
    }
    
    return isValid;
}

/**
 * Validates a single input field
 * @param {HTMLInputElement} input - The input to validate
 * @returns {boolean} - Whether the input is valid
 */
function validateInput(input) {
    // Reset previous validation
    input.setCustomValidity('');
    
    // Check if empty but required
    if (input.hasAttribute('required') && !input.value.trim()) {
        const fieldName = input.labels[0] ? input.labels[0].textContent.split('|')[0].trim() : '필드';
        input.setCustomValidity(`${fieldName}을(를) 입력해주세요.`);
        return false;
    }
    
    // Check select elements
    if (input.tagName === 'SELECT' && input.hasAttribute('required') && 
        (input.value === '' || input.selectedIndex === 0)) {
        const fieldName = input.labels[0] ? input.labels[0].textContent.split('|')[0].trim() : '항목';
        input.setCustomValidity(`${fieldName}을(를) 선택해주세요.`);
        return false;
    }
    
    return true;
}

/**
 * Sets up special validation for specific field types
 * @param {HTMLFormElement} form - The form containing the fields
 */
function setupSpecialValidation(form) {
    // Price validation
    const priceInput = form.querySelector('#price');
    if (priceInput) {
        priceInput.addEventListener('input', function() {
            if (isNaN(this.value) || parseInt(this.value) <= 0) {
                this.setCustomValidity('유효한 가격을 입력해주세요. | Please enter a valid price.');
            } else {
                this.setCustomValidity('');
            }
        });
    }
    
    // Phone number validation
    const phoneInput = form.querySelector('#phone');
    if (phoneInput) {
        phoneInput.addEventListener('input', function() {
            if (this.value && !validatePhoneNumber(this.value)) {
                this.setCustomValidity('유효한 전화번호 형식이 아닙니다. | Invalid phone number format.');
            } else {
                this.setCustomValidity('');
            }
        });
    }
    
    // URL validation
    const urlInput = form.querySelector('#website');
    if (urlInput) {
        urlInput.addEventListener('input', function() {
            if (this.value && !validateURL(this.value)) {
                this.setCustomValidity('유효한 URL 형식이 아닙니다. | Invalid URL format.');
            } else {
                this.setCustomValidity('');
            }
        });
    }
}

/**
 * Validates a Korean phone number
 * @param {string} phone - The phone number to validate
 * @returns {boolean} - Whether the phone number is valid
 */
function validatePhoneNumber(phone) {
    // Korean phone number formats: 02-123-4567, 010-1234-5678, etc.
    const phoneRegex = /^(0[2-6][0-9]|01[0-9]|070|080)-[0-9]{3,4}-[0-9]{4}$/;
    return phoneRegex.test(phone);
}

/**
 * Validates a URL
 * @param {string} url - The URL to validate
 * @returns {boolean} - Whether the URL is valid
 */
function validateURL(url) {
    try {
        new URL(url);
        return true;
    } catch (e) {
        return false;
    }
}
