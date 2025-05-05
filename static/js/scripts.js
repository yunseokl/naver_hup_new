/**
 * Main JavaScript file for the Naver Data Entry System
 */
document.addEventListener('DOMContentLoaded', function() {
    // Make sure the navbar active state reflects the current page
    setActiveNavLink();
    
    // Initialize any tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    if (tooltipTriggerList.length > 0) {
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
    
    // Auto-hide flash messages after 5 seconds
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(function(alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
});

/**
 * Sets the active state on the navigation link that matches the current page
 */
function setActiveNavLink() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.navbar-nav .nav-link');
    
    navLinks.forEach(function(link) {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });
}

/**
 * Translates text between Korean and English placeholders/labels
 * Note: This is a simple example and would need to be expanded for a real app
 */
function translateText(element, lang) {
    // This would typically use a translation dictionary or API
    // For now, we're just toggling preset translations
    
    // Example implementation for a future enhancement
    console.log(`Translation for ${element} to ${lang} would happen here`);
}
