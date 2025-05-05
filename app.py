import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.middleware.proxy_fix import ProxyFix

# Create the Flask application
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@app.route('/')
def index():
    """Render the main index page."""
    return render_template('index.html')

@app.route('/shopping', methods=['GET', 'POST'])
def shopping():
    """Handle Naver Shopping form submission."""
    if request.method == 'POST':
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
        
        # Log form submission (in a real app, this would be saved to a database)
        logger.info(f"Shopping form submitted: {product_name}")
        
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
    
    return render_template('shopping.html')

@app.route('/place', methods=['GET', 'POST'])
def place():
    """Handle Naver Place form submission."""
    if request.method == 'POST':
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
        
        # Log form submission (in a real app, this would be saved to a database)
        logger.info(f"Place form submitted: {place_name}")
        
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
    
    return render_template('place.html')

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

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('index.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors."""
    logger.error(f"Server error: {e}")
    return render_template('index.html'), 500
