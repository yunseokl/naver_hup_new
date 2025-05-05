import os
import logging
import uuid
import pandas as pd
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

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
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max upload size
app.config["ALLOWED_EXTENSIONS"] = {'xlsx', 'xls'}

# Initialize the database with the app
db.init_app(app)

# Import models after initializing db to avoid circular imports
from models import ShoppingData, PlaceData

# Create database tables
with app.app_context():
    db.create_all()

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    """Render the main index page."""
    return render_template('index.html')

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

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('index.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors."""
    logger.error(f"Server error: {e}")
    return render_template('index.html'), 500
