# replit.md

## Overview

This is a Flask-based web application for managing Naver Shopping and Place advertising slots. The system operates with a three-tier user hierarchy (admin → distributor → agency) and provides comprehensive slot management, approval workflows, and settlement systems.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Backend Architecture
- **Framework**: Flask (Python web framework)
- **Database ORM**: SQLAlchemy with Flask-SQLAlchemy
- **Authentication**: Flask-Login for session management
- **Security**: Flask-WTF for CSRF protection
- **Database**: PostgreSQL (configured via DATABASE_URL environment variable)

### Frontend Architecture
- **Template Engine**: Jinja2 (Flask's default)
- **CSS Framework**: Bootstrap 5 with dark theme
- **Icons**: Feather Icons
- **JavaScript**: Vanilla JS for form validation and interactive features

### Application Structure
- **Entry Point**: `main.py` - Application startup and configuration
- **Core Application**: `app.py` - Main Flask application with routes and business logic
- **Data Models**: `models.py` - SQLAlchemy database models
- **Templates**: `templates/` - HTML templates organized by user roles
- **Static Assets**: `static/` - CSS, JavaScript, and image files

## Key Components

### User Management System
- Three-tier role hierarchy: Admin → Distributor (총판) → Agency (대행사)
- User registration with admin approval workflow
- Role-based access control throughout the application
- Parent-child relationships between distributors and agencies

### Slot Management
- **Shopping Slots**: For Naver Shopping advertisements
- **Place Slots**: For Naver Place (location-based) advertisements
- Slot states: empty → pending → approved → live → rejected
- Bulk operations via Excel file upload/download
- Individual slot creation and management

### Approval Workflow
- Hierarchical approval process based on user roles
- Slot creation, modification, and deletion require approval
- Bulk approval capabilities for administrators
- Request tracking and notification system

### Settlement System
- Automated settlement calculations based on slot usage
- Pricing model: 30 KRW × slot count × duration
- Settlement history and refund processing
- Financial reporting and analytics

## Data Flow

### User Registration Flow
1. User submits registration form
2. Admin reviews and approves/rejects application
3. Approved users can access role-specific features
4. Hierarchical relationships established (distributor → agency)

### Slot Management Flow
1. Agency requests slot quota from distributor
2. Distributor allocates empty slots to agency
3. Agency fills slots with advertising content
4. Slots require approval before going live
5. Live slots generate settlement entries

### Settlement Flow
1. Approved slots automatically generate settlement calculations
2. Settlement records track financial obligations
3. Refund requests can be processed for cancelled slots
4. Financial reports provide overview of all transactions

## External Dependencies

### Required Python Packages
- `flask` - Web framework
- `flask-sqlalchemy` - Database ORM
- `flask-login` - Authentication
- `flask-wtf` - Form handling and CSRF protection
- `psycopg2-binary` - PostgreSQL driver
- `pandas` - Excel file processing
- `openpyxl` - Excel file manipulation
- `email-validator` - Email validation
- `gunicorn` - WSGI server for deployment

### External Services
- **PostgreSQL Database**: Primary data storage
- **Bootstrap CDN**: CSS framework and components
- **Feather Icons CDN**: Icon library

## Deployment Strategy

### Environment Configuration
- `DATABASE_URL`: PostgreSQL connection string
- `SESSION_SECRET`: Secret key for session management
- Default admin credentials: username=admin, password=adminpassword

### File Structure Requirements
- `uploads/` directory for file uploads
- `static/img/` directory for static images
- Database initialization on first run

### Deployment Considerations
- Application runs on port 5000 in development
- Uses Gunicorn for production deployment
- ProxyFix middleware for reverse proxy compatibility
- Database connection pooling with automatic reconnection

### Security Features
- CSRF protection on all forms
- Password hashing for user authentication
- Role-based access control
- File upload restrictions and validation

## Notes

- The application uses Korean language throughout the interface
- Number formatting follows Korean locale conventions
- File upload limit set to 64MB
- Database connection includes pool recycling for reliability
- The system supports both individual and bulk operations for efficiency