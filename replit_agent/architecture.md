# Architecture Overview

## Overview

This application is a Naver ad slot management system designed to facilitate the management of advertising slots for Naver Shopping and Naver Place (location-based) services. The system serves three primary user roles: administrators, distributors, and agencies, within a hierarchical relationship. Distributors manage agencies, and all roles interact with ad slot management in various capacities.

The application is built with a Flask backend, SQLAlchemy ORM for database management, and utilizes Bootstrap for the frontend. It provides functionality for user management, ad slot registration and tracking, and an approval workflow system.

## System Architecture

### High-Level Architecture

The system follows a traditional web application architecture with:

1. **Presentation Layer**: HTML templates with Bootstrap CSS framework
2. **Application Layer**: Flask framework handling HTTP requests and business logic
3. **Data Access Layer**: SQLAlchemy ORM for database interactions
4. **Database Layer**: PostgreSQL database for persistent storage

### Key Technologies

- **Backend Framework**: Flask (Python)
- **ORM**: SQLAlchemy
- **Database**: PostgreSQL
- **Frontend**: Bootstrap with Feather Icons
- **Authentication**: Flask-Login
- **File Processing**: Pandas for Excel file processing
- **Deployment**: Gunicorn as WSGI server

## Key Components

### Backend Components

#### Flask Application (`app.py`)

The central component of the application, responsible for:
- Application configuration
- Database initialization
- Authentication management
- Request handling setup

#### User Authentication and Authorization (`models.py` + `app.py`)

- Uses Flask-Login for authentication management
- Role-based authorization with distinct permissions for admins, distributors, and agencies
- Hierarchical user structure where distributors manage agencies

#### Data Models (`models.py`)

Core data models include:
- `Role`: Defines user roles (admin, distributor, agency)
- `User`: Stores user information with relationships to roles and hierarchical structure
- `ShoppingSlot` and `PlaceSlot`: Represents advertising slots for different platforms

### Frontend Components

#### Templates

Organized into several directories:
- `templates/`: Base templates and common views
- `templates/auth/`: Authentication-related views
- `templates/admin/`: Administrator-specific views
- `templates/distributor/`: Distributor-specific views
- `templates/errors/`: Error pages

#### Static Assets

- `static/css/`: Custom stylesheets
- `static/js/`: JavaScript for client-side validation and interactions
- `static/img/`: Image assets

## Data Flow

### Authentication Flow

1. Users navigate to the login page
2. Credentials are validated against the database
3. Flask-Login manages the user session
4. Role-based access controls direct users to appropriate dashboards

### Ad Slot Management Flow

1. Users can upload Excel files containing slot data or create entries manually
2. Data is processed (using Pandas for Excel files) and validated
3. Entries are stored in the database
4. Approval workflows may be triggered based on user roles

### Approval Workflow

1. Agencies request slot approvals from distributors
2. Distributors receive notifications of pending approvals
3. Distributors can approve or reject requests
4. Status updates are reflected in the database

## Database Schema

### Core Tables

- **Role**: Stores role definitions
- **User**: Stores user information with foreign keys to roles and parent users
- **ShoppingSlot**: Stores Naver Shopping ad slot data
- **PlaceSlot**: Stores Naver Place ad slot data
- **SlotApproval**: Tracks approval requests and status

### Key Relationships

- **Users to Roles**: Many-to-one (each user has one role)
- **Distributors to Agencies**: One-to-many (distributors manage multiple agencies)
- **Users to Slots**: One-to-many (users own multiple slots)
- **Slots to Approvals**: One-to-many (slots can have multiple approval requests)

## External Dependencies

### Core Dependencies

- **Flask**: Web framework
- **SQLAlchemy**: ORM for database operations
- **Flask-Login**: User authentication management
- **Pandas**: Data processing for Excel files
- **Werkzeug**: Utilities for Flask (file uploads, security)
- **Gunicorn**: WSGI HTTP server for deployment

### Third-Party Services

- No external API integrations are explicitly defined in the codebase
- The system appears to be self-contained with a focus on internal management

## Deployment Strategy

### Configuration

- The application uses environment variables for configuration:
  - `DATABASE_URL`: Database connection string
  - `SESSION_SECRET`: Secret key for session security

### Deployment Setup

- **WSGI Server**: Gunicorn
- **Deployment Target**: Auto-scaling environment (based on .replit configuration)
- **Port Configuration**: Internal port 5000 mapped to external port 80

### Replit Configuration

The application is configured to run on Replit with:
- Python 3.11 as the runtime
- PostgreSQL database
- Gunicorn as the WSGI server
- Auto-scaling deployment strategy

## Security Considerations

### Authentication Security

- Passwords are hashed using Werkzeug's security utilities
- Session management through Flask-Login
- Secret key configuration for session security

### Input Validation

- Client-side validation via JavaScript
- Server-side validation for form submissions
- Secure file uploads with extension and size restrictions

### Error Handling

- Custom error pages for common HTTP errors (403, 404, 500)
- Structured exception handling

## Development Considerations

### File Structure

- Modular organization with separate files for different concerns
- Template inheritance for consistent UI
- Static assets organization by type

### Potential Improvements

- API-based architecture for better client-server separation
- Enhanced frontend with modern JavaScript frameworks
- More comprehensive error handling and logging
- Structured migrations strategy for database schema changes