# MyDispatcher - GTA 5 Mod Store

## Overview
MyDispatcher is a full-featured GTA 5 mod store web application that allows users to browse, download, and share game modifications. The platform includes user authentication, an admin panel for content management, mod browsing with search and filtering capabilities, video upload support for mod previews, and a custom download page with a countdown timer. The application features a dark theme with a blue/black color scheme optimized for gaming communities.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### Backend Framework
- **Flask** serves as the web framework, chosen for its simplicity and flexibility for small-to-medium web applications
- Uses Flask-SQLAlchemy for ORM database interactions
- Flask-Login handles session management and user authentication
- Flask-WTF provides form handling with CSRF protection
- Flask-Dance enables OAuth integration (Replit authentication)

### Authentication System
- Dual authentication: traditional email/password login and OAuth via Replit
- Passwords are hashed using Werkzeug's security functions
- Admin users have elevated privileges controlled by an `is_admin` boolean flag
- Default admin credentials: admin@mydispatcher.com / admin123

### Database Models
- **User**: Stores user accounts with username, email, hashed password, admin status
- **Category**: Organizes mods into browsable categories
- **Mod**: Main content model with relationships to categories (implied from code structure)

### File Upload System
- Supports three types of uploads: mod files, images, and videos
- Files stored in `uploads/` directory with subdirectories for organization
- Maximum upload size: 500MB
- Secure filename handling via Werkzeug utilities

### Frontend Architecture
- Server-side rendering with Jinja2 templates
- Bootstrap 5 for responsive layout and components
- Custom CSS with CSS variables for consistent dark theme styling
- Template inheritance from `base.html` for consistent layout

### Route Structure
- Public routes: homepage, browse, mod details, download page
- Auth routes: login, register, logout
- Admin routes: dashboard, mod management, category management
- Protected routes use `@login_required` decorator

## External Dependencies

### Database
- **PostgreSQL** as the primary database (configured via `DATABASE_URL` environment variable)
- psycopg2-binary for PostgreSQL connectivity

### Authentication Services
- Replit OIDC integration for OAuth authentication
- PyJWT for token handling

### Frontend CDN Resources
- Bootstrap 5.3.0 CSS and JS
- Bootstrap Icons 1.10.0

### Python Packages (Key Dependencies)
- Flask 3.1.2 - Web framework
- Flask-SQLAlchemy 3.1.1 - Database ORM
- Flask-Login 0.6.3 - User session management
- Flask-WTF 1.2.2 - Form handling
- Flask-Dance 7.1.0 - OAuth integration
- Gunicorn - Production WSGI server

### Environment Variables Required
- `SECRET_KEY` - Flask session secret
- `DATABASE_URL` - PostgreSQL connection string
- `REPL_ID` - Replit application identifier (for OAuth)
- `ISSUER_URL` - OAuth issuer URL