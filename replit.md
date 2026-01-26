# MyDispatcher - GTA 5 Mod Store

## Overview
A full-featured GTA 5 mod store with user authentication, admin panel, mod browsing with search/filters, video uploads for mods, and a custom download page with 5-second timer. Features a dark theme with black and blue accents.

## Admin Credentials
- **Email**: admin@mydispatcher.com
- **Password**: admin123

## Features
- User authentication (login/register)
- Admin panel for managing mods and categories
- Browse mods with search and category filters
- Sort by latest, popular, or oldest
- Featured mods section on homepage
- Video upload support for mod previews
- Custom download page with 5-second countdown timer
- Dark theme with blue/black color scheme

## Tech Stack
- **Backend**: Python Flask
- **Database**: PostgreSQL
- **Frontend**: Bootstrap 5, Custom CSS
- **Authentication**: Flask-Login with password hashing

## Project Structure
```
/
├── app.py              # Main Flask application
├── templates/
│   ├── base.html       # Base template with navigation
│   ├── index.html      # Homepage
│   ├── login.html      # Login page
│   ├── register.html   # Registration page
│   ├── browse.html     # Mod browsing with filters
│   ├── mod_detail.html # Single mod view
│   ├── download.html   # Download page with timer
│   └── admin/
│       ├── dashboard.html   # Admin dashboard
│       ├── mod_form.html    # Add/edit mod form
│       └── category_form.html # Add category form
├── uploads/            # Uploaded files directory
│   ├── mods/           # Mod files (.zip, .rar, etc.)
│   ├── images/         # Mod cover images
│   └── videos/         # Mod preview videos
└── static/             # Static assets
```

## Database Models
- **User**: id, username, email, password_hash, is_admin, created_at
- **Category**: id, name, description
- **Mod**: id, title, description, version, file_path, image_path, video_path, download_count, category_id, is_featured, download_token

## Default Categories
- Vehicles
- Scripts
- Maps
- Weapons
- Characters
- Graphics

## Running the Application
The application runs on port 5000 with the command `python app.py`.
