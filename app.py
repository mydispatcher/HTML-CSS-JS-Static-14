from flask import Flask, render_template, redirect, url_for, flash, request, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.middleware.proxy_fix import ProxyFix
import os
import logging
import sys
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import uuid

# Load dotenv if available (for local development)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Configure Logging to Replit Console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Security and Configuration
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'mydispatcher-secret-key-2024')

def configure_database(app):
    try:
        # Priority 1: Environment Variable (Recommended for Render/Replit)
        uri = os.environ.get('DATABASE_URL')
        
        # Priority 2: Individual Replit PG variables
        if not uri or uri.strip() == "":
            pg_user = os.environ.get('PGUSER')
            pg_pass = os.environ.get('PGPASSWORD')
            pg_host = os.environ.get('PGHOST')
            pg_port = os.environ.get('PGPORT')
            pg_db = os.environ.get('PGDATABASE')
            if all([pg_user, pg_pass, pg_host, pg_port, pg_db]):
                uri = f"postgresql://{pg_user}:{pg_pass}@{pg_host}:{pg_port}/{pg_db}"

        if uri and uri.strip():
            # Handle Render/Supabase postgres:// format
            if uri.startswith("postgres://"):
                uri = uri.replace("postgres://", "postgresql://", 1)
            
            # Add SSL requirements for Supabase if not present
            if "supabase.co" in uri and "sslmode" not in uri:
                separator = "&" if "?" in uri else "?"
                uri = f"{uri}{separator}sslmode=require"
            
            # Force IPv4 for Supabase if requested (via pgbouncer port 6543 or 5432)
            # Some environments (like Render) have trouble with IPv6 to Supabase
            # We don't change the host here, but the user should ensure they use the 
            # connection pooling URL (port 6543) if port 5432 is blocked.
            
            logger.info("Database URI configured successfully from environment")
            return uri
        
        # Default Fallback: SQLite
        logger.warning("No database configuration found. Using local SQLite.")
        basedir = os.path.abspath(os.path.dirname(__file__))
        return f"sqlite:///{os.path.join(basedir, 'mydispatcher.db')}"
    except Exception as e:
        logger.error(f"DB Config Error: {e}")
        basedir = os.path.abspath(os.path.dirname(__file__))
        return f"sqlite:///{os.path.join(basedir, 'mydispatcher.db')}"

app.config['SQLALCHEMY_DATABASE_URI'] = configure_database(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

# Ensure Upload Directories Exist
for folder in ['mods', 'images', 'videos']:
    os.makedirs(os.path.join('uploads', folder), exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Category(db.Model):
    __tablename__ = 'category'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    mods = db.relationship('Mod', backref='category', lazy=True)

class Mod(db.Model):
    __tablename__ = 'mod'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    version = db.Column(db.String(50))
    file_path = db.Column(db.String(500))
    image_path = db.Column(db.String(500))
    video_path = db.Column(db.String(500))
    download_count = db.Column(db.Integer, default=0)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_featured = db.Column(db.Boolean, default=False)
    download_token = db.Column(db.String(100))
    comments = db.relationship('Comment', backref='mod', lazy=True, order_by='Comment.created_at.desc()')

class Comment(db.Model):
    __tablename__ = 'comment'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mod_id = db.Column(db.Integer, db.ForeignKey('mod.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='comments')

# Replit Auth
try:
    from replit_auth import make_replit_blueprint
    app.register_blueprint(make_replit_blueprint(), url_prefix="/auth")
except ImportError:
    pass

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        logger.error(f"User load error: {e}")
        return None

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired(), Length(min=1, max=1000)])

# Routes
@app.route('/')
def index():
    try:
        featured_mods = Mod.query.filter_by(is_featured=True).limit(6).all()
        latest_mods = Mod.query.order_by(Mod.created_at.desc()).limit(8).all()
        categories = Category.query.all()
        return render_template('index.html', featured_mods=featured_mods, latest_mods=latest_mods, categories=categories)
    except Exception as e:
        logger.error(f"Index error: {e}")
        return "Critical system error - Refresh in a moment.", 500

@app.route('/browse')
def browse():
    try:
        page = request.args.get('page', 1, type=int)
        cat_id = request.args.get('category', type=int)
        search = request.args.get('search', '')
        sort = request.args.get('sort', 'latest')
        
        query = Mod.query
        if cat_id: query = query.filter_by(category_id=cat_id)
        if search: query = query.filter(Mod.title.ilike(f'%{search}%') | Mod.description.ilike(f'%{search}%'))
        
        if sort == 'popular': query = query.order_by(Mod.download_count.desc())
        elif sort == 'oldest': query = query.order_by(Mod.created_at.asc())
        else: query = query.order_by(Mod.created_at.desc())
        
        mods = query.paginate(page=page, per_page=12, error_out=False)
        return render_template('browse.html', mods=mods, categories=Category.query.all(), 
                             current_category=cat_id, search=search, sort=sort)
    except Exception as e:
        logger.error(f"Browse error: {e}")
        return redirect(url_for('index'))

@app.route('/mod/<int:mod_id>')
def mod_detail(mod_id):
    try:
        mod = Mod.query.get_or_404(mod_id)
        related = Mod.query.filter(Mod.category_id == mod.category_id, Mod.id != mod.id).limit(4).all()
        return render_template('mod_detail.html', mod=mod, related_mods=related, form=CommentForm())
    except Exception as e:
        logger.error(f"Detail error: {e}")
        return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if current_user.is_authenticated: return redirect(url_for('index'))
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user and user.check_password(form.password.data):
                login_user(user)
                flash('Welcome back!', 'success')
                return redirect(url_for('index'))
            flash('Invalid credentials', 'danger')
        return render_template('login.html', form=form)
    except Exception as e:
        logger.error(f"Login error: {e}")
        return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        if current_user.is_authenticated: return redirect(url_for('index'))
        form = RegisterForm()
        if form.validate_on_submit():
            if User.query.filter_by(email=form.email.data).first():
                flash('Email taken', 'danger')
                return render_template('register.html', form=form)
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Account created!', 'success')
            return redirect(url_for('login'))
        return render_template('register.html', form=form)
    except Exception as e:
        logger.error(f"Reg error: {e}")
        return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Unauthorized', 'danger')
        return redirect(url_for('index'))
    mods = Mod.query.all()
    categories = Category.query.all()
    users = User.query.all()
    stats = {
        'total_mods': len(mods),
        'total_users': len(users),
        'total_downloads': sum(m.download_count for m in mods),
        'total_categories': len(categories)
    }
    return render_template('admin/dashboard.html', mods=mods, categories=categories, users=users, stats=stats)

@app.route('/admin/mod/new', methods=['GET', 'POST'])
@login_required
def admin_new_mod():
    if not current_user.is_admin: return redirect(url_for('index'))
    # Minimal implementation to satisfy routing
    return "New Mod Form - Coming Soon"

@app.route('/admin/mod/edit/<int:mod_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_mod(mod_id):
    if not current_user.is_admin: return redirect(url_for('index'))
    return f"Edit Mod {mod_id} - Coming Soon"

@app.route('/admin/mod/delete/<int:mod_id>', methods=['POST'])
@login_required
def admin_delete_mod(mod_id):
    if not current_user.is_admin: return redirect(url_for('index'))
    return "Delete Mod - Coming Soon"

@app.route('/admin/category/new', methods=['GET', 'POST'])
@login_required
def admin_new_category():
    if not current_user.is_admin: return redirect(url_for('index'))
    return "New Category Form - Coming Soon"

@app.route('/admin/category/delete/<int:cat_id>', methods=['POST'])
@login_required
def admin_delete_category(cat_id):
    if not current_user.is_admin: return redirect(url_for('index'))
    return "Delete Category - Coming Soon"

@app.route('/settings')
@login_required
def settings():
    return "Settings page - Coming Soon"

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Database Initialization
def init_db():
    try:
        with app.app_context():
            db.create_all()
            if not User.query.filter_by(email='admin@mydispatcher.com').first():
                admin = User(username='admin', email='admin@mydispatcher.com', is_admin=True)
                admin.set_password('admin123')
                db.session.add(admin)
            if not Category.query.first():
                for n in ['Vehicles', 'Scripts', 'Maps', 'Weapons', 'Characters', 'Graphics']:
                    db.session.add(Category(name=n))
            db.session.commit()
            logger.info("DB Ready")
    except Exception as e:
        logger.error(f"DB Init Fatal: {e}")

# init_db() # Moved inside main block or handled externally to avoid issues during module imports

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
