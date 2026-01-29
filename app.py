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

# Database Connection with Safety Wrapper
def configure_database(app):
    try:
        # Check for DATABASE_URL first
        uri = os.environ.get('DATABASE_URL')
        
        # If DATABASE_URL is missing or suspicious (like "localhost"), use individual PG variables
        if not uri or "localhost" in uri:
            pg_user = os.environ.get('PGUSER')
            pg_pass = os.environ.get('PGPASSWORD')
            pg_host = os.environ.get('PGHOST')
            pg_port = os.environ.get('PGPORT')
            pg_db = os.environ.get('PGDATABASE')
            
            if all([pg_user, pg_pass, pg_host, pg_port, pg_db]):
                uri = f"postgresql://{pg_user}:{pg_pass}@{pg_host}:{pg_port}/{pg_db}"
                logger.info(f"Using PostgreSQL from individual environment variables")
        
        if uri and uri.strip() and "localhost" not in uri:
            # Handle Render's postgres:// format
            if uri.startswith("postgres://"):
                uri = uri.replace("postgres://", "postgresql://", 1)
            logger.info(f"Configuring database with remote URI")
            return uri
        else:
            logger.warning("No remote DATABASE_URL found or it points to localhost. Falling back to local SQLite database.")
            basedir = os.path.abspath(os.path.dirname(__file__))
            db_path = os.path.join(basedir, "mydispatcher.db")
            return f"sqlite:///{db_path}"
    except Exception as e:
        logger.error(f"CRITICAL: Failed to parse DATABASE_URL: {e}")
        basedir = os.path.abspath(os.path.dirname(__file__))
        db_path = os.path.join(basedir, "mydispatcher.db")
        return f"sqlite:///{db_path}"

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
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    mods = db.relationship('Mod', backref='category', lazy=True)

class Mod(db.Model):
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
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mod_id = db.Column(db.Integer, db.ForeignKey('mod.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='comments')

# Replit Auth Integration
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
        logger.error(f"Error loading user {user_id}: {e}")
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

class ModForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Description', validators=[DataRequired()])
    version = StringField('Version', validators=[Length(max=50)])
    category_id = SelectField('Category', coerce=int)
    is_featured = BooleanField('Featured')

# Routes
@app.route('/')
def index():
    try:
        featured_mods = Mod.query.filter_by(is_featured=True).limit(6).all()
        latest_mods = Mod.query.order_by(Mod.created_at.desc()).limit(8).all()
        categories = Category.query.all()
        return render_template('index.html', featured_mods=featured_mods, latest_mods=latest_mods, categories=categories)
    except Exception as e:
        logger.error(f"Index route error: {e}")
        return "Critical system error - Please check console logs.", 500

@app.route('/browse')
def browse():
    try:
        page = request.args.get('page', 1, type=int)
        category_id = request.args.get('category', type=int)
        search = request.args.get('search', '')
        sort = request.args.get('sort', 'latest')
        
        query = Mod.query
        if category_id: query = query.filter_by(category_id=category_id)
        if search: query = query.filter(Mod.title.ilike(f'%{search}%') | Mod.description.ilike(f'%{search}%'))
        
        if sort == 'popular': query = query.order_by(Mod.download_count.desc())
        elif sort == 'oldest': query = query.order_by(Mod.created_at.asc())
        else: query = query.order_by(Mod.created_at.desc())
        
        mods = query.paginate(page=page, per_page=12, error_out=False)
        categories = Category.query.all()
        return render_template('browse.html', mods=mods, categories=categories, 
                             current_category=category_id, search=search, sort=sort)
    except Exception as e:
        logger.error(f"Browse error: {e}")
        return redirect(url_for('index'))

@app.route('/mod/<int:mod_id>')
def mod_detail(mod_id):
    try:
        mod = Mod.query.get_or_404(mod_id)
        form = CommentForm()
        related_mods = Mod.query.filter(Mod.category_id == mod.category_id, Mod.id != mod.id).limit(4).all()
        return render_template('mod_detail.html', mod=mod, related_mods=related_mods, form=form)
    except Exception as e:
        logger.error(f"Mod detail error: {e}")
        return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if current_user.is_authenticated:
            return redirect(url_for('index'))
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
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        form = RegisterForm()
        if form.validate_on_submit():
            if User.query.filter_by(email=form.email.data).first():
                flash('Email already registered', 'danger')
                return render_template('register.html', form=form)
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Account created! You can now login.', 'success')
            return redirect(url_for('login'))
        return render_template('register.html', form=form)
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/download/<int:mod_id>')
def download_page(mod_id):
    try:
        mod = Mod.query.get_or_404(mod_id)
        token = str(uuid.uuid4())
        mod.download_token = token
        db.session.commit()
        return render_template('download.html', mod=mod, token=token)
    except Exception as e:
        logger.error(f"Download page error: {e}")
        return redirect(url_for('index'))

@app.route('/download-file/<int:mod_id>/<token>')
def download_file(mod_id, token):
    try:
        mod = Mod.query.get_or_404(mod_id)
        if mod.download_token != token:
            flash('Invalid token', 'danger')
            return redirect(url_for('mod_detail', mod_id=mod_id))
        mod.download_count = (mod.download_count or 0) + 1
        db.session.commit()
        if mod.file_path:
            return send_from_directory(os.path.dirname(os.path.abspath(mod.file_path)), os.path.basename(mod.file_path), as_attachment=True)
        return redirect(url_for('mod_detail', mod_id=mod_id))
    except Exception as e:
        logger.error(f"Download file error: {e}")
        return redirect(url_for('index'))

# Database Initialization
def init_db_safely():
    try:
        with app.app_context():
            db.create_all()
            if not User.query.filter_by(email='admin@mydispatcher.com').first():
                admin = User(username='admin', email='admin@mydispatcher.com', is_admin=True)
                admin.set_password('admin123')
                db.session.add(admin)
            if not Category.query.first():
                for name in ['Vehicles', 'Scripts', 'Maps', 'Weapons', 'Characters', 'Graphics']:
                    db.session.add(Category(name=name))
            db.session.commit()
            logger.info("Database system ready.")
    except Exception as e:
        logger.error(f"FATAL: Database initialization failed: {e}")

if __name__ == '__main__':
    init_db_safely()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
