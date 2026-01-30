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
    user_rank = db.Column(db.String(50), default='Player')
    badge_color = db.Column(db.String(20), default='secondary')
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

@app.before_request
def handle_db_session():
    # Ensure a clean transaction for each request
    # SQLAlchemy naturally manages this, but this serves as a safeguard
    pass

@app.teardown_appcontext
def shutdown_session(exception=None):
    if exception:
        db.session.rollback()
    db.session.remove()

class ModForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Description', validators=[DataRequired()])
    version = StringField('Version', validators=[Length(max=50)])
    category_id = SelectField('Category', coerce=int, validators=[DataRequired()])
    is_featured = BooleanField('Featured Mod')

@app.route('/')
def index():
    try:
        featured_mods = Mod.query.filter_by(is_featured=True).limit(6).all()
        latest_mods = Mod.query.order_by(Mod.created_at.desc()).limit(8).all()
        categories = Category.query.all()
        return render_template('index.html', featured_mods=featured_mods, latest_mods=latest_mods, categories=categories)
    except Exception as e:
        db.session.rollback()
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
        db.session.rollback()
        logger.error(f"Browse error: {e}")
        return redirect(url_for('index'))

@app.route('/download/<int:mod_id>')
def download_page(mod_id):
    try:
        mod = Mod.query.get_or_404(mod_id)
        return render_template('download.html', mod=mod)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Download page error: {e}")
        return redirect(url_for('index'))

@app.route('/download/file/<int:mod_id>')
def download_file(mod_id):
    try:
        mod = Mod.query.get_or_404(mod_id)
        mod.download_count += 1
        db.session.commit()
        
        # Clean path logic
        directory = os.path.join(app.root_path, 'uploads', 'mods')
        filename = os.path.basename(mod.file_path)
        return send_from_directory(directory, filename, as_attachment=True)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Download file error: {e}")
        return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/comment/delete/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    try:
        comment = Comment.query.get_or_404(comment_id)
        if not current_user.is_admin and current_user.id != comment.user_id:
            flash('Unauthorized', 'danger')
            return redirect(url_for('index'))
        mod_id = comment.mod_id
        db.session.delete(comment)
        db.session.commit()
        flash('Comment deleted', 'success')
        return redirect(url_for('mod_detail', mod_id=mod_id))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Comment delete error: {e}")
        return redirect(url_for('index'))

@app.route('/mod/<int:mod_id>', methods=['GET', 'POST'])
def mod_detail(mod_id):
    try:
        logger.info(f"Accessing mod_detail for mod_id: {mod_id}")
        mod = Mod.query.get_or_404(mod_id)
        form = CommentForm()
        if form.validate_on_submit() and current_user.is_authenticated:
            comment = Comment(content=form.content.data, user_id=current_user.id, mod_id=mod.id)
            db.session.add(comment)
            db.session.commit()
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': True})
            flash('Comment added!', 'success')
            return redirect(url_for('mod_detail', mod_id=mod.id))
        
        related = Mod.query.filter(Mod.category_id == mod.category_id, Mod.id != mod.id).limit(4).all()
        return render_template('mod_detail.html', mod=mod, related_mods=related, form=form)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Detail error for mod {mod_id}: {e}")
        return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if current_user.is_authenticated: return redirect(url_for('index'))
        form = LoginForm()
        if form.validate_on_submit():
            logger.info(f"Login attempt for email: {form.email.data}")
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                logger.info(f"User found: {user.username}")
                if user.check_password(form.password.data):
                    logger.info(f"Password correct for user: {user.username}")
                    login_user(user)
                    flash('Welcome back!', 'success')
                    return redirect(url_for('index'))
                else:
                    logger.warning(f"Invalid password for user: {user.username}")
            else:
                logger.warning(f"No user found with email: {form.email.data}")
            flash('Invalid credentials', 'danger')
        return render_template('login.html', form=form)
    except Exception as e:
        db.session.rollback()
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
        db.session.rollback()
        logger.error(f"Reg error: {e}")
        return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    try:
        logout_user()
    except Exception as e:
        logger.error(f"Logout error: {e}")
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    try:
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
    except Exception as e:
        db.session.rollback()
        logger.error(f"Admin dashboard error: {e}")
        return redirect(url_for('index'))

@app.route('/admin/mod/new', methods=['GET', 'POST'])
@login_required
def admin_new_mod():
    try:
        if not current_user.is_admin: return redirect(url_for('index'))
        form = ModForm()
        form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
        
        if form.validate_on_submit():
            mod_file = request.files.get('mod_file')
            image_file = request.files.get('image')
            video_file = request.files.get('video')
            
            if not mod_file or not image_file:
                flash('Mod file and cover image are required', 'danger')
                return render_template('admin/mod_form.html', form=form, title='Add New Mod')
            
            # Save files
            mod_filename = secure_filename(f"{uuid.uuid4()}_{mod_file.filename}")
            image_filename = secure_filename(f"{uuid.uuid4()}_{image_file.filename}")
            
            mod_path = os.path.join(app.config['UPLOAD_FOLDER'], 'mods', mod_filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'images', image_filename)
            
            mod_file.save(mod_path)
            image_file.save(image_path)
            
            video_path = None
            if video_file and video_file.filename:
                video_filename = secure_filename(f"{uuid.uuid4()}_{video_file.filename}")
                video_path = os.path.join(app.config['UPLOAD_FOLDER'], 'videos', video_filename)
                video_file.save(video_path)
            
            new_mod = Mod(
                title=form.title.data,
                description=form.description.data,
                version=form.version.data,
                category_id=form.category_id.data,
                is_featured=form.is_featured.data,
                file_path=mod_path,
                image_path=image_path,
                video_path=video_path,
                download_token=str(uuid.uuid4())
            )
            
            db.session.add(new_mod)
            db.session.commit()
            flash('Mod published successfully!', 'success')
            return redirect(url_for('admin'))
            
        return render_template('admin/mod_form.html', form=form, title='Add New Mod')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding mod: {e}")
        flash('An error occurred while saving the mod', 'danger')
        return redirect(url_for('admin'))

@app.route('/admin/mod/edit/<int:mod_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_mod(mod_id):
    try:
        if not current_user.is_admin: return redirect(url_for('index'))
        mod = Mod.query.get_or_404(mod_id)
        form = ModForm(obj=mod)
        form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
        
        if form.validate_on_submit():
            mod.title = form.title.data
            mod.description = form.description.data
            mod.version = form.version.data
            mod.category_id = form.category_id.data
            mod.is_featured = form.is_featured.data
            
            mod_file = request.files.get('mod_file')
            image_file = request.files.get('image')
            video_file = request.files.get('video')
            
            if mod_file and mod_file.filename:
                mod_filename = secure_filename(f"{uuid.uuid4()}_{mod_file.filename}")
                mod_path = os.path.join(app.config['UPLOAD_FOLDER'], 'mods', mod_filename)
                mod_file.save(mod_path)
                mod.file_path = mod_path
                
            if image_file and image_file.filename:
                image_filename = secure_filename(f"{uuid.uuid4()}_{image_file.filename}")
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'images', image_filename)
                image_file.save(image_path)
                mod.image_path = image_path
                
            if video_file and video_file.filename:
                video_filename = secure_filename(f"{uuid.uuid4()}_{video_file.filename}")
                video_path = os.path.join(app.config['UPLOAD_FOLDER'], 'videos', video_filename)
                video_file.save(video_path)
                mod.video_path = video_path
            
            db.session.commit()
            flash('Mod updated successfully!', 'success')
            return redirect(url_for('admin'))
            
        return render_template('admin/mod_form.html', form=form, title='Edit Mod', mod=mod)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating mod: {e}")
        flash('An error occurred while updating the mod', 'danger')
        return redirect(url_for('admin'))

@app.route('/admin/mod/delete/<int:mod_id>', methods=['POST'])
@login_required
def admin_delete_mod(mod_id):
    try:
        if not current_user.is_admin: return redirect(url_for('index'))
        mod = Mod.query.get_or_404(mod_id)
        db.session.delete(mod)
        db.session.commit()
        flash('Mod deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting mod: {e}")
        flash('Error deleting mod', 'danger')
    return redirect(url_for('admin'))

@app.route('/admin/category/new', methods=['GET', 'POST'])
@login_required
def admin_new_category():
    try:
        if not current_user.is_admin: return redirect(url_for('index'))
        if request.method == 'POST':
            name = request.form.get('name')
            description = request.form.get('description')
            if name:
                cat = Category(name=name, description=description)
                db.session.add(cat)
                db.session.commit()
                flash('Category added!', 'success')
                return redirect(url_for('admin'))
        return render_template('admin/category_form.html')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Cat error: {e}")
        flash('Error adding category', 'danger')
        return redirect(url_for('admin'))

@app.route('/admin/category/delete/<int:cat_id>', methods=['POST'])
@login_required
def admin_delete_category(cat_id):
    try:
        if not current_user.is_admin: return redirect(url_for('index'))
        cat = Category.query.get_or_404(cat_id)
        db.session.delete(cat)
        db.session.commit()
        flash('Category deleted', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Cat delete error: {e}")
        flash('Error deleting category', 'danger')
    return redirect(url_for('admin'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    try:
        if request.method == 'POST':
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if new_password and new_password == confirm_password:
                current_user.set_password(new_password)
                db.session.commit()
                flash('Password updated successfully!', 'success')
                return redirect(url_for('settings'))
            flash('Passwords do not match or are empty', 'danger')
            
        return render_template('settings.html')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Settings error: {e}")
        return redirect(url_for('index'))

@app.route('/admin/user/update/<int:user_id>', methods=['POST'])
@login_required
def update_user_rank(user_id):
    try:
        if not current_user.is_admin: return redirect(url_for('index'))
        user = User.query.get_or_404(user_id)
        user.user_rank = request.form.get('rank', 'Player')
        user.badge_color = request.form.get('badge_color', 'secondary')
        db.session.commit()
        flash(f'Updated {user.username}\'s rank', 'success')
        return redirect(url_for('admin'))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating user rank: {e}")
        flash('Error updating user rank', 'danger')
        return redirect(url_for('admin'))

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
