import os
from flask import Flask, render_template, redirect, url_for, flash, request, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'mydispatcher-secret-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

os.makedirs('uploads/mods', exist_ok=True)
os.makedirs('uploads/images', exist_ok=True)
os.makedirs('uploads/videos', exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

class ModForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Description', validators=[DataRequired()])
    version = StringField('Version', validators=[Length(max=50)])
    category_id = SelectField('Category', coerce=int)
    is_featured = BooleanField('Featured')

class CategoryForm(FlaskForm):
    name = StringField('Category Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description')

class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired(), Length(min=1, max=1000)])

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])

class ChangeEmailForm(FlaskForm):
    new_email = StringField('New Email', validators=[DataRequired(), Email()])
    password = PasswordField('Current Password', validators=[DataRequired()])

@app.route('/')
def index():
    featured_mods = Mod.query.filter_by(is_featured=True).limit(6).all()
    latest_mods = Mod.query.order_by(Mod.created_at.desc()).limit(8).all()
    categories = Category.query.all()
    total_users = User.query.count()
    return render_template('index.html', featured_mods=featured_mods, latest_mods=latest_mods, categories=categories, total_users=total_users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        flash('Invalid email or password', 'error')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered', 'error')
            return render_template('register.html', form=form)
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already taken', 'error')
            return render_template('register.html', form=form)
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/browse')
def browse():
    page = request.args.get('page', 1, type=int)
    category_id = request.args.get('category', type=int)
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'latest')
    
    query = Mod.query
    
    if category_id:
        query = query.filter_by(category_id=category_id)
    
    if search:
        query = query.filter(Mod.title.ilike(f'%{search}%') | Mod.description.ilike(f'%{search}%'))
    
    if sort == 'popular':
        query = query.order_by(Mod.download_count.desc())
    elif sort == 'oldest':
        query = query.order_by(Mod.created_at.asc())
    else:
        query = query.order_by(Mod.created_at.desc())
    
    mods = query.paginate(page=page, per_page=12, error_out=False)
    categories = Category.query.all()
    
    return render_template('browse.html', mods=mods, categories=categories, 
                         current_category=category_id, search=search, sort=sort)

@app.route('/mod/<int:mod_id>', methods=['GET', 'POST'])
def mod_detail(mod_id):
    mod = Mod.query.get_or_404(mod_id)
    form = CommentForm()
    
    if form.validate_on_submit() and current_user.is_authenticated:
        comment = Comment(
            content=form.content.data,
            user_id=current_user.id,
            mod_id=mod.id
        )
        db.session.add(comment)
        db.session.commit()
        flash('Comment added successfully!', 'success')
        return redirect(url_for('mod_detail', mod_id=mod_id))
    
    related_mods = Mod.query.filter(Mod.category_id == mod.category_id, Mod.id != mod.id).limit(4).all()
    return render_template('mod_detail.html', mod=mod, related_mods=related_mods, form=form)

@app.route('/comment/delete/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if current_user.id == comment.user_id or current_user.is_admin:
        mod_id = comment.mod_id
        db.session.delete(comment)
        db.session.commit()
        flash('Comment deleted', 'success')
        return redirect(url_for('mod_detail', mod_id=mod_id))
    flash('Permission denied', 'error')
    return redirect(url_for('index'))

@app.route('/download/<int:mod_id>')
def download_page(mod_id):
    mod = Mod.query.get_or_404(mod_id)
    token = str(uuid.uuid4())
    mod.download_token = token
    db.session.commit()
    return render_template('download.html', mod=mod, token=token)

@app.route('/download-file/<int:mod_id>/<token>')
def download_file(mod_id, token):
    mod = Mod.query.get_or_404(mod_id)
    if mod.download_token != token:
        flash('Invalid download link', 'error')
        return redirect(url_for('mod_detail', mod_id=mod_id))
    
    mod.download_count += 1
    mod.download_token = None
    db.session.commit()
    
    if mod.file_path:
        directory = os.path.dirname(mod.file_path)
        filename = os.path.basename(mod.file_path)
        return send_from_directory(directory, filename, as_attachment=True)
    
    flash('File not found', 'error')
    return redirect(url_for('mod_detail', mod_id=mod_id))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    mods = Mod.query.order_by(Mod.created_at.desc()).all()
    categories = Category.query.all()
    users = User.query.all()
    
    stats = {
        'total_mods': len(mods),
        'total_users': len(users),
        'total_downloads': sum(m.download_count for m in mods),
        'total_categories': len(categories)
    }
    
    return render_template('admin/dashboard.html', mods=mods, categories=categories, 
                         users=users, stats=stats)

@app.route('/admin/mod/new', methods=['GET', 'POST'])
@login_required
def admin_new_mod():
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    form = ModForm()
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
    
    if form.validate_on_submit():
        mod = Mod(
            title=form.title.data,
            description=form.description.data,
            version=form.version.data,
            category_id=form.category_id.data,
            is_featured=form.is_featured.data
        )
        
        if 'mod_file' in request.files:
            file = request.files['mod_file']
            if file and file.filename:
                filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
                filepath = os.path.join('uploads/mods', filename)
                file.save(filepath)
                mod.file_path = filepath
        
        if 'image' in request.files:
            image = request.files['image']
            if image and image.filename:
                filename = secure_filename(f"{uuid.uuid4()}_{image.filename}")
                filepath = os.path.join('uploads/images', filename)
                image.save(filepath)
                mod.image_path = filepath
        
        if 'video' in request.files:
            video = request.files['video']
            if video and video.filename:
                filename = secure_filename(f"{uuid.uuid4()}_{video.filename}")
                filepath = os.path.join('uploads/videos', filename)
                video.save(filepath)
                mod.video_path = filepath
        
        db.session.add(mod)
        db.session.commit()
        flash('Mod created successfully!', 'success')
        return redirect(url_for('admin'))
    
    return render_template('admin/mod_form.html', form=form, title='Add New Mod')

@app.route('/admin/mod/edit/<int:mod_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_mod(mod_id):
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    mod = Mod.query.get_or_404(mod_id)
    form = ModForm(obj=mod)
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
    
    if form.validate_on_submit():
        mod.title = form.title.data
        mod.description = form.description.data
        mod.version = form.version.data
        mod.category_id = form.category_id.data
        mod.is_featured = form.is_featured.data
        
        if 'mod_file' in request.files:
            file = request.files['mod_file']
            if file and file.filename:
                filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
                filepath = os.path.join('uploads/mods', filename)
                file.save(filepath)
                mod.file_path = filepath
        
        if 'image' in request.files:
            image = request.files['image']
            if image and image.filename:
                filename = secure_filename(f"{uuid.uuid4()}_{image.filename}")
                filepath = os.path.join('uploads/images', filename)
                image.save(filepath)
                mod.image_path = filepath
        
        if 'video' in request.files:
            video = request.files['video']
            if video and video.filename:
                filename = secure_filename(f"{uuid.uuid4()}_{video.filename}")
                filepath = os.path.join('uploads/videos', filename)
                video.save(filepath)
                mod.video_path = filepath
        
        db.session.commit()
        flash('Mod updated successfully!', 'success')
        return redirect(url_for('admin'))
    
    return render_template('admin/mod_form.html', form=form, mod=mod, title='Edit Mod')

@app.route('/admin/mod/delete/<int:mod_id>', methods=['POST'])
@login_required
def admin_delete_mod(mod_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    mod = Mod.query.get_or_404(mod_id)
    db.session.delete(mod)
    db.session.commit()
    flash('Mod deleted successfully!', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/category/new', methods=['GET', 'POST'])
@login_required
def admin_new_category():
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    form = CategoryForm()
    if form.validate_on_submit():
        category = Category(name=form.name.data, description=form.description.data)
        db.session.add(category)
        db.session.commit()
        flash('Category created successfully!', 'success')
        return redirect(url_for('admin'))
    
    return render_template('admin/category_form.html', form=form, title='Add Category')

@app.route('/admin/category/delete/<int:cat_id>', methods=['POST'])
@login_required
def admin_delete_category(cat_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    category = Category.query.get_or_404(cat_id)
    db.session.delete(category)
    db.session.commit()
    flash('Category deleted successfully!', 'success')
    return redirect(url_for('admin'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    password_form = ChangePasswordForm(prefix='password')
    email_form = ChangeEmailForm(prefix='email')
    
    if request.method == 'POST':
        if 'password-submit' in request.form:
            if password_form.validate_on_submit():
                if current_user.check_password(password_form.current_password.data):
                    current_user.set_password(password_form.new_password.data)
                    db.session.commit()
                    flash('Password updated successfully!', 'success')
                    return redirect(url_for('settings'))
                else:
                    flash('Current password is incorrect', 'error')
        elif 'email-submit' in request.form:
            if email_form.validate_on_submit():
                if current_user.check_password(email_form.password.data):
                    if User.query.filter_by(email=email_form.new_email.data).first():
                        flash('Email already in use', 'error')
                    else:
                        current_user.email = email_form.new_email.data
                        db.session.commit()
                        flash('Email updated successfully!', 'success')
                        return redirect(url_for('settings'))
                else:
                    flash('Password is incorrect', 'error')
    
    return render_template('settings.html', password_form=password_form, email_form=email_form)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory('uploads', filename)

def init_db():
    with app.app_context():
        db.create_all()
        
        if not User.query.filter_by(email='admin@mydispatcher.com').first():
            admin = User(
                username='admin',
                email='admin@mydispatcher.com',
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
        
        if not Category.query.first():
            categories = [
                Category(name='Vehicles', description='Cars, bikes, planes and more'),
                Category(name='Scripts', description='Game scripts and modifications'),
                Category(name='Maps', description='Custom maps and locations'),
                Category(name='Weapons', description='Custom weapons and tools'),
                Category(name='Characters', description='Player skins and NPCs'),
                Category(name='Graphics', description='Visual enhancements and textures')
            ]
            for cat in categories:
                db.session.add(cat)
        
        db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
