from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from app import db, bcrypt
from app.models.user import User

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username', '').strip()).first()
        if user and bcrypt.check_password_hash(user.password, request.form.get('password', '')):
            login_user(user)
            if not user.password_changed:
                return redirect(url_for('auth.change_password'))
            return redirect(url_for('main.dashboard'))
        flash('Invalid credentials.', 'error')
    return render_template('auth/login.html')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if request.form.get('confirm_password', '') != password:
            flash('Passwords do not match.', 'error')
            return render_template('auth/register.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('auth/register.html')
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
            return render_template('auth/register.html')
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('auth/register.html')
        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed, password_changed=True)
        db.session.add(user)
        db.session.commit()
        login_user(User.query.filter_by(username=username).first())
        return redirect(url_for('main.dashboard'))
    return render_template('auth/register.html')


@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')
        if len(new_password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('auth/change_password.html')
        if new_password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('auth/change_password.html')
        current_user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        current_user.password_changed = True
        db.session.commit()
        flash('Password updated successfully.', 'success')
        return redirect(url_for('main.dashboard'))
    return render_template('auth/change_password.html')


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
