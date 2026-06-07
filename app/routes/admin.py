from flask import Blueprint, render_template, redirect, url_for, flash, jsonify, request
from flask_login import login_required, current_user
from app.models.user import User, HuntSession
from app import db

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
api_bp = Blueprint('api', __name__, url_prefix='/api')


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required.', 'error')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    return decorated


@admin_bp.route('/')
@login_required
@admin_required
def index():
    users = User.query.order_by(User.created_at.desc()).all()
    total_hunts = HuntSession.query.count()
    completed_hunts = HuntSession.query.filter_by(status='complete').count()
    total_ai_calls = sum(u.daily_ai_calls for u in users)
    return render_template('admin/index.html',
                           users=users,
                           total_hunts=total_hunts,
                           completed_hunts=completed_hunts,
                           total_ai_calls=total_ai_calls)


@admin_bp.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('Cannot delete admin account.', 'error')
        return redirect(url_for('admin.index'))
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} deleted.', 'success')
    return redirect(url_for('admin.index'))


@api_bp.route('/status')
def status():
    return jsonify({'status': 'operational', 'service': 'GHOSTTRACE'})
