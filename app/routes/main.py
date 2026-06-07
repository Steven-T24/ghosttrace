from flask import Blueprint, render_template, redirect, url_for, current_app
from flask_login import login_required, current_user
from app.models.user import HuntSession
from app.services.apt_loader import list_profiles
from app.services.misp_service import check_misp_connection

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    from flask_login import current_user
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@main_bp.route('/dashboard')
@login_required
def dashboard():
    profiles = list_profiles()
    active_hunt = HuntSession.query.filter_by(user_id=current_user.id).filter(
        HuntSession.status != 'complete').order_by(HuntSession.created_at.desc()).first()
    completed_hunts = HuntSession.query.filter_by(
        user_id=current_user.id, status='complete').order_by(HuntSession.completed_at.desc()).all()
    misp_online = check_misp_connection(
        current_app.config.get('MISP_URL'), current_app.config.get('MISP_KEY'))
    return render_template('main/dashboard.html', profiles=profiles,
                           active_hunt=active_hunt, completed_hunts=completed_hunts,
                           misp_online=misp_online)
