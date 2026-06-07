from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os

load_dotenv()

db = SQLAlchemy()
login_manager = LoginManager()
bcrypt = Bcrypt()


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-me')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:////opt/ghosttrace/ghosttrace.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['LOCAL_MODE'] = os.getenv('LOCAL_MODE', 'true').lower() == 'true'
    app.config['DAILY_AI_LIMIT'] = int(os.getenv('DAILY_AI_LIMIT', 20))
    app.config['HINTS_PER_SESSION'] = int(os.getenv('HINTS_PER_SESSION', 3))
    app.config['MISP_URL'] = os.getenv('MISP_URL', 'https://10.10.10.80')
    app.config['MISP_KEY'] = os.getenv('MISP_KEY', '')

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Authentication required.'

    from app.routes.auth import auth_bp
    from app.routes.main import main_bp
    from app.routes.hunt import hunt_bp
    from app.routes.admin import admin_bp, api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(hunt_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)

    with app.app_context():
        db.create_all()
        _seed_admin(app)

    return app


def _seed_admin(app):
    from app.models.user import User
    admin_username = os.getenv('ADMIN_USERNAME', 'admin')
    if not User.query.filter_by(username=admin_username).first():
        admin_pw = os.getenv('ADMIN_PASSWORD', 'changeme')
        hashed = bcrypt.generate_password_hash(admin_pw).decode('utf-8')
        admin = User(username=admin_username, email='admin@ghosttrace.local',
                     password=hashed, is_admin=True)
        db.session.add(admin)
        db.session.commit()
