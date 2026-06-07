from app import db, login_manager
from flask_login import UserMixin
from datetime import datetime


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(128), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    password_changed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    daily_ai_calls = db.Column(db.Integer, default=0)
    last_ai_reset = db.Column(db.Date, default=datetime.utcnow().date)
    hunts = db.relationship('HuntSession', backref='user', lazy=True)

    def reset_daily_limit_if_needed(self):
        today = datetime.utcnow().date()
        if self.last_ai_reset != today:
            self.daily_ai_calls = 0
            self.last_ai_reset = today
            db.session.commit()


class HuntSession(db.Model):
    __tablename__ = 'hunt_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    apt_id = db.Column(db.String(32), nullable=False)
    apt_name = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(32), default='research')
    hypothesis_text = db.Column(db.Text)
    ttp_mapping = db.Column(db.Text)
    hypothesis_submitted = db.Column(db.Boolean, default=False)
    research_notes = db.Column(db.Text)
    hints_used = db.Column(db.Integer, default=0)
    current_question = db.Column(db.Integer, default=0)
    overall_score = db.Column(db.Float)
    overall_feedback = db.Column(db.Text)
    hypothesis_score = db.Column(db.Float)
    ttp_score = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    answers = db.relationship('HuntAnswer', backref='session', lazy=True)
    hunt_doc = db.relationship('HuntDocument', backref='session', uselist=False, lazy=True)


class HuntAnswer(db.Model):
    __tablename__ = 'hunt_answers'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('hunt_sessions.id'), nullable=False)
    question_id = db.Column(db.String(64), nullable=False)
    phase = db.Column(db.String(16))
    question_text = db.Column(db.Text)
    answer_text = db.Column(db.Text)
    spl_query = db.Column(db.Text)
    score = db.Column(db.Float)
    feedback = db.Column(db.Text)
    answered_at = db.Column(db.DateTime, default=datetime.utcnow)


class HuntDocument(db.Model):
    __tablename__ = 'hunt_documents'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('hunt_sessions.id'), nullable=False)
    analyst_name = db.Column(db.String(128))
    hunt_title = db.Column(db.String(256))
    executive_summary = db.Column(db.Text)
    data_sources = db.Column(db.Text)
    timeline = db.Column(db.Text)
    confirmed_ttps = db.Column(db.Text)
    visibility_gaps = db.Column(db.Text)
    detection_rules = db.Column(db.Text)
    recommendations = db.Column(db.Text)
    doc_score = db.Column(db.Float)
    doc_feedback = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
