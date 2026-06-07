from flask import (Blueprint, render_template, redirect, url_for,
                   request, flash, current_app, send_file, jsonify)
from flask_login import login_required, current_user
from app import db
from app.models.user import HuntSession, HuntAnswer, HuntDocument
from app.services.apt_loader import load_profile
from app.services.log_generator import generate_index_file
from app.services.misp_service import get_misp_summary
from app.services import ai_assessment
import json, os, io
from datetime import datetime

hunt_bp = Blueprint('hunt', __name__, url_prefix='/hunt')
QUESTIONS_DIR = os.path.join(os.path.dirname(__file__), '../../data/question_banks')


def _load_questions(apt_id):
    path = os.path.join(QUESTIONS_DIR, f'{apt_id}_questions.json')
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return sorted(json.load(f), key=lambda x: x['order'])


def _check_ai_limit():
    current_user.reset_daily_limit_if_needed()
    return current_user.daily_ai_calls < current_app.config.get('DAILY_AI_LIMIT', 20)


def _inc_ai():
    current_user.daily_ai_calls += 1
    db.session.commit()


@hunt_bp.route('/start/<apt_id>', methods=['POST'])
@login_required
def start(apt_id):
    profile = load_profile(apt_id)
    if not profile:
        flash('Unknown APT group.', 'error')
        return redirect(url_for('main.dashboard'))
    HuntSession.query.filter_by(user_id=current_user.id).filter(
        HuntSession.status != 'complete').delete()
    db.session.commit()
    s = HuntSession(user_id=current_user.id, apt_id=apt_id,
                    apt_name=profile['display_name'], status='research')
    db.session.add(s)
    db.session.commit()
    return redirect(url_for('hunt.research', session_id=s.id))


@hunt_bp.route('/<int:session_id>/quit', methods=['POST'])
@login_required
def quit_hunt(session_id):
    s = HuntSession.query.get_or_404(session_id)
    if s.user_id != current_user.id:
        return redirect(url_for('main.dashboard'))
    db.session.delete(s)
    db.session.commit()
    flash('Hunt abandoned.', 'success')
    return redirect(url_for('main.dashboard'))


@hunt_bp.route('/<int:session_id>/research', methods=['GET', 'POST'])
@login_required
def research(session_id):
    s = HuntSession.query.get_or_404(session_id)
    if s.user_id != current_user.id:
        return redirect(url_for('main.dashboard'))
    profile = load_profile(s.apt_id)
    misp = get_misp_summary(s.apt_id, profile['display_name'],
                            current_app.config.get('MISP_URL'),
                            current_app.config.get('MISP_KEY'))
    if request.method == 'POST':
        s.research_notes = request.form.get('research_notes', '')
        db.session.commit()
        flash('Notes saved.', 'success')
    return render_template('hunt/research.html', session=s, profile=profile, misp=misp)


@hunt_bp.route('/<int:session_id>/hypothesis', methods=['GET', 'POST'])
@login_required
def hypothesis(session_id):
    s = HuntSession.query.get_or_404(session_id)
    if s.user_id != current_user.id:
        return redirect(url_for('main.dashboard'))
    profile = load_profile(s.apt_id)
    if request.method == 'POST':
        hyp = request.form.get('hypothesis', '').strip()
        ttp = request.form.get('ttp_mapping', '').strip()
        if not hyp or not ttp:
            flash('Please complete both fields.', 'error')
            return render_template('hunt/hypothesis.html', session=s, profile=profile)
        s.hypothesis_text = hyp
        s.ttp_mapping = ttp
        s.hypothesis_submitted = True
        s.status = 'ingestion'
        db.session.commit()
        flash('Hypothesis submitted. Proceed to log ingestion.', 'success')
        return redirect(url_for('hunt.ingestion', session_id=s.id))
    return render_template('hunt/hypothesis.html', session=s, profile=profile)


@hunt_bp.route('/<int:session_id>/ingestion')
@login_required
def ingestion(session_id):
    s = HuntSession.query.get_or_404(session_id)
    if s.user_id != current_user.id:
        return redirect(url_for('main.dashboard'))
    if not s.hypothesis_submitted:
        flash('You must submit your hypothesis first.', 'error')
        return redirect(url_for('hunt.hypothesis', session_id=s.id))
    return render_template('hunt/ingestion.html', session=s, profile=load_profile(s.apt_id))


@hunt_bp.route('/<int:session_id>/download-logs')
@login_required
def download_logs(session_id):
    s = HuntSession.query.get_or_404(session_id)
    if s.user_id != current_user.id:
        return redirect(url_for('main.dashboard'))
    buf = io.BytesIO(generate_index_file(s.apt_id).encode('utf-8'))
    buf.seek(0)
    return send_file(buf, as_attachment=True,
                     download_name=f'ghosttrace_{s.apt_id}_logs.json',
                     mimetype='application/json')


@hunt_bp.route('/<int:session_id>/ingestion/confirm', methods=['POST'])
@login_required
def confirm_ingestion(session_id):
    s = HuntSession.query.get_or_404(session_id)
    if s.user_id != current_user.id:
        return redirect(url_for('main.dashboard'))
    s.status = 'investigation'
    db.session.commit()
    return redirect(url_for('hunt.investigate', session_id=s.id))


@hunt_bp.route('/<int:session_id>/investigate')
@login_required
def investigate(session_id):
    s = HuntSession.query.get_or_404(session_id)
    if s.user_id != current_user.id:
        return redirect(url_for('main.dashboard'))
    profile = load_profile(s.apt_id)
    questions = _load_questions(s.apt_id)
    idx = s.current_question
    total = len(questions)
    if idx >= total:
        s.status = 'documentation'
        db.session.commit()
        return redirect(url_for('hunt.documentation', session_id=s.id))
    q = questions[idx]
    hints_limit = current_app.config.get('HINTS_PER_SESSION', 3)
    return render_template('hunt/investigate.html', session=s, profile=profile,
                           question=q, question_num=idx + 1, total=total,
                           progress=int((idx / total) * 100),
                           hints_remaining=hints_limit - s.hints_used)


@hunt_bp.route('/<int:session_id>/investigate/submit', methods=['POST'])
@login_required
def submit_answer(session_id):
    s = HuntSession.query.get_or_404(session_id)
    if s.user_id != current_user.id:
        return redirect(url_for('main.dashboard'))
    questions = _load_questions(s.apt_id)
    idx = int(request.form.get('question_index', 0))
    if idx >= len(questions):
        return redirect(url_for('hunt.documentation', session_id=s.id))
    q = questions[idx]
    answer_text = request.form.get('answer', '').strip()
    spl_query = request.form.get('spl_query', '').strip()
    existing = next((a for a in s.answers if a.question_id == q['id']), None)
    if existing:
        existing.answer_text = answer_text
        existing.spl_query = spl_query
    else:
        db.session.add(HuntAnswer(
            session_id=s.id, question_id=q['id'], phase=q['phase'],
            question_text=q['question'], answer_text=answer_text,
            spl_query=spl_query))
    s.current_question = idx + 1
    db.session.commit()
    return redirect(url_for('hunt.investigate', session_id=s.id))


@hunt_bp.route('/<int:session_id>/hint', methods=['POST'])
@login_required
def get_hint(session_id):
    s = HuntSession.query.get_or_404(session_id)
    if s.user_id != current_user.id:
        return jsonify({'hint': 'Access denied'})
    limit = current_app.config.get('HINTS_PER_SESSION', 3)
    if s.hints_used >= limit:
        return jsonify({'hint': 'No hints remaining.', 'hints_remaining': 0})
    if not _check_ai_limit():
        return jsonify({'hint': 'Daily AI limit reached.', 'hints_remaining': 0})
    profile = load_profile(s.apt_id)
    questions = _load_questions(s.apt_id)
    q_index = int(request.json.get('question_index', 0))
    q = questions[q_index]
    hint = ai_assessment.generate_hint(profile, q['phase'], q['question'])
    s.hints_used += 1
    _inc_ai()
    db.session.commit()
    return jsonify({'hint': hint, 'hints_remaining': limit - s.hints_used})


@hunt_bp.route('/<int:session_id>/documentation', methods=['GET', 'POST'])
@login_required
def documentation(session_id):
    s = HuntSession.query.get_or_404(session_id)
    if s.user_id != current_user.id:
        return redirect(url_for('main.dashboard'))
    profile = load_profile(s.apt_id)
    if not s.hunt_doc:
        db.session.add(HuntDocument(session_id=s.id,
                                    hunt_title=f'{s.apt_name} Threat Hunt',
                                    analyst_name=current_user.username))
        db.session.commit()
    doc = s.hunt_doc
    if request.method == 'POST':
        doc.analyst_name = request.form.get('analyst_name', current_user.username)
        doc.hunt_title = request.form.get('hunt_title', '')
        doc.executive_summary = request.form.get('executive_summary', '')
        doc.data_sources = request.form.get('data_sources', '')
        doc.timeline = request.form.get('timeline', '')
        doc.confirmed_ttps = request.form.get('confirmed_ttps', '')
        doc.visibility_gaps = request.form.get('visibility_gaps', '')
        doc.detection_rules = request.form.get('detection_rules', '')
        doc.recommendations = request.form.get('recommendations', '')
        db.session.commit()
        if 'submit_final' in request.form:
            return redirect(url_for('hunt.final_assessment', session_id=s.id))
        flash('Documentation saved.', 'success')
    return render_template('hunt/documentation.html', session=s, profile=profile, doc=doc)


@hunt_bp.route('/<int:session_id>/assessment')
@login_required
def final_assessment(session_id):
    s = HuntSession.query.get_or_404(session_id)
    if s.user_id != current_user.id:
        return redirect(url_for('main.dashboard'))
    profile = load_profile(s.apt_id)
    doc = s.hunt_doc
    answers = s.answers

    result = {}
    if _check_ai_limit():
        answers_data = [{'phase': a.phase, 'question_text': a.question_text,
                         'answer_text': a.answer_text, 'spl_query': a.spl_query}
                        for a in answers]
        doc_data = {k: getattr(doc, k) for k in [
            'executive_summary', 'data_sources', 'timeline',
            'confirmed_ttps', 'visibility_gaps', 'detection_rules', 'recommendations'
        ]} if doc else {}
        result = ai_assessment.full_hunt_assessment(
            profile, s.hypothesis_text or '', s.ttp_mapping or '',
            answers_data, doc_data)
        _inc_ai()

        # Apply scores back to answers
        inv_scores = result.get('investigation_scores', [])
        for i, a in enumerate(answers):
            key = f'q{i+1}'
            score_entry = next((x for x in inv_scores if x.get('question_id') == key), None)
            if score_entry:
                a.score = score_entry.get('score', 0)
                a.feedback = score_entry.get('feedback', '')

        if doc:
            doc.doc_score = result.get('doc_score', 0)
            doc.doc_feedback = result.get('doc_feedback', '')

        s.hypothesis_score = result.get('hypothesis_score', 0)
        s.ttp_score = result.get('ttp_score', 0)
        s.overall_score = result.get('overall_score', 0)
        s.overall_feedback = result.get('summary', '')
        db.session.commit()

    s.status = 'complete'
    s.completed_at = datetime.utcnow()
    db.session.commit()

    return render_template('hunt/assessment.html', session=s, profile=profile,
                           doc=doc, result=result, answers=answers)


@hunt_bp.route('/<int:session_id>/export')
@login_required
def export(session_id):
    s = HuntSession.query.get_or_404(session_id)
    if s.user_id != current_user.id:
        return redirect(url_for('main.dashboard'))
    profile = load_profile(s.apt_id)
    html = render_template('hunt/export.html', session=s, profile=profile,
                           doc=s.hunt_doc, answers=s.answers, now=datetime.utcnow())
    buf = io.BytesIO(html.encode('utf-8'))
    buf.seek(0)
    return send_file(buf, as_attachment=True,
                     download_name=f'GHOSTTRACE_{s.apt_id}_hunt_report.html',
                     mimetype='text/html')
