import os
import json
import urllib.request
import urllib.error

GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
GEMINI_MODEL = 'gemini-2.0-flash'
GEMINI_URL = f'https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent'


def _call(system: str, user: str) -> str:
    if not GEMINI_API_KEY:
        return '{"error": "No API key configured"}'
    payload = json.dumps({
        'system_instruction': {'parts': [{'text': system}]},
        'contents': [{'parts': [{'text': user}]}],
        'generationConfig': {'maxOutputTokens': 2000, 'temperature': 0.3}
    }).encode('utf-8')
    req = urllib.request.Request(
        f'{GEMINI_URL}?key={GEMINI_API_KEY}',
        data=payload,
        headers={'Content-Type': 'application/json'}
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data['candidates'][0]['content']['parts'][0]['text']
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8')
        return f'{{"error": "HTTP {e.code}: {body[:300]}"}}'
    except Exception as e:
        return f'{{"error": "{str(e)}"}}'


def _parse(raw: str, fallback: dict) -> dict:
    try:
        clean = raw.strip().strip('```json').strip('```').strip()
        return json.loads(clean)
    except Exception:
        fallback['raw_feedback'] = raw
        return fallback


def full_hunt_assessment(apt_profile: dict, hypothesis: str, ttp_mapping: str,
                          answers: list, doc: dict) -> dict:
    """
    Single API call that assesses the entire hunt in one go.
    Returns scores and feedback for all dimensions plus overall performance summary.
    """
    system = """You are an expert threat hunting instructor performing a comprehensive assessment
of a completed threat hunt. Evaluate all aspects and return a single JSON response.
Return valid JSON only, no markdown, no preamble.
Format:
{
  "hypothesis_score": float,
  "hypothesis_feedback": str,
  "ttp_score": float,
  "ttp_feedback": str,
  "investigation_scores": [{"question_id": str, "score": float, "feedback": str}],
  "investigation_avg": float,
  "doc_score": float,
  "doc_feedback": str,
  "overall_score": float,
  "grade": str,
  "summary": str,
  "strengths": list,
  "areas_for_improvement": list,
  "recommended_next_steps": list
}
Grade must be one of: Excellent / Good / Developing / Needs Work
overall_score is weighted: hypothesis 20%, ttp_mapping 20%, investigation 45%, documentation 15%"""

    answers_text = '\n'.join([
        f"Q{i+1} [{a.get('phase','').upper()}]: {a.get('question_text','')[:80]}\n"
        f"Answer: {a.get('answer_text','')[:200]}\n"
        f"SPL: {a.get('spl_query','') or 'None'}"
        for i, a in enumerate(answers)
    ])

    user = f"""APT Group: {apt_profile['display_name']} ({apt_profile.get('attribution','')})
Known correct TTPs: {', '.join(apt_profile.get('correct_ttps', []))}

=== HYPOTHESIS ===
{hypothesis}

=== TTP MAPPING ===
{ttp_mapping}

=== INVESTIGATION ANSWERS ({len(answers)} questions) ===
{answers_text}

=== HUNT DOCUMENT ===
Executive Summary: {doc.get('executive_summary','Not provided')[:300]}
Timeline: {doc.get('timeline','Not provided')[:300]}
Confirmed TTPs: {doc.get('confirmed_ttps','Not provided')[:200]}
Visibility Gaps: {doc.get('visibility_gaps','Not provided')[:200]}
Detection Rules: {doc.get('detection_rules','Not provided')[:200]}
Recommendations: {doc.get('recommendations','Not provided')[:200]}

Assess all dimensions comprehensively. For investigation_scores, include one entry per question
using the question index as question_id (q1, q2, q3 etc)."""

    raw = _call(system, user)
    return _parse(raw, {
        'hypothesis_score': 0, 'hypothesis_feedback': 'Assessment unavailable.',
        'ttp_score': 0, 'ttp_feedback': '',
        'investigation_scores': [], 'investigation_avg': 0,
        'doc_score': 0, 'doc_feedback': '',
        'overall_score': 0, 'grade': 'Developing',
        'summary': 'Assessment unavailable.',
        'strengths': [], 'areas_for_improvement': [], 'recommended_next_steps': []
    })


def generate_hint(apt_profile: dict, phase: str, question: str) -> str:
    system = "You are a threat hunting instructor. Provide a brief directional hint without revealing the answer. Maximum 3 sentences. Plain text only."
    user = f"APT Group: {apt_profile['display_name']}\nPhase: {phase}\nQuestion: {question}\nProvide a hint."
    return _call(system, user)
