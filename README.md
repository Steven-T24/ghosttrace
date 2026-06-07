# GHOSTTRACE

**Adversary Emulation & Threat Hunting Training Platform**

GHOSTTRACE is a structured threat hunting training platform that simulates realistic adversary activity across cloud and endpoint environments. It guides analysts through a hypothesis-driven investigation methodology aligned to the [ThreatHunter Playbook](https://threathunterplaybook.com), with AI-powered assessment of the complete hunt at the end of each session.

---

## Live Demo

🔗 **[ghosttrace-w1jo.onrender.com](https://ghosttrace-w1jo.onrender.com)**

> **Note:** The hosted version runs on Render's free tier. If the service has been idle, the first page load may take 30–50 seconds to wake up. This is normal — just wait and it will load.

---

## What is GHOSTTRACE?

GHOSTTRACE is a training tool for SOC analysts and threat hunters. Each hunt session follows a structured six-stage workflow:

1. **Select** an APT group from the dashboard
2. **Research** the group using authoritative threat intelligence references (MITRE ATT&CK, CISA, Mandiant, The DFIR Report)
3. **Form a hypothesis** and map ATT&CK techniques based on your research
4. **Download generated logs** and ingest them into your Splunk instance
5. **Investigate** through a structured set of questions following the Plan → Execute → Report methodology
6. **Document** your findings and submit for AI assessment

At the end of each hunt, a single Gemini AI call assesses your hypothesis, TTP mapping, all investigation answers, and your hunt documentation — returning scored feedback across every dimension.

---

## APT Groups

| Group | Attribution | Environment | Questions |
|-------|------------|-------------|-----------|
| APT29 | Russia (SVR) | AWS + Endpoints | 16 |
| APT28 | Russia (GRU) | Endpoints | 17 |
| APT41 | China (MSS) | GCP + Endpoints | 16 |
| Lazarus Group | DPRK | AWS + Endpoints | 16 |
| UNC3944 | Financial | Azure + Endpoints | 16 |

---

## Features

- **Realistic log generation** — CloudTrail, Azure AD, GCP Audit, Sysmon, Windows Event Logs
- **Structured investigation** — 16–17 questions per APT following ThreatHunter Playbook methodology
- **Research notepad** — capture IOCs and notes during research, visible throughout the hunt
- **Guiding prompts** — expandable hints on each question without revealing answers
- **AI hint system** — on-demand directional hints (3 per session)
- **Hunt documentation** — structured report template populated throughout the investigation
- **AI assessment** — single Gemini API call reviews the entire hunt at completion
- **Export** — portfolio-ready HTML hunt report
- **MISP integration** — surfaces relevant threat intel events from a local MISP instance (local deployment only)

---

## Tech Stack

- **Backend:** Python 3.11, Flask, SQLAlchemy, SQLite
- **Frontend:** HTML/CSS/JS (dark theme)
- **AI Engine:** Google Gemini 2.0 Flash (free tier — 1,500 requests/day)
- **Server:** Gunicorn

---

## Local Deployment

GHOSTTRACE is designed to run locally alongside a Splunk instance. Full deployment instructions are available in the Technical Documentation.

### Requirements

- Python 3.11+
- Splunk (for log ingestion and investigation)
- Google Gemini API key (free at [aistudio.google.com](https://aistudio.google.com))

### Quick Start

```bash
git clone https://github.com/Steven-T24/ghosttrace.git
cd ghosttrace
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
python3 run.py
```

Navigate to `http://localhost:5000`

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SECRET_KEY` | Flask session signing key | Yes |
| `GEMINI_API_KEY` | Google AI Studio API key | Yes |
| `MISP_URL` | Local MISP instance URL | No |
| `MISP_KEY` | MISP user API key | No |
| `DATABASE_URL` | SQLite path | Yes |
| `LOCAL_MODE` | `true` for local, `false` for hosted | Yes |
| `DAILY_AI_LIMIT` | Max AI calls per user per day (default 20) | No |
| `HINTS_PER_SESSION` | Max hints per hunt (default 3) | No |
| `ADMIN_USERNAME` | Admin account username | No |
| `ADMIN_PASSWORD` | Admin account password | No |

---

## Design Philosophy

GHOSTTRACE does not give analysts the answers. It provides:

- A realistic scenario and references to authoritative threat intelligence
- Generated telemetry that reflects the adversary's actual tradecraft
- Structured questions that guide the investigation without revealing findings
- AI assessment that evaluates reasoning quality, not just factual accuracy

Analysts must research the threat intel, form their own hypothesis, investigate the data, and document their findings — mirroring the real-world threat hunting process.

---

## Part of the DEADFUSE Ecosystem

GHOSTTRACE is part of a wider homelab threat hunting and malware analysis pipeline including Splunk, CAPE sandbox, Caldera C2, Arkime, and DEADFUSE static analysis.

---

## Disclaimer

GHOSTTRACE generates synthetic log data for training purposes only. All IP addresses, domain names, hostnames, and usernames in generated datasets are fictional. No real threat actor infrastructure is referenced or contacted.
