# Cybersecurity Detection Framework (mini-project-s6)

An automated framework for detecting **exposed sensitive data** and **government-impersonation websites** on the public internet, with built-in reporting to India's CERT-In. Built with FastAPI.

> Educational / defensive-security project. Intended for authorized research and responsible disclosure only.

---

## Overview

The system uses search-engine dorking, document analysis, and pattern matching to surface two classes of online threats, then helps generate responsible-disclosure reports to the relevant authorities.

- **Module 1 — Sensitive Data Detection:** Discovers leaked documents (PDF, DOC/DOCX, LOG, TXT) containing Indian identity data — Aadhaar, PAN, voter ID, passport numbers — and reports findings to CERT-In.
- **Module 2 — Government Impersonation Detection:** Identifies fraudulent sites spoofing Indian government services and generates abuse reports for malicious domains.

## Features

- Automated Google-dork search with API key rotation
- Document downloading + text extraction (PDF, Word, HTML, OCR for images)
- Regex + contextual pattern matching with confidence scoring
- Wayback Machine archival lookup for discovered URLs
- Asynchronous, long-running scans with status polling and cancellation
- HTML email reports delivered over SMTP to disclosure contacts
- SQLite persistence for scans, findings, reports, and audit logs

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI, Uvicorn, Pydantic |
| Database | SQLAlchemy 2.x, SQLite (aiosqlite) |
| Search | SerpAPI (`google-search-results`) |
| Documents | pdfminer.six, python-docx, BeautifulSoup/lxml, Pillow, pytesseract |
| HTTP | requests, aiohttp, httpx |
| Security utils | pyOpenSSL, cryptography, dnspython, python-Levenshtein |
| Frontend | HTML / CSS / JavaScript (`static/`) |

## Architecture

```
Frontend (static/)  ──REST──▶  FastAPI (main.py)
                                   │
        ┌──────────────────────────┼───────────────────────────┐
        ▼                          ▼                           ▼
 google_search.py        document_processor.py        *_detector.py
 (dork + key rotation)   (extract text / OCR)         (pattern match + score)
        │                          │                           │
        └──────────► wayback_fetcher.py ◄────────┐             │
                                                 ▼             ▼
                                          database.py     email_reporter.py
                                          (SQLite)        (SMTP → CERT-In)
```

| File | Responsibility |
|------|----------------|
| `main.py` | FastAPI app, routes, background scan orchestration |
| `config.py` | Settings & environment variables, detection patterns |
| `models.py` | Pydantic request/response schemas |
| `database.py` | SQLite persistence (scans, leaks, reports, audit logs) |
| `google_search.py` | Search API calls with multi-key rotation |
| `document_processor.py` | Format detection + text extraction (incl. OCR) |
| `sensitive_data_detector.py` | Aadhaar/PAN/bank pattern detection + scoring |
| `government_impersonation_detector.py` | Spoofed-domain / impersonation detection |
| `wayback_fetcher.py` | Retrieves archived URL snapshots |
| `email_reporter.py` | Builds HTML reports, sends via SMTP |

## Prerequisites

- Python 3.8+
- `pip`
- Internet connection (for search APIs)
- A SerpAPI key
- A Gmail account with an **App Password** (for email reporting)
- *(Optional)* Tesseract OCR installed locally if you need image OCR via `pytesseract`

## Installation

```bash
git clone https://github.com/progprnv/mini-project-s6.git
cd mini-project-s6

# (recommended) create a virtual environment
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the project root:

```env
# Search
SERPAPI_KEY=your_serpapi_key

# Email reporting (Gmail App Password, not your login password)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_EMAIL=you@gmail.com
SMTP_PASSWORD=your_16_char_app_password
CERT_IN_EMAIL=vdisclose@cert-in.org.in

# Database / server
DATABASE_URL=sqlite+aiosqlite:///./app.db
DEBUG=True
HOST=0.0.0.0
PORT=8000

# Tuning
MAX_SEARCH_PAGES_PER_QUERY=2
MAX_PARALLEL_URL_WORKERS=6
```

> **Gmail App Password:** enable 2-Step Verification, then Google Account → Security → App Passwords → generate a password for "Mail". Use that 16-character value as `SMTP_PASSWORD`.

The SQLite database is created automatically on first launch.

## Running

```bash
python main.py
```

The app starts at **http://localhost:8000**. Interactive API docs are available at **http://localhost:8000/docs**.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan/sensitive-data` | Start a sensitive-data scan |
| POST | `/api/scan/government-impersonation` | Start an impersonation-detection scan |
| GET | `/api/scan/{scan_id}/status` | Get scan progress / results |
| POST | `/api/scan/{scan_id}/stop` | Stop an in-progress scan |
| POST | `/api/scan/send-report` | Email findings to CERT-In |
| POST | `/api/scan/send-abuse-report` | Report an impersonation site |
| DELETE | `/api/scan/{scan_id}` | Delete a scan and its data |
| GET | `/api/config/status` | Verify API/configuration status |

## Documentation

- [SETUP.md](SETUP.md) — detailed setup instructions
- [ARCHITECTURE.md](ARCHITECTURE.md) — system design and data flow
- [TESTING.md](TESTING.md) — testing notes

## Disclaimer

This project is for **educational and authorized defensive-security research** only. Use it solely on data and systems you are permitted to assess, and follow responsible-disclosure practices. The authors are not responsible for misuse.

## License

Add a license of your choice (e.g., MIT) in a `LICENSE` file.
