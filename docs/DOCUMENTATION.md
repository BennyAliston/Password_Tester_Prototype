# Password Tester Web Application — Documentation

## Table of Contents
1. [Introduction](#introduction)
2. [System Overview](#system-overview)
3. [Architecture & Workflow](#architecture--workflow)
4. [Feature Details](#feature-details)
5. [How It Works: End-to-End Flow](#how-it-works-end-to-end-flow)
6. [Setup & Installation](#setup--installation)
7. [Usage Guide](#usage-guide)
8. [Custom Dictionary Upload](#custom-dictionary-upload)
9. [Security & Privacy](#security--privacy)
10. [Accessibility & Responsiveness](#accessibility--responsiveness)
11. [Deployment](#deployment)
12. [Troubleshooting](#troubleshooting)
13. [Contributing](#contributing)
14. [License](#license)

---

## 1. Introduction
The Password Tester is a Django-based web application that helps users analyze password strength, check for breaches, and generate strong passwords. It is designed for educational and ethical use, offering advanced feedback and security insights.

## 2. System Overview
- **Backend:** Python 3, Django 5.x
- **Frontend:** HTML5, CSS3, JavaScript (zxcvbn via CDN)
- **Database:** SQLite (default) — supports PostgreSQL/MySQL
- **External APIs/Libraries:** HaveIBeenPwned (via `pwnedpasswords` k-anonymity library)
- **Async Processing (optional):** Celery workers with Redis broker/result backend
- **Caching:** Django cache framework (with thread-safe in-process fallback)

## 3. Architecture & Workflow
- **MVC Pattern:**
  - **Models:** `DisallowedWord` with a case-insensitive uniqueness constraint to prevent case-duplicates.
  - **Views:** Form-based password analysis, secure dictionary uploads, async status endpoint `hibp_status` for polling.
  - **Templates:** Render UI, wire client-side polling, and accessibility.
- **Frontend:**
  - zxcvbn.js (via CDN) for real-time strength estimation and UX feedback.
  - JavaScript polls the server for HIBP status using a short-lived server-generated token (no client SHA1).
- **Backend:**
  - Validates inputs using Django forms; stores only SHA-256 hashes of recently tested passwords in session.
  - Processes custom dictionary uploads with deduplication and bulk insert under a transaction; ignores conflicts.
  - Performs HIBP checks synchronously or enqueues Celery tasks when available.
  - Caches HIBP results keyed by `hibp:<sha1>` for fast subsequent responses.
- **Security:**
  - Plaintext passwords are never persisted or logged.
  - HIBP integration uses k-anonymity via the installed library; client never sends raw SHA1.

## 4. Feature Details
### 4.1 Password Strength Meter
- Uses zxcvbn.js for advanced strength estimation (entropy, feedback, and score from 0–4).
- Visual strength bar updates in real time as you type.
- Policy checklist shows which requirements are met (length, uppercase, number, symbol).
- Entropy (bits) is displayed for technical users.

### 4.2 Password Breach Check
- Checks if the password has appeared in known data breaches using HaveIBeenPwned via the `pwnedpasswords` library.
- The server computes SHA-1, looks up via k-anonymity, and caches results. The client receives a short-lived token to poll status; the raw SHA1 is not exposed to the client.
- Shows a warning if the password is found in a breach, with actionable advice.

### 4.3 Password Generator
- Customizable generator lets users choose length (8–32), and include/exclude uppercase, lowercase, numbers, and symbols.
- Generates a random password meeting the selected criteria.
- Suggested password can be copied to clipboard.

### 4.4 Clipboard Copy Feedback
- All copy buttons trigger a floating “Copied!” toast notification for instant feedback.
- Works for both user-entered and generated passwords.

### 4.5 Custom Dictionary Upload
- Upload a `.txt` file with disallowed words/phrases (one per line), with a server-enforced size limit.
- Uploads are deduplicated and inserted in bulk inside a database transaction; conflicts are ignored.
- Entries are case-insensitive unique to prevent duplicates and are used during password analysis.

### 4.6 Accessibility & Responsiveness
- All interactive elements have ARIA labels.
- Keyboard navigation is fully supported.
- Responsive design ensures usability on desktop and mobile devices.

## 5. How It Works: End-to-End Flow
1. **User visits the app:** The main page loads with the password input, strength meter, and breach-check status UI.
2. **Password Entry:**
   - zxcvbn.js analyzes in real time and updates the UI.
   - The server computes SHA-1 and checks cache. If needed, it triggers a background HIBP lookup (Celery) or performs a synchronous check.
   - A short-lived token mapped to the internal SHA1 is returned to the client to poll `hibp_status`.
3. **Async Polling:**
   - Client polls the `hibp_status` endpoint with the token.
   - When the cache has the result, the server returns the breach count.
4. **Password Generator:** User configures options and generates a strong password suggestion.
5. **Clipboard:** User copies passwords and receives a toast confirmation.
6. **Custom Dictionary Upload:** User uploads a `.txt` file; the server deduplicates and bulk-inserts entries transactionally.
7. **Accessibility & Mobile:** Full keyboard/screen-reader support and responsive layout.

## 6. Setup & Installation
See the [README.md](README.md) for full instructions. Summary:
- Create a virtualenv, install dependencies, run migrations:
  - `python manage.py makemigrations`
  - `python manage.py migrate`
- Optional async setup: install Redis, configure Celery (`CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`), and start a worker:
  - `celery -A password_tester worker -l info`

## 7. Usage Guide
- **Analyze Password:** Enter a password and click Analyze. View strength, entropy, and breach status (breach result may arrive asynchronously).
- **Compare Passwords:** Use the compare field for side-by-side analysis.
- **Password Generator:** Customize options and generate a strong password.
- **Clipboard:** Copy any password with a single click ("Copied!" toast appears).
- **Custom Dictionary:** Upload a `.txt` file of disallowed words/phrases (one per line). Large files may be rejected if they exceed the configured limit.

## 8. Custom Dictionary Upload
- Go to the “Upload Custom Disallowed Words/Phrases” section.
- Select a `.txt` file and click “Upload Dictionary.”
- Each word/phrase will be added to your database and checked against all future passwords.

## 9. Security & Privacy
- Plaintext passwords are never stored or logged.
- Only SHA-256 hashes of recent password history are kept in session for reuse detection.
- HIBP checks use k-anonymity through a server-side library; the client never sends the SHA1 hash.
- Custom dictionaries are stored in the database and enforced with case-insensitive uniqueness.
- Production recommendations (see `password_tester/settings.py`):
  - `SESSION_COOKIE_SECURE=True`, `CSRF_COOKIE_SECURE=True`, `SECURE_HSTS_SECONDS`, `SECURE_SSL_REDIRECT=True`, `DEBUG=False`, `SECRET_KEY` via environment.
- **Do not use real passwords in this demo.**

## 10. Accessibility & Responsiveness
- All interactive elements have ARIA labels.
- Keyboard navigation is supported.
- Responsive design for desktop and mobile.

## 11. Deployment
- Recommended platforms: Render, Railway, Fly.io, or a VPS.
- Environment variables to set: `SECRET_KEY`, `DEBUG=False`, `ALLOWED_HOSTS`, database URL, cache/Redis URLs, Celery broker/result backend.
- Steps: Push to GitHub, connect to host, deploy, run migrations, start workers, set up custom domain/HTTPS.

## 12. Troubleshooting
- **Server won’t start:** Check dependencies and migrations.
- **Breach check pending forever:** Ensure Redis is running and a Celery worker is started; otherwise the app will fall back to synchronous checks.
- **Redis/Celery connection errors:** Verify `CELERY_BROKER_URL` and `CELERY_RESULT_BACKEND` environment variables.
- **Cache not updating:** Verify Django cache backend configuration or rely on in-process fallback for development.
- **Password not analyzed:** Ensure required fields are filled and CSRF token is valid.
- **Dictionary upload fails:** Check file format (plain text, one per line) and size limits.

## 13. Testing & CI
- Run tests locally with `pytest -q` (see `pwdchecker/tests_forms.py` for examples: upload size rejection, hashed history reuse prevention, bulk upload behavior).
- A GitHub Actions workflow at `.github/workflows/ci.yml` installs dependencies, runs format/lint, and executes tests.

## 14. Contributing
- Fork the repo, make changes (with tests), and submit a pull request.
- Open issues for bugs or feature requests.

## 15. License
- For educational and ethical use only. See LICENSE for details.

---

**Questions?** Open an issue or contact the maintainer.
