# Password Tester

A comprehensive web application for password security analysis, strength testing, and breach checking. Built with Django, featuring advanced security measures, asynchronous processing, and robust testing infrastructure.

## 🚀 Features

### Core Functionality
- **Password Strength Analysis** — Real-time strength meter using zxcvbn algorithm
- **Breach Detection** — Integration with HaveIBeenPwned API using k-anonymity for privacy
- **Password Generator** — Strong password generation with customizable options
- **Custom Dictionary** — Upload and manage custom disallowed word lists
- **Password History** — Secure hashed storage of previously tested passwords

### Generation & Tools
- **Passphrase Generator** — Diceware-style passphrases from a built-in 1,300-word list with configurable word count, separator, and capitalization
- **Password Scoring History** — Session-based trend chart tracking zxcvbn scores across analyses (canvas-drawn, no external charting library)
- **Bulk Password Audit** — Analyze up to 100 passwords at once via textarea or file upload; returns a table with scores, labels, and suggestions

### Advanced Features
- **Asynchronous Processing** — Celery-based background tasks for HIBP checks
- **Intelligent Caching** — Multi-layer caching system for performance optimization
- **Secure Token System** — Server-side token mapping for safe client polling
- **Retry Logic** — Exponential backoff for network resilience
- **Form Validation** — Comprehensive input validation and security checks

## 🛠️ Quick Start

### Prerequisites
- Python 3.8+
- Virtual environment (recommended)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd password_tester_prototype
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # Linux/Mac
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run database migrations**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

5. **Start the development server**
   ```bash
   python manage.py runserver
   ```

6. **Access the application**
   Open your browser at `http://127.0.0.1:8000/`

## 🔧 Advanced Setup (Optional)

### Asynchronous HIBP Processing

For enhanced performance with large-scale usage:

1. **Install Redis** (broker for Celery)
   ```bash
   # Windows: Use WSL or Docker
   # Linux/Mac: Use package manager
   ```

2. **Configure Celery settings** in `password_tester/settings.py`:
   ```python
   CELERY_BROKER_URL = 'redis://localhost:6379/0'
   CELERY_RESULT_BACKEND = 'redis://localhost:6379/1'
   ```

3. **Start Celery worker**
   ```bash
   celery -A password_tester worker -l info
   ```

### Production Configuration

Set these environment variables for production:

```bash
SECRET_KEY=your-secure-secret-key
DEBUG=False
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
SECURE_HSTS_SECONDS=31536000
SECURE_SSL_REDIRECT=True
```

## 📋 Usage

### Basic Password Analysis
1. Enter a password in the strength meter
2. View real-time strength analysis and recommendations
3. Check breach status (may require polling for async results)

### Passphrase Generator
1. Navigate to the **Passphrase** section
2. Adjust word count (3–10), separator, and capitalization
3. Click **Generate** for a Diceware-style passphrase with entropy readout
4. Copy to clipboard with one click

### Bulk Password Audit
1. Navigate to the **Bulk Audit** section
2. Paste passwords (one per line) or upload a `.txt` file (max 1 MB, 100 passwords)
3. Click **Audit Passwords** to get a table of scores, strength labels, and suggestions

### Scoring History
- Every password analyzed in the main analyzer is scored and tracked in your session
- View the trend chart in the **Scoring History** section
- Clear history at any time with the **Clear History** button

### Custom Dictionary Management
1. Upload a `.txt` file with disallowed words (max 2MB)
2. Words are automatically deduplicated and case-normalized
3. Use the delete button to clear custom dictionary

### Password Generation
1. Use the password generator for secure alternatives
2. Copy generated passwords to clipboard
3. Customize generation parameters as needed

## 🧪 Testing

### Run Test Suite
```bash
# Install test dependencies
pip install -r requirements.txt

# Run all tests (Django)
python manage.py test pwdchecker.tests -v2

# Run all tests (pytest)
pytest -q

# Run with coverage
pytest --cov=pwdchecker

# Run a specific test module
pytest pwdchecker/tests/test_forms.py -v
pytest pwdchecker/tests/test_utils.py -v
pytest pwdchecker/tests/test_views.py -v
```

### Code Quality Checks
```bash
# Format code
black .

# Lint code
flake8 .

# Type checking
mypy .
```

## 🏗️ Architecture

### Key Components

- **Models** (`pwdchecker/models.py`)
  - `DisallowedWord` with case-insensitive unique constraints
  - Secure password history storage

- **Forms** (`pwdchecker/forms.py`)
  - `PasswordCheckForm` for password validation
  - `CustomDictUploadForm` with size limits and validation
  - `PassphraseForm` for passphrase generation options
  - `BulkAuditForm` for bulk password analysis input

- **Views** (`pwdchecker/views.py`)
  - Form-based password checking
  - Secure file upload handling
  - AJAX endpoints for async operations
  - `generate_passphrase_view` — Diceware passphrase API
  - `bulk_audit_view` — bulk password scoring API
  - `score_history_view` / `clear_score_history_view` — session score management

- **Utils** (`pwdchecker/utils.py`)
  - HIBP integration with k-anonymity
  - Retry logic with exponential backoff
  - Multi-layer caching system
  - `generate_passphrase()` — cryptographically secure word selection
  - `quick_score()` — lightweight zxcvbn-only scoring for bulk use

- **Tasks** (`pwdchecker/tasks.py`)
  - Celery tasks for background processing
  - HIBP result caching

### Security Features

- **Password Hashing** - SHA-256 for session storage
- **Token-based Polling** - Server-side token mapping prevents SHA1 exposure
- **Input Validation** - Comprehensive form validation and sanitization
- **File Upload Security** - Size limits and content validation
- **CSRF Protection** - Built-in Django CSRF protection

## 🔄 Async Processing Flow

1. **Password Submission** - User enters password for analysis
2. **Immediate Response** - Basic analysis returned instantly
3. **Background Processing** - HIBP check queued if needed
4. **Client Polling** - JavaScript polls for HIBP results
5. **Result Display** - Breach information displayed when ready

## 📁 Project Structure

```
Password_Tester_Prototype/
├── manage.py                     # Django management script
├── requirements.txt              # Python dependencies
├── pyproject.toml                # Project metadata & tool config
├── build.sh                      # Production build script
├── render.yaml                   # Render.com deployment config
├── conftest.py                   # Shared pytest fixtures
├── README.md
├── LICENSE
├── docs/
│   └── DOCUMENTATION.md          # Detailed project documentation
├── .github/workflows/
│   └── ci.yml                    # CI/CD pipeline
├── password_tester/              # Django project settings
│   ├── settings.py
│   ├── urls.py
│   ├── celery.py
│   ├── wsgi.py
│   └── asgi.py
└── pwdchecker/                   # Main application
    ├── apps.py
    ├── models.py                 # Database models
    ├── forms.py                  # Form definitions
    ├── views.py                  # View functions & AJAX endpoints
    ├── urls.py                   # App URL routing
    ├── utils.py                  # Utility functions & algorithms
    ├── tasks.py                  # Celery background tasks
    ├── data/
    │   ├── common_passwords.txt  # Common password dictionary
    │   └── diceware_words.txt    # Passphrase word list (~1,300 words)
    ├── static/pwdchecker/
    │   ├── main.js               # Client-side interactivity
    │   ├── styles.css            # Application styles
    │   └── vendor/               # Third-party static assets
    ├── templates/pwdchecker/
    │   └── index.html            # Main single-page template
    ├── tests/
    │   ├── test_forms.py         # Form & view integration tests
    │   ├── test_utils.py         # Utility function unit tests
    │   └── test_views.py         # View integration tests
    └── migrations/               # Database migrations
```

## 🚀 Deployment

### Environment Variables
```bash
SECRET_KEY=your-secret-key
DEBUG=False
ALLOWED_HOSTS=your-domain.com
DATABASE_URL=your-database-url
REDIS_URL=your-redis-url
```

### Production Checklist
- [ ] Set `DEBUG=False`
- [ ] Configure secure cookies
- [ ] Set up SSL/TLS
- [ ] Configure HSTS headers
- [ ] Set up Redis for caching
- [ ] Configure Celery workers
- [ ] Set up monitoring and logging

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## 📄 License

For educational and ethical use only. Do not use with real passwords in production without proper security review.

## 👨‍💻 Author

Kritagya Kumar (Benny Aliston)

## 🔄 Recent Updates

### Version 2.1 (16-02-2026)

**New Features:**
- Diceware-style **Passphrase Generator** with configurable word count, separator, and capitalization
- **Password Scoring History** — session-based trend chart drawn on canvas
- **Bulk Password Audit** — analyze up to 100 passwords via textarea or file upload

**Project Restructuring:**
- Moved data files to `pwdchecker/data/` (was `pwdchecker/pwdchecker/`)
- Moved templates into app directory (`pwdchecker/templates/pwdchecker/`)
- Organized tests into `pwdchecker/tests/` package with `test_` prefix convention
- Added `docs/` folder for project documentation
- Added `static/pwdchecker/vendor/` for third-party static assets
- Fixed HTML template linter errors by replacing inline Django variables with `data-*` attributes

### Version 2.0 (13-10-2025)

**Security Enhancements:**
- Added case-insensitive unique constraints on dictionary words
- Implemented secure password history with SHA-256 hashing
- Added server-side token mapping for safe client polling
- Enhanced form validation with upload size limits

**Performance Improvements:**
- Asynchronous HIBP processing with Celery
- Multi-layer caching system (Django cache + in-process fallback)
- Retry logic with exponential backoff for network resilience
- Bulk database operations for dictionary uploads

**Developer Experience:**
- Comprehensive test suite (78 tests)
- CI/CD pipeline with GitHub Actions
- Code quality tools (black, flake8, mypy)
- Detailed documentation and setup guides

### Migration Required
After pulling the latest changes, run:
```bash
python manage.py migrate
```

