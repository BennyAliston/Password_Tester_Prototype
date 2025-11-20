# Password Tester

A comprehensive web application for password security analysis, strength testing, and breach checking. Built with Django, featuring advanced security measures, asynchronous processing, and robust testing infrastructure.

## 🚀 Features

### Core Functionality
- **Password Strength Analysis** - Real-time strength meter using zxcvbn algorithm
- **Breach Detection** - Integration with HaveIBeenPwned API using k-anonymity for privacy
- **Password Generator** - Strong password generation with customizable options
- **Custom Dictionary** - Upload and manage custom disallowed word lists
- **Password History** - Secure hashed storage of previously tested passwords

### Advanced Features
- **Asynchronous Processing** - Celery-based background tasks for HIBP checks
- **Intelligent Caching** - Multi-layer caching system for performance optimization
- **Secure Token System** - Server-side token mapping for safe client polling
- **Retry Logic** - Exponential backoff for network resilience
- **Form Validation** - Comprehensive input validation and security checks

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
   python -m venv ptvienv
   # Windows
   ptvienv\Scripts\activate
   # Linux/Mac
   source ptvienv/bin/activate
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

# Run all tests
pytest -q

# Run with coverage
pytest --cov=pwdchecker

# Run specific test file
pytest pwdchecker/tests_forms.py -v
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

- **Views** (`pwdchecker/views.py`)
  - Form-based password checking
  - Secure file upload handling
  - AJAX endpoints for async operations

- **Utils** (`pwdchecker/utils.py`)
  - HIBP integration with k-anonymity
  - Retry logic with exponential backoff
  - Multi-layer caching system

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
password_tester_prototype/
├── password_tester/          # Django project settings
│   ├── celery.py            # Celery configuration
│   └── settings.py          # Django settings
├── pwdchecker/              # Main application
│   ├── forms.py             # Form definitions
│   ├── models.py            # Database models
│   ├── tasks.py             # Celery tasks
│   ├── utils.py             # Utility functions
│   ├── views.py             # View functions
│   └── tests_forms.py       # Unit tests
├── templates/               # HTML templates
├── requirements.txt         # Python dependencies
└── .github/workflows/       # CI/CD configuration
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
- Comprehensive test suite with unit tests
- CI/CD pipeline with GitHub Actions
- Code quality tools (black, flake8, mypy)
- Detailed documentation and setup guides

**New Features:**
- Custom dictionary upload with deduplication
- Background task processing for HIBP checks
- Secure file upload handling
- Enhanced error handling and user feedback

### Migration Required
After pulling the latest changes, run:
```bash
python manage.py makemigrations
python manage.py migrate
```

