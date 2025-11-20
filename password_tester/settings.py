"""
Django settings for the password_tester project.

This file contains all the configuration settings for the Django project, including database setup,
installed apps, middleware, and static file handling.
For more details, refer to the Django documentation: https://docs.djangoproject.com/en/5.2/topics/settings/
"""

from pathlib import Path

# Define the base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Security settings
# IMPORTANT: Replace SECRET_KEY with an environment variable in production
SECRET_KEY = 'django-insecure-f*3)u^(3&&z+f(-)sf%kev7(h5)s#nc7+06zg!g*3cm_$n=lof'

# Debug mode should be turned off in production
DEBUG = True

# Define the allowed hosts for the application
ALLOWED_HOSTS = []

# Production security hardening (toggle as appropriate)
# Ensure these are set to True in production when using HTTPS
SESSION_COOKIE_SECURE = False  # set True in production
CSRF_COOKIE_SECURE = False  # set True in production
SECURE_HSTS_SECONDS = 0  # set to 31536000 (1 year) in production
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
# Redirect HTTP to HTTPS in production
SECURE_SSL_REDIRECT = False

# Session lifetime (seconds). Tune for your app.
SESSION_COOKIE_AGE = 1209600  # 2 weeks

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',  # Admin interface
    'django.contrib.auth',  # Authentication system
    'django.contrib.contenttypes',  # Content type framework
    'django.contrib.sessions',  # Session framework
    'django.contrib.messages',  # Messaging framework
    'django.contrib.staticfiles',  # Static file handling
    'pwdchecker',  # Custom app for password checking
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',  # Security enhancements
    'django.contrib.sessions.middleware.SessionMiddleware',  # Session management
    'django.middleware.common.CommonMiddleware',  # Common HTTP middleware
    'django.middleware.csrf.CsrfViewMiddleware',  # CSRF protection
    'django.contrib.auth.middleware.AuthenticationMiddleware',  # Authentication middleware
    'django.contrib.messages.middleware.MessageMiddleware',  # Messaging middleware
    'django.middleware.clickjacking.XFrameOptionsMiddleware',  # Clickjacking protection
]

# URL configuration
ROOT_URLCONF = 'password_tester.urls'

# Template settings
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],  # Directory for custom templates
        'APP_DIRS': True,  # Enable app-specific templates
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',  # Add request context
                'django.contrib.auth.context_processors.auth',  # Add auth context
                'django.contrib.messages.context_processors.messages',  # Add messages context
            ],
        },
    },
]

# WSGI application
WSGI_APPLICATION = 'password_tester.wsgi.application'

# Database configuration
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',  # SQLite database engine
        'NAME': BASE_DIR / 'db.sqlite3',  # Database file path
    }
}

# Password validation settings
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization settings
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static file settings
STATIC_URL = 'static/'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# CSRF trusted origins
CSRF_TRUSTED_ORIGINS = [
    "http://127.0.0.1:51790",
    "http://localhost:51790",
]