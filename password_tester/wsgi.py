"""
WSGI configuration for the password_tester project.

This file sets up the WSGI application, which is used for serving the project in production.
For more details, refer to the Django documentation: https://docs.djangoproject.com/en/5.2/howto/deployment/wsgi/
"""

# Import necessary modules
import os
from django.core.wsgi import get_wsgi_application

# Set the default settings module for the WSGI application
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'password_tester.settings')

# Create the WSGI application instance
application = get_wsgi_application()
