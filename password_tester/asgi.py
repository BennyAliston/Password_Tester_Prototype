"""
ASGI configuration for the password_tester project.

This file sets up the ASGI application, which is used for handling asynchronous web requests.
For more details, refer to the Django documentation: https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

# Import necessary modules
import os
from django.core.asgi import get_asgi_application

# Set the default settings module for the ASGI application
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'password_tester.settings')

# Create the ASGI application instance
application = get_asgi_application()
