"""
URL configuration for the password_tester project.

This file defines the URL patterns for the project, mapping URLs to views.
For more details, refer to the Django documentation: https://docs.djangoproject.com/en/5.2/topics/http/urls/
"""

from django.contrib import admin
from django.urls import path, include
from pwdchecker import views as pwd_views

# Define the URL patterns for the project
urlpatterns = [
    path('admin/', admin.site.urls),  # Admin interface
    # Include URLs from the pwdchecker app with namespace
    path('', include(('pwdchecker.urls', 'pwdchecker'), namespace='pwdchecker')),
    # Provide a global alias for tests and external callers
    path('hibp-status/', pwd_views.hibp_status, name='hibp_status'),
]
