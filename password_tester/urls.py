"""
URL configuration for the password_tester project.

This file defines the URL patterns for the project, mapping URLs to views.
For more details, refer to the Django documentation: https://docs.djangoproject.com/en/5.2/topics/http/urls/
"""

from django.contrib import admin
from django.urls import path, include

# Define the URL patterns for the project
urlpatterns = [
    path('admin/', admin.site.urls),  # Admin interface
    path('', include('pwdchecker.urls')),  # Include URLs from the pwdchecker app
]
