from django.urls import path
from . import views

# Enable namespacing for this app's URL patterns
app_name = 'pwdchecker'

# This file defines the URL patterns for the `pwdchecker` app.
# Each pattern maps a URL to a specific view function.

urlpatterns = [
    path('', views.index, name='index'),  # Maps the root URL of the app to the `index` view.
    path('hibp-status/', views.hibp_status, name='hibp_status'),
    path('generate-passphrase/', views.generate_passphrase_view, name='generate_passphrase'),
    path('bulk-audit/', views.bulk_audit_view, name='bulk_audit'),
    path('score-history/', views.score_history_view, name='score_history'),
    path('clear-score-history/', views.clear_score_history_view, name='clear_score_history'),
]