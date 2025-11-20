# This file defines the configuration for the `pwdchecker` app.
# The `name` attribute specifies the app's name, and `default_auto_field` sets the default primary key type.

from django.apps import AppConfig


class PwdcheckerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'pwdchecker'
