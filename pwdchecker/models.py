from django.db import models
from django.db.models import UniqueConstraint
from django.db.models.functions import Lower

# This file defines the database models for the `pwdchecker` app.
# Models represent the structure of the database tables.

class DisallowedWord(models.Model):
    # Represents a word or phrase that is disallowed in passwords.
    # The field itself is not marked `unique=True` because we enforce
    # case-insensitive uniqueness with a database constraint below.
    word = models.CharField(max_length=128)
    added_at = models.DateTimeField(auto_now_add=True)  # Timestamp when the word was added.

    class Meta:
        constraints = [
            UniqueConstraint(Lower('word'), name='unique_lower_word')
        ]

    def __str__(self):
        # Returns the word as its string representation.
        return self.word
