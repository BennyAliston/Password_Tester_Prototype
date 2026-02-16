from django import forms

MAX_DICT_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MB
MAX_BULK_PASSWORDS = 100
MAX_BULK_UPLOAD_BYTES = 1 * 1024 * 1024  # 1 MB


class PasswordCheckForm(forms.Form):
    password = forms.CharField(required=False, widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}))
    compare_password = forms.CharField(required=False, widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}))
    generate = forms.BooleanField(required=False)


class CustomDictUploadForm(forms.Form):
    custom_dict = forms.FileField(required=False)

    def clean_custom_dict(self):
        f = self.cleaned_data.get('custom_dict')
        if f is None:
            return None
        if f.size > MAX_DICT_UPLOAD_BYTES:
            raise forms.ValidationError('Uploaded file too large (max 2MB).')
        # Optionally validate content-type or file extension here
        return f


class PassphraseForm(forms.Form):
    """Form for Diceware-style passphrase generation."""
    word_count = forms.IntegerField(min_value=3, max_value=10, initial=4, required=False)
    separator = forms.CharField(max_length=5, initial='-', required=False)
    capitalize = forms.BooleanField(required=False)


class BulkAuditForm(forms.Form):
    """Form for bulk password audit — textarea or file upload."""
    bulk_passwords = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'placeholder': 'Enter passwords, one per line...',
            'rows': 6,
        }),
    )
    bulk_file = forms.FileField(required=False)

    def clean_bulk_file(self):
        f = self.cleaned_data.get('bulk_file')
        if f is None:
            return None
        if f.size > MAX_BULK_UPLOAD_BYTES:
            raise forms.ValidationError('Bulk file too large (max 1MB).')
        return f

    def clean(self):
        cleaned = super().clean()
        text = cleaned.get('bulk_passwords', '').strip()
        bulk_file = cleaned.get('bulk_file')
        if not text and not bulk_file:
            raise forms.ValidationError('Provide passwords in the textarea or upload a file.')
        return cleaned
