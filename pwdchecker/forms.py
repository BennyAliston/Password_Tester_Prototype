from django import forms

MAX_DICT_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MB


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
