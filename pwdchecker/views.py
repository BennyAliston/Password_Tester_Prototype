from django.shortcuts import render
from .utils import check_password_strength, password_similarity
from django.utils.crypto import get_random_string
from django.core.files.uploadedfile import UploadedFile
from django.db import transaction
import hashlib

from .models import DisallowedWord
from .forms import PasswordCheckForm, CustomDictUploadForm
from django.http import JsonResponse
from django.core.cache import cache
from django.utils.crypto import get_random_string

# This file contains the views for the `pwdchecker` app.
# Views handle HTTP requests and return responses, such as rendering templates or processing forms.

# Create your views here.

PASSWORD_POLICY = [
    # Defines the password policy rules for validation.
    # Each rule is a tuple containing a description and a validation function.
    ("At least 8 characters", lambda pw: len(pw) >= 8),
    ("At least 1 uppercase letter", lambda pw: any(c.isupper() for c in pw)),
    ("At least 1 lowercase letter", lambda pw: any(c.islower() for c in pw)),
    ("At least 1 digit", lambda pw: any(c.isdigit() for c in pw)),
    ("At least 1 symbol", lambda pw: any(not c.isalnum() for c in pw)),
]


def _hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()


def index(request):
    # Handles the main page of the `pwdchecker` app.
    # Processes password analysis, custom dictionary management, and password generation.
    context = {}

    # Forms
    pwd_form = PasswordCheckForm(request.POST or None)
    upload_form = CustomDictUploadForm(request.POST or None, request.FILES or None)

    # Handle custom dictionary deletion
    if request.method == 'POST' and request.POST.get('delete_custom_dict'):
        deleted_count = DisallowedWord.objects.all().delete()[0]
        context['custom_dict_status'] = f"Custom dictionary deleted. {deleted_count} entries removed."

    # Handle custom dictionary upload via form
    if request.method == 'POST' and upload_form.is_valid() and upload_form.cleaned_data.get('custom_dict'):
        uploaded_file = upload_form.cleaned_data['custom_dict']
        if isinstance(uploaded_file, UploadedFile):
            try:
                raw = uploaded_file.read()
                text = raw.decode('utf-8', errors='replace')
                words = [w.strip() for w in text.splitlines() if w.strip()]
                objs = []
                seen = set()
                for w in words:
                    lw = w.lower()
                    if lw in seen:
                        continue
                    seen.add(lw)
                    objs.append(DisallowedWord(word=w))
                # Use bulk_create to speed up large uploads; ignore conflicts
                with transaction.atomic():
                    DisallowedWord.objects.bulk_create(objs, ignore_conflicts=True)
                context['custom_dict_status'] = f"Custom dictionary uploaded. {len(objs)} entries processed."
            except Exception as e:
                context['custom_dict_status'] = f"Failed to upload dictionary: {e}"
    elif request.method == 'POST' and not upload_form.is_valid():
        context['custom_dict_status'] = upload_form.errors.as_json()

    # Show custom dictionary status if present
    dict_count = DisallowedWord.objects.count()
    if dict_count > 0:
        context.setdefault('custom_dict_status', f"Custom dictionary loaded with {dict_count} entries.")

    if request.method == 'POST' and pwd_form.is_valid():
        password = pwd_form.cleaned_data.get('password') or ''
        compare_pw = pwd_form.cleaned_data.get('compare_password') or ''

        # Password history validator (store hashed values, not plaintext)
        password_history = request.session.get('password_history', [])
        reused_password = False
        if password:
            phash = _hash_pw(password)
            reused_password = phash in password_history
            if not reused_password:
                password_history.append(phash)
                # Limit history size to last 10 passwords
                password_history = password_history[-10:]
                request.session['password_history'] = password_history
        context['reused_password'] = reused_password

        # Load custom dictionary for check
        custom_dict = list(DisallowedWord.objects.values_list('word', flat=True))
        if password:
            strength_results = check_password_strength(password, deep=True, custom_dict=custom_dict)
            # generate a short-lived server-side token and store mapping token -> sha1 in cache
            sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest()
            token = get_random_string(40)
            cache.set(f"hibp_token:{token}", sha1, 5 * 60)  # token valid for 5 minutes
            context['hibp_token'] = token
            context['results'] = strength_results
            # Extract crack time display strings early to avoid template fallthrough
            crack_times = (strength_results.get('zxcvbn_result') or {}).get('crack_times_display') or {}
            def _fmt(val):
                return val if val else "N/A"
            context['crack_times_display'] = {
                'online_throttling_100_per_hour': _fmt(crack_times.get('online_throttling_100_per_hour')),
                'online_no_throttling_10_per_second': _fmt(crack_times.get('online_no_throttling_10_per_second')),
                'offline_slow_hashing_1e4_per_second': _fmt(crack_times.get('offline_slow_hashing_1e4_per_second')),
                'offline_fast_hashing_1e10_per_second': _fmt(crack_times.get('offline_fast_hashing_1e10_per_second')),
            }
            # Do NOT keep the raw checked password in session or logs
            context['password_checked'] = '********' if password else ''
            context['hacker_steps'] = strength_results.get('steps', [])
            # Password policy check (basic feedback)
            policy_results = [(desc, rule(password)) for desc, rule in PASSWORD_POLICY]
            context['policy_results'] = policy_results
            # Split feedback
            basic_feedback = []
            advanced_feedback = []
            # Basic: length and char types
            for desc, ok in policy_results:
                if not ok:
                    basic_feedback.append(desc)
            # Advanced: entropy, breached, patterns
            if strength_results.get('entropy') is not None:
                advanced_feedback.append(f"Entropy: {strength_results['entropy']} bits")
            if strength_results.get('hibp_count') is not None:
                hibp = strength_results['hibp_count']
                if hibp > 0:
                    advanced_feedback.append(f"Found in {hibp} breaches!")
                elif hibp == 0:
                    advanced_feedback.append("Not found in breaches.")
            if strength_results.get('keyboard_patterns'):
                advanced_feedback.append(f"Keyboard patterns: {', '.join(strength_results['keyboard_patterns'])}")
            if strength_results.get('leet_matches'):
                advanced_feedback.append(f"Leet/dictionary matches: {', '.join(strength_results['leet_matches'])}")
            if strength_results.get('custom_dict_matches'):
                advanced_feedback.append(f"Custom dictionary matches: {', '.join(strength_results['custom_dict_matches'])}")
            if strength_results.get('extra_checks'):
                advanced_feedback.extend(strength_results['extra_checks'])
            context['basic_feedback'] = basic_feedback
            context['advanced_feedback'] = advanced_feedback
            # Comparison
            if compare_pw:
                compare_results = check_password_strength(compare_pw, deep=True, custom_dict=custom_dict)
                similarity = password_similarity(password, compare_pw)
                context['compare'] = {
                    'pw': '********',
                    'results': compare_results,
                    'similarity': similarity,
                }
        else:
            context['error'] = "Please enter a password."

        # Password generator
        if pwd_form.cleaned_data.get('generate'):
            gen_pw = get_random_string(14, allowed_chars='abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()')
            context['generated_password'] = gen_pw
    else:
        # GET -> empty forms rendered
        context = {**context, 'pwd_form': pwd_form, 'upload_form': upload_form}

    # Ensure forms are present in context for template rendering
    context.setdefault('pwd_form', pwd_form)
    context.setdefault('upload_form', upload_form)
    context.setdefault('crack_times_display', {})

    return render(request, 'pwdchecker/index.html', context)


def hibp_status(request):
    """AJAX endpoint to return cached HIBP result for a server-side token."""
    token = request.GET.get('token')
    if not token:
        return JsonResponse({'error': 'token parameter required'}, status=400)
    sha1 = cache.get(f"hibp_token:{token}")
    if not sha1:
        return JsonResponse({'error': 'invalid or expired token'}, status=400)
    cache_key = f"hibp:{sha1}"
    val = cache.get(cache_key)
    if val is None:
        return JsonResponse({'status': 'pending'})
    return JsonResponse({'status': 'ready', 'hibp_count': val})