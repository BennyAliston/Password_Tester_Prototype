# This file contains utility functions for password analysis and validation.
# These functions include entropy calculation, pattern detection, and integration with external services.

import time
import urllib.error
import math
import re
from zxcvbn import zxcvbn
import pwnedpasswords
import requests
from django.core.cache import cache
import hashlib
from pwnedpasswords import exceptions as pw_exceptions
import threading
import time as _time

# Small in-process cache fallback for environments where Django settings
# (and CACHES) are not configured (e.g., running snippets/tests outside Django).
_local_hibp_cache = {}
_local_hibp_lock = threading.Lock()


def _cache_get(key):
    """Try Django cache first, fall back to local in-memory cache."""
    try:
        val = cache.get(key)
        return val
    except Exception:
        # Fall back to local cache
        with _local_hibp_lock:
            entry = _local_hibp_cache.get(key)
            if not entry:
                return None
            value, expires_at = entry
            if _time.time() >= expires_at:
                # expired
                del _local_hibp_cache[key]
                return None
            return value


def _cache_set(key, value, ttl):
    """Set value in Django cache if available, otherwise local cache."""
    try:
        cache.set(key, value, ttl)
    except Exception:
        with _local_hibp_lock:
            _local_hibp_cache[key] = (value, _time.time() + ttl)

# Helper: entropy calculation
# Calculates the entropy of a password based on its character set.
def calculate_entropy(password):
    charset = 0
    if re.search(r'[a-z]', password):
        charset += 26
    if re.search(r'[A-Z]', password):
        charset += 26
    if re.search(r'[0-9]', password):
        charset += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        charset += 32  # Approximation for symbols
    if charset == 0:
        return 0
    entropy = len(password) * math.log2(charset)
    return round(entropy, 2)

# Helper: keyboard patterns
# Checks for common keyboard patterns in the password.
KEYBOARD_PATTERNS = [
    '12345', 'qwerty', 'asdf', 'zxcv', 'password', 'letmein', 'admin', 'welcome', 'passw0rd', 'qazwsx', 'iloveyou'
]
def check_keyboard_patterns(password):
    pw_lower = password.lower()
    found = [p for p in KEYBOARD_PATTERNS if p in pw_lower]
    return found

# Helper: leet speak dictionary check
# Converts leet speak to plain text and checks against a dictionary of common words.
LEET_MAP = {'4':'a','@':'a','3':'e','1':'i','!':'i','0':'o','$':'s','5':'s','7':'t'}
def leet_to_plain(password):
    pw = password.lower()
    for k, v in LEET_MAP.items():
        pw = pw.replace(k, v)
    return pw

def check_leet_dictionary(password, common_words):
    pw_plain = leet_to_plain(password)
    found = [w for w in common_words if w in pw_plain]
    return found

# Helper: brute-force time estimate
# Estimates the time required to brute-force the password based on its character set.
def brute_force_time(password):
    charset = 0
    if re.search(r'[a-z]', password):
        charset += 26
    if re.search(r'[A-Z]', password):
        charset += 26
    if re.search(r'[0-9]', password):
        charset += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        charset += 32
    guesses = charset ** len(password)
    guesses_per_sec = 1e9  # 1 billion guesses/sec (fast GPU)
    seconds = guesses / guesses_per_sec
    return seconds

# Load common words for dictionary/leet checks
# Loads a list of common passwords from a file for validation.
import os
COMMON_WORDS_PATH = os.path.join(os.path.dirname(__file__), 'data', 'common_passwords.txt')
try:
    with open(COMMON_WORDS_PATH, 'r', encoding='utf-8') as f:
        COMMON_WORDS = set(line.strip().lower() for line in f if line.strip())
except Exception:
    COMMON_WORDS = set()

def check_password_strength(password, deep=False, custom_dict=None):
    # Analyzes the strength of a password using various metrics and checks.
    results = {
        'zxcvbn_result': None,
        'hibp_count': None,
        'entropy': None,
        'keyboard_patterns': [],
        'leet_matches': [],
        'brute_force_seconds': None,
        'brute_force_minutes': None,
        'brute_force_hours': None,
        'brute_force_days': None,
        'brute_force_years': None,
        'steps': [],
        'error': None,
        'extra_checks': [],
        'custom_dict_matches': [],
    }
    steps = results['steps']

    steps.append('> [*] Analyzing password...')

    # 1. Check strength using zxcvbn
    try:
        start_time = time.time()
        zxcvbn_analysis = zxcvbn(password)
        end_time = time.time()
        zxcvbn_analysis['calc_time'] = (end_time - start_time) * 1000
        results['zxcvbn_result'] = zxcvbn_analysis
        entropy = calculate_entropy(password)
        results['entropy'] = entropy
        steps.append('> [*] zxcvbn analysis complete.')
    except Exception as e:
        results['error'] = f"Error during zxcvbn analysis: {e}"
        steps.append(f"> [!] zxcvbn analysis error: {e}")

    # 2. Entropy calculation
    steps.append(f"> [*] Entropy calculated: {results['entropy']} bits.")

    # 3. Keyboard patterns
    patterns = check_keyboard_patterns(password)
    results['keyboard_patterns'] = patterns
    if patterns:
        steps.append(f"> [!] Keyboard patterns found: {', '.join(patterns)}")
    else:
        steps.append("> [*] No common keyboard patterns detected.")

    # 4. Leet speak dictionary check
    leet_matches = check_leet_dictionary(password, COMMON_WORDS)
    results['leet_matches'] = leet_matches
    if leet_matches:
        steps.append(f"> [!] Leet/dictionary matches: {', '.join(leet_matches)}")
    else:
        steps.append("> [*] No leet/dictionary matches detected.")

    # 5. Brute-force time estimate
    seconds = brute_force_time(password)
    results['brute_force_seconds'] = seconds
    results['brute_force_minutes'] = seconds / 60
    results['brute_force_hours'] = seconds / 3600
    results['brute_force_days'] = seconds / 86400
    results['brute_force_years'] = seconds / 31536000
    # Human-readable label for templates/UX
    if seconds < 0.01:
        brute_label = "< 0.01 seconds (Very Weak)"
        steps.append("> [!] Brute-force time: < 0.01 seconds (Very Weak)")
    elif seconds < 60:
        brute_label = f"{seconds:.2f} seconds (Very Weak)"
        steps.append(f"> [!] Brute-force time: {seconds:.2f} seconds (Very Weak)")
    elif seconds < 3600:
        brute_label = f"{seconds/60:.2f} minutes (Weak)"
        steps.append(f"> [!] Brute-force time: {seconds/60:.2f} minutes (Weak)")
    elif seconds < 86400:
        brute_label = f"{seconds/3600:.2f} hours"
        steps.append(f"> [*] Brute-force time: {seconds/3600:.2f} hours")
    elif seconds < 31536000:
        brute_label = f"{seconds/86400:.2f} days"
        steps.append(f"> [*] Brute-force time: {seconds/86400:.2f} days")
    elif seconds < 31851360:
        brute_label = "< 1 year"
        steps.append("> [*] Brute-force time: < 1 year")
    else:
        brute_label = f"{seconds/31536000:.2f} years"
        steps.append(f"> [*] Brute-force time: {seconds/31536000:.2f} years")
    results['brute_force_label'] = brute_label

    # 6. Check Have I Been Pwned (HIBP) database using k-anonymity with caching
    hibp_count = -1
    # Cache key: sha1 of the plaintext password (we store only counts, not plaintext)
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest()
    cache_key = f"hibp:{sha1}"
    CACHE_TTL = 24 * 60 * 60  # 24 hours
    try:
        cached = _cache_get(cache_key)
        if cached is not None:
            hibp_count = cached
            results['hibp_count'] = hibp_count
            steps.append(f"> [*] HIBP cache hit (ttl {CACHE_TTL}s).")
        else:
            # If Celery is available, enqueue an async task and return pending (-1)
            try:
                from pwdchecker.tasks import check_hibp_task

                # enqueue the task (non-blocking)
                check_hibp_task.delay(password)
                results['hibp_count'] = -1
                steps.append("> [*] HIBP check enqueued (async). Poll the status endpoint to get the result.")
                return results
            except Exception:
                # Celery not available or import failed; fall back to synchronous check
                pass
            # Retry/backoff parameters
            max_attempts = 4
            backoff_base = 0.5
            attempt = 0
            last_exc = None
            while attempt < max_attempts:
                try:
                    pw_obj = pwnedpasswords.Password(password)
                    hibp_count = pw_obj.check(anonymous=True)
                    results['hibp_count'] = hibp_count
                    _cache_set(cache_key, hibp_count, CACHE_TTL)
                    if hibp_count > 0:
                        steps.append(f"> [!] Found in {hibp_count} real-world breaches (HIBP).")
                    else:
                        steps.append("> [*] Not found in real-world breaches (HIBP).")
                    last_exc = None
                    break
                except (pw_exceptions.RateLimitExceeded, urllib.error.URLError, requests.exceptions.RequestException) as e:
                    # transient/network/rate-limit errors: retry with exponential backoff
                    last_exc = e
                    attempt += 1
                    sleep_for = backoff_base * (2 ** (attempt - 1))
                    # small jitter
                    sleep_for = sleep_for * (0.9 + 0.2 * (attempt % 3) / 2)
                    steps.append(f"> [!] HIBP transient error (attempt {attempt}/{max_attempts}): {e}; retrying in {sleep_for:.1f}s")
                    try:
                        _time.sleep(sleep_for)
                    except Exception:
                        pass
                except pw_exceptions.PasswordNotFound:
                    results['hibp_count'] = 0
                    _cache_set(cache_key, 0, CACHE_TTL)
                    steps.append("> [*] Not found in real-world breaches (HIBP).")
                    last_exc = None
                    break
                except Exception as e:
                    last_exc = e
                    # non-transient error: break and record
                    steps.append(f"> [!] HIBP unexpected error: {e}")
                    break
            if last_exc:
                results['error'] = (results['error'] + "; " if results['error'] else "") + f"Error during HIBP check after retries: {last_exc}"
                results['hibp_count'] = -1
                steps.append(f"> [!] HIBP check failed after {max_attempts} attempts: {last_exc}")
    except Exception as e:
        results['error'] = (results['error'] + "; " if results['error'] else "") + f"Error during HIBP setup/check: {e}"
        results['hibp_count'] = -1
        steps.append(f"> [!] HIBP setup/check error: {e}")

    # Custom dictionary check
    if custom_dict:
        matches = [w for w in custom_dict if w and w.lower() in password.lower()]
        results['custom_dict_matches'] = matches
        if matches:
            steps.append(f"> [!] Custom dictionary match: {', '.join(matches)}")
            results['extra_checks'].append(f"Password contains disallowed word(s): {', '.join(matches)}.")

    # 7. Deep checks (if requested)
    if deep:
        extra = results['extra_checks']
        # Check for repeated chars
        if len(set(password)) == 1:
            extra.append('Password is made of a single repeated character (very weak).')
            steps.append('> [!] Password is a single repeated character.')
        # Check for sequential patterns (e.g. abc, 123, qwerty...)
        seq = 'abcdefghijklmnopqrstuvwxyz'
        seq_num = '0123456789'
        pw_lower = password.lower()
        found_seq = any(s in pw_lower for s in [seq[i:i+3] for i in range(len(seq)-2)])
        found_seq_num = any(s in pw_lower for s in [seq_num[i:i+3] for i in range(len(seq_num)-2)])
        if found_seq or found_seq_num:
            extra.append('Password contains sequential letters or numbers (easily guessable).')
            steps.append('> [!] Sequential pattern detected.')
        # Check for common substitutions (e.g. p@ssw0rd)
        common_subs = {'@':'a','1':'i','!':'i','0':'o','$':'s','5':'s','3':'e','7':'t'}
        for k, v in common_subs.items():
            if k in password:
                steps.append(f'> [*] Found common substitution: {k}->{v}')
        # Check for date patterns (e.g. 1990, 2020)
        import re
        if re.search(r'(19|20)\d{2}', password):
            extra.append('Password contains a year (e.g. birth year, weak).')
            steps.append('> [!] Year pattern detected.')
        # Check for palindrome
        if len(password) > 3 and password == password[::-1]:
            extra.append('Password is a palindrome (weak).')
            steps.append('> [!] Password is a palindrome.')
        # Check for keyboard walks (e.g. qwerty, asdf)
        keyboard_walks = ['qwerty','asdf','zxcv','1234','qaz','wsx']
        if any(w in pw_lower for w in keyboard_walks):
            extra.append('Password contains keyboard walk patterns (very weak).')
            steps.append('> [!] Keyboard walk pattern detected.')
        # Check for common words fully present
        if pw_lower in COMMON_WORDS:
            extra.append('Password is a common word or password (very weak).')
            steps.append('> [!] Password is a common word.')
        # Check for short length
        if len(password) < 8:
            extra.append('Password is very short (less than 8 chars).')
            steps.append('> [!] Password is very short.')
        # Check for whitespace
        if ' ' in password:
            extra.append('Password contains whitespace.')
            steps.append('> [*] Password contains whitespace.')
        # Check for dictionary words inside password
        found_words = [w for w in COMMON_WORDS if w in pw_lower and len(w) > 3]
        if found_words:
            extra.append(f'Contains common word(s): {", ".join(found_words[:3])}...')
            steps.append(f'> [!] Contains common word(s): {", ".join(found_words[:3])}...')
        # Custom blacklist check (user-supplied)
        BLACKLIST = set(['password', 'letmein', '123456', 'admin', 'welcome', 'qwerty', 'passw0rd', 'iloveyou', 'monkey', 'dragon', 'sunshine', 'princess', 'football', 'baseball', 'abc123', 'trustno1'])
        if pw_lower in BLACKLIST:
            extra.append('Password is in a known blacklist (very weak).')
            steps.append('> [!] Password is in a known blacklist.')
        # Check for email/username patterns
        if re.search(r'^[\w\.-]+@[\w\.-]+\.[a-z]{2,}$', password):
            extra.append('Password looks like an email address (not recommended).')
            steps.append('> [!] Password looks like an email address.')
        if re.search(r'^[a-z0-9_\.-]{3,}$', password) and not re.search(r'[^a-z0-9_\.-]', password):
            extra.append('Password looks like a username (not recommended).')
            steps.append('> [!] Password looks like a username.')
        # Check for phone number patterns
        if re.search(r'\b\d{10,}\b', password):
            extra.append('Password contains a phone number pattern (not recommended).')
            steps.append('> [!] Password contains a phone number pattern.')
        # Check for credit card patterns (basic)
        if re.search(r'\b(?:\d[ -]*?){13,16}\b', password):
            extra.append('Password contains a credit card-like pattern (not recommended).')
            steps.append('> [!] Password contains a credit card-like pattern.')
    # 8. Password composition breakdown
    composition = password_composition(password)
    results['composition'] = composition
    steps.append(f"> [*] Composition: {composition['uppercase_pct']:.0f}% upper, {composition['lowercase_pct']:.0f}% lower, {composition['digits_pct']:.0f}% digits, {composition['symbols_pct']:.0f}% symbols")

    # 9. Password mask
    mask = password_mask(password)
    results['mask'] = mask
    steps.append(f"> [*] Mask pattern: {mask}")

    # 10. Attack scenario breakdown
    scenarios = attack_scenarios(password)
    results['attack_scenarios'] = scenarios
    steps.append('> [*] Attack scenarios computed.')

    # 11. Entropy benchmark
    benchmark = entropy_benchmark(results.get('entropy', 0))
    results['entropy_benchmark'] = benchmark
    steps.append(f"> [*] Entropy benchmark: {benchmark['label']}")

    steps.append('> [*] Analysis complete.')
    return results


def password_composition(password):
    """Return count and percentage breakdown of character types."""
    length = len(password) or 1
    upper = sum(1 for c in password if c.isupper())
    lower = sum(1 for c in password if c.islower())
    digits = sum(1 for c in password if c.isdigit())
    symbols = sum(1 for c in password if not c.isalnum())
    return {
        'uppercase': upper,
        'lowercase': lower,
        'digits': digits,
        'symbols': symbols,
        'uppercase_pct': upper / length * 100,
        'lowercase_pct': lower / length * 100,
        'digits_pct': digits / length * 100,
        'symbols_pct': symbols / length * 100,
    }


def password_mask(password):
    """Return a structural mask of the password.

    U = uppercase, l = lowercase, d = digit, s = symbol.
    Example: P@ssw0rd -> Usllldld
    """
    mask_chars = []
    for c in password:
        if c.isupper():
            mask_chars.append('U')
        elif c.islower():
            mask_chars.append('l')
        elif c.isdigit():
            mask_chars.append('d')
        else:
            mask_chars.append('s')
    return ''.join(mask_chars)


def _format_time(seconds):
    """Format seconds into a human-readable string."""
    if seconds < 0.001:
        return "instant"
    if seconds < 1:
        return f"{seconds:.3f} seconds"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < 31536000:
        return f"{seconds / 86400:.1f} days"
    years = seconds / 31536000
    if years > 1e12:
        return "centuries+"
    if years > 1e6:
        return f"{years:.2e} years"
    return f"{years:.1f} years"


def attack_scenarios(password):
    """Return crack-time estimates for multiple attack types."""
    charset = 0
    if re.search(r'[a-z]', password):
        charset += 26
    if re.search(r'[A-Z]', password):
        charset += 26
    if re.search(r'[0-9]', password):
        charset += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        charset += 32
    if charset == 0:
        charset = 26

    total_combos = charset ** len(password)

    scenarios = []

    # Dictionary attack: ~10 billion entries checked at 10M/s
    dict_seconds = 1e10 / 1e7  # ~1000 seconds for a pure dictionary hit
    # But if the password is NOT a dictionary word the attack fails.
    # We use zxcvbn guesses as a proxy for dictionary vulnerability.
    scenarios.append({
        'name': 'Dictionary Attack',
        'speed': '10M passwords/sec',
        'description': 'Attacker tries known leaked passwords and common words. Most effective against reused or common passwords.',
        'time': _format_time(dict_seconds),
        'raw_seconds': dict_seconds,
        'icon': 'book',
    })

    # Hybrid attack: dictionary + rules (capitalise, append numbers, leet)
    # Typically expands dictionary by 1000x rules at ~1M/s
    hybrid_combos = 1e10 * 1000  # 10B words * 1000 rules
    hybrid_speed = 1e6
    hybrid_seconds = hybrid_combos / hybrid_speed
    scenarios.append({
        'name': 'Hybrid Attack',
        'speed': '1M passwords/sec',
        'description': 'Dictionary words combined with rules: capitalizing, appending digits, leet substitutions (@ for a, 3 for e).',
        'time': _format_time(hybrid_seconds),
        'raw_seconds': hybrid_seconds,
        'icon': 'shuffle',
    })

    # Mask / brute-force: tries all combinations for the detected charset
    bf_speed = 1e9  # 1 billion/sec (fast GPU)
    bf_seconds = total_combos / bf_speed
    scenarios.append({
        'name': 'Mask / Brute-Force',
        'speed': '1B passwords/sec',
        'description': 'Tries every possible combination for the character set. Time depends on password length and complexity.',
        'time': _format_time(bf_seconds),
        'raw_seconds': bf_seconds,
        'icon': 'zap',
    })

    # Credential stuffing: uses credentials from prior breaches
    # Typically limited by target rate limiting: ~100-1000/sec
    cred_speed = 1000
    cred_combos = 1e10  # testing against breach databases
    cred_seconds = cred_combos / cred_speed
    scenarios.append({
        'name': 'Credential Stuffing',
        'speed': '1K attempts/sec',
        'description': 'Uses username/password pairs from previous breaches against other sites. Rate-limited by target services.',
        'time': _format_time(cred_seconds),
        'raw_seconds': cred_seconds,
        'icon': 'globe',
    })

    return scenarios


def _levenshtein_distance(s1, s2):
    """Compute the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,        # insert
                prev_row[j + 1] + 1,    # delete
                prev_row[j] + cost      # substitute
            ))
        prev_row = curr_row
    return prev_row[-1]


def _longest_common_substring(s1, s2):
    """Return the length of the longest common substring."""
    if not s1 or not s2:
        return 0
    m, n = len(s1), len(s2)
    prev = [0] * (n + 1)
    longest = 0
    for i in range(1, m + 1):
        curr = [0] * (n + 1)
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                curr[j] = prev[j - 1] + 1
                if curr[j] > longest:
                    longest = curr[j]
        prev = curr
    return longest


def password_similarity(pw1, pw2):
    """Compare two passwords and return similarity metrics."""
    lev_dist = _levenshtein_distance(pw1, pw2)
    max_len = max(len(pw1), len(pw2), 1)
    similarity_pct = round((1 - lev_dist / max_len) * 100, 1)

    lcs_len = _longest_common_substring(pw1, pw2)
    lcs_pct = round(lcs_len / max_len * 100, 1)

    too_similar = similarity_pct >= 70

    return {
        'levenshtein_distance': lev_dist,
        'similarity_pct': similarity_pct,
        'lcs_length': lcs_len,
        'lcs_pct': lcs_pct,
        'too_similar': too_similar,
        'verdict': 'Too similar - use a completely different password' if too_similar else 'Sufficiently different',
    }


def entropy_benchmark(entropy):
    """Return where the entropy falls on a benchmark scale."""
    benchmarks = [
        (28, 'Common Word', 'danger'),
        (36, 'Weak Password', 'danger'),
        (50, 'Basic Password', 'warning'),
        (60, 'Moderate', 'warning'),
        (80, 'Good', 'success'),
        (100, 'Strong', 'success'),
        (128, 'Excellent', 'success'),
    ]

    label = 'Extremely Strong'
    css_class = 'success'
    for threshold, name, cls in benchmarks:
        if entropy < threshold:
            label = name
            css_class = cls
            break

    # Compute percentage position on the scale (0-128 bits mapped to 0-100%)
    scale_max = 128
    position = min(entropy / scale_max * 100, 100)

    return {
        'label': label,
        'css_class': css_class,
        'position': round(position, 1),
        'entropy': entropy,
        'benchmarks': benchmarks,
    }


# ==========================================================================
# Diceware-style Passphrase Generator
# ==========================================================================

DICEWARE_WORDS_PATH = os.path.join(os.path.dirname(__file__), 'data', 'diceware_words.txt')
try:
    with open(DICEWARE_WORDS_PATH, 'r', encoding='utf-8') as _f:
        DICEWARE_WORDS = [line.strip() for line in _f if line.strip()]
except Exception:
    DICEWARE_WORDS = []

import secrets


def generate_passphrase(word_count=4, separator='-', capitalize=False):
    """Generate a Diceware-style passphrase from the built-in word list.

    Args:
        word_count: Number of words in the passphrase (3-10).
        separator: Character(s) separating words.
        capitalize: Whether to capitalize each word.

    Returns:
        dict with 'passphrase', 'entropy', 'word_count', 'separator'.
    """
    word_count = max(3, min(word_count, 10))
    if not DICEWARE_WORDS:
        return {
            'passphrase': '',
            'entropy': 0,
            'word_count': word_count,
            'separator': separator,
            'error': 'Word list not available.',
        }

    pool_size = len(DICEWARE_WORDS)
    chosen = [secrets.choice(DICEWARE_WORDS) for _ in range(word_count)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    passphrase = separator.join(chosen)

    # Entropy = word_count * log2(pool_size)
    entropy = round(word_count * math.log2(pool_size), 2) if pool_size > 0 else 0

    return {
        'passphrase': passphrase,
        'entropy': entropy,
        'word_count': word_count,
        'separator': separator,
    }


def quick_score(password):
    """Return a quick score dict for bulk audit (no HIBP, no deep checks).

    Returns dict with 'score' (0-4), 'entropy', 'label', 'suggestions'.
    """
    try:
        result = zxcvbn(password)
        score = result.get('score', 0)
    except Exception:
        score = 0
        result = {'feedback': {}}

    entropy = calculate_entropy(password)
    labels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong']
    label = labels[score] if 0 <= score <= 4 else 'Unknown'

    suggestions = []
    feedback = result.get('feedback') or {}
    if feedback.get('warning'):
        suggestions.append(feedback['warning'])
    suggestions.extend(feedback.get('suggestions', []))
    if not suggestions:
        if score <= 1:
            suggestions.append('Use a longer password with a mix of character types.')
        elif score == 2:
            suggestions.append('Consider adding symbols or increasing length.')

    return {
        'score': score,
        'entropy': entropy,
        'label': label,
        'suggestions': suggestions,
    }