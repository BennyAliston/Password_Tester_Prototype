from celery import shared_task
import pwnedpasswords
from django.core.cache import cache
import hashlib

CACHE_TTL = 24 * 60 * 60

@shared_task(bind=True)
def check_hibp_task(self, password_plain):
    """Check HIBP via pwnedpasswords and cache the result keyed by SHA1(password).
    Stores the count (int) or -1 for errors.
    """
    sha1 = hashlib.sha1(password_plain.encode('utf-8')).hexdigest()
    cache_key = f"hibp:{sha1}"
    try:
        pw = pwnedpasswords.Password(password_plain)
        count = pw.check(anonymous=True)
        cache.set(cache_key, count, CACHE_TTL)
        return count
    except Exception as e:
        # store -1 to indicate error; could also choose not to cache
        cache.set(cache_key, -1, CACHE_TTL)
        raise
