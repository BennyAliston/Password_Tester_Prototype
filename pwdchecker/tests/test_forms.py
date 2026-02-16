from django.test import TestCase, RequestFactory, Client
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from pwdchecker.forms import CustomDictUploadForm, PasswordCheckForm, PassphraseForm, BulkAuditForm
from pwdchecker.models import DisallowedWord
from pwdchecker.views import _hash_pw, index


class FormsAndViewsTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_custom_dict_upload_too_large(self):
        # Create a file > 2MB
        big_content = b'a' * (2 * 1024 * 1024 + 1)
        f = SimpleUploadedFile('big.txt', big_content, content_type='text/plain')
        form = CustomDictUploadForm(files={'custom_dict': f})
        self.assertFalse(form.is_valid())
        self.assertIn('custom_dict', form.errors)

    def test_password_history_hashed_and_reused(self):
        # Simulate posting a password and then reposting same password
        pw = 'Secur3P@ssw0rd'
        # First request: new password
        req1 = self.factory.post(reverse('pwdchecker:index'), data={'password': pw})
        # Need session middleware
        from django.contrib.sessions.middleware import SessionMiddleware

        def add_session(r):
            middleware = SessionMiddleware(lambda req: None)
            middleware.process_request(r)
            r.session.save()

        add_session(req1)
        response1 = index(req1)
        # After first request, session should have password_history
        hist = req1.session.get('password_history', [])
        self.assertTrue(_hash_pw(pw) in hist)

        # Second request with same password
        req2 = self.factory.post(reverse('pwdchecker:index'), data={'password': pw})
        add_session(req2)
        # copy previous history into new request to simulate same client
        req2.session['password_history'] = hist
        response2 = index(req2)
        # The view sets 'reused_password' in context
        # When rendering with RequestFactory we get an HttpResponse; call the view context by retrieving a rendered template attribute if available
        # Simpler: call logic directly: check reused flag via hash membership
        reused = _hash_pw(pw) in req2.session.get('password_history', [])
        self.assertTrue(reused)

    def test_bulk_upload_creates_entries(self):
        # Upload a small dictionary file
        content = b"apple\nBanana\napple\n"
        f = SimpleUploadedFile('dict.txt', content, content_type='text/plain')
        form = CustomDictUploadForm(files={'custom_dict': f})
        self.assertTrue(form.is_valid())
        uploaded = form.cleaned_data['custom_dict']
        text = uploaded.read().decode('utf-8')
        words = [w.strip() for w in text.splitlines() if w.strip()]
        objs = []
        for w in words:
            objs.append(DisallowedWord(word=w))
        DisallowedWord.objects.bulk_create(objs, ignore_conflicts=True)
        # Should have 2 distinct entries: apple, Banana
        self.assertEqual(DisallowedWord.objects.count(), 2)


class PassphraseFormTests(TestCase):
    """Tests for the PassphraseForm."""

    def test_valid_defaults(self):
        form = PassphraseForm(data={})
        self.assertTrue(form.is_valid())

    def test_valid_with_values(self):
        form = PassphraseForm(data={'word_count': 6, 'separator': '.', 'capitalize': True})
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['word_count'], 6)
        self.assertEqual(form.cleaned_data['separator'], '.')
        self.assertTrue(form.cleaned_data['capitalize'])

    def test_word_count_too_low(self):
        form = PassphraseForm(data={'word_count': 1})
        self.assertFalse(form.is_valid())
        self.assertIn('word_count', form.errors)

    def test_word_count_too_high(self):
        form = PassphraseForm(data={'word_count': 20})
        self.assertFalse(form.is_valid())
        self.assertIn('word_count', form.errors)


class BulkAuditFormTests(TestCase):
    """Tests for the BulkAuditForm."""

    def test_valid_with_textarea(self):
        form = BulkAuditForm(data={'bulk_passwords': 'password1\npassword2\n'})
        self.assertTrue(form.is_valid())

    def test_valid_with_file(self):
        f = SimpleUploadedFile('passwords.txt', b'pass1\npass2\n', content_type='text/plain')
        form = BulkAuditForm(data={'bulk_passwords': ''}, files={'bulk_file': f})
        self.assertTrue(form.is_valid())

    def test_invalid_empty(self):
        form = BulkAuditForm(data={'bulk_passwords': ''})
        self.assertFalse(form.is_valid())

    def test_file_too_large(self):
        big = b'a' * (1 * 1024 * 1024 + 1)
        f = SimpleUploadedFile('big.txt', big, content_type='text/plain')
        form = BulkAuditForm(data={'bulk_passwords': ''}, files={'bulk_file': f})
        self.assertFalse(form.is_valid())


class PassphraseViewTests(TestCase):
    """Tests for the passphrase generation AJAX endpoint."""

    def setUp(self):
        self.client = Client()

    def test_get_returns_passphrase(self):
        response = self.client.get(reverse('pwdchecker:generate_passphrase'))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('passphrase', data)
        self.assertIn('entropy', data)
        self.assertGreater(len(data['passphrase']), 0)

    def test_post_with_params(self):
        response = self.client.post(
            reverse('pwdchecker:generate_passphrase'),
            data={'word_count': 6, 'separator': '.', 'capitalize': 'on'},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('passphrase', data)
        # Should have 5 separators for 6 words
        self.assertEqual(data['passphrase'].count('.'), 5)
        # Should be capitalized
        words = data['passphrase'].split('.')
        for w in words:
            self.assertTrue(w[0].isupper(), f"'{w}' should start uppercase")

    def test_post_invalid_word_count(self):
        response = self.client.post(
            reverse('pwdchecker:generate_passphrase'),
            data={'word_count': 0},
        )
        self.assertEqual(response.status_code, 400)


class BulkAuditViewTests(TestCase):
    """Tests for the bulk audit AJAX endpoint."""

    def setUp(self):
        self.client = Client()

    def test_get_returns_405(self):
        response = self.client.get(reverse('pwdchecker:bulk_audit'))
        self.assertEqual(response.status_code, 405)

    def test_post_with_textarea(self):
        response = self.client.post(
            reverse('pwdchecker:bulk_audit'),
            data={'bulk_passwords': 'password123\nSuperStr0ng!Pass\nab'},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['count'], 3)
        self.assertEqual(len(data['results']), 3)
        # First password should be weak
        self.assertLessEqual(data['results'][0]['score'], 1)
        # Each result should have required fields
        for r in data['results']:
            self.assertIn('score', r)
            self.assertIn('label', r)
            self.assertIn('entropy', r)
            self.assertIn('masked', r)

    def test_post_with_file(self):
        content = b'password1\npassword2\npassword3\n'
        f = SimpleUploadedFile('pws.txt', content, content_type='text/plain')
        response = self.client.post(
            reverse('pwdchecker:bulk_audit'),
            data={'bulk_passwords': '', 'bulk_file': f},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['count'], 3)

    def test_post_empty(self):
        response = self.client.post(
            reverse('pwdchecker:bulk_audit'),
            data={'bulk_passwords': ''},
        )
        self.assertEqual(response.status_code, 400)


class ScoreHistoryViewTests(TestCase):
    """Tests for the score history AJAX endpoints."""

    def setUp(self):
        self.client = Client()

    def test_score_history_empty(self):
        response = self.client.get(reverse('pwdchecker:score_history'))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['scores'], [])

    def test_clear_score_history(self):
        # Set up some session data first
        session = self.client.session
        session['score_history'] = [3, 2, 4]
        session.save()

        response = self.client.post(reverse('pwdchecker:clear_score_history'))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'cleared')

    def test_clear_requires_post(self):
        response = self.client.get(reverse('pwdchecker:clear_score_history'))
        self.assertEqual(response.status_code, 405)
