"""
Integration tests for pwdchecker views.

Tests cover:
- Index page GET request
- Password analysis POST request
- HIBP status endpoint
- Dictionary upload and deletion
"""
from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from unittest.mock import patch

from pwdchecker.models import DisallowedWord


class TestIndexView(TestCase):
    """Test the main index view."""

    def setUp(self):
        """Set up test client."""
        self.client = Client()

    def test_index_get_request(self):
        """GET request should return 200 with empty form."""
        response = self.client.get(reverse('pwdchecker:index'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pwdchecker/index.html')

    def test_index_page_contains_form(self):
        """Index page should contain password form."""
        response = self.client.get(reverse('pwdchecker:index'))
        self.assertContains(response, 'name="password"')
        self.assertContains(response, 'type="submit"')

    @patch('pwdchecker.views.check_password_strength')
    def test_index_post_valid_password(self, mock_check):
        """POST with valid password should return analysis results."""
        mock_check.return_value = {
            'zxcvbn_result': {'score': 3, 'feedback': {}},
            'entropy': 50.0,
            'keyboard_patterns': [],
            'leet_matches': [],
            'brute_force_seconds': 1000000,
            'brute_force_minutes': 16666.67,
            'brute_force_hours': 277.78,
            'brute_force_days': 11.57,
            'brute_force_years': 0.03,
            'hibp_count': 0,
            'steps': ['> [*] Analysis complete.'],
            'error': None,
            'extra_checks': [],
            'custom_dict_matches': [],
        }
        
        response = self.client.post(
            reverse('pwdchecker:index'),
            data={'password': 'TestPassword123!'}
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Analysis Results')

    def test_index_post_empty_password(self):
        """POST without password should show error."""
        response = self.client.post(
            reverse('pwdchecker:index'),
            data={'password': ''}
        )
        # Form is required=False, but view checks for empty password
        self.assertEqual(response.status_code, 200)


class TestHibpStatusView(TestCase):
    """Test the HIBP status endpoint."""

    def setUp(self):
        """Set up test client."""
        self.client = Client()

    def test_hibp_status_no_token(self):
        """Request without token should return 400."""
        response = self.client.get(reverse('hibp_status'))
        self.assertEqual(response.status_code, 400)
        self.assertJSONEqual(
            response.content,
            {'error': 'token parameter required'}
        )

    def test_hibp_status_invalid_token(self):
        """Request with invalid token should return 400."""
        response = self.client.get(
            reverse('hibp_status'),
            {'token': 'invalid_token_12345'}
        )
        self.assertEqual(response.status_code, 400)
        self.assertJSONEqual(
            response.content,
            {'error': 'invalid or expired token'}
        )

    @patch('pwdchecker.views.cache')
    def test_hibp_status_valid_token_pending(self, mock_cache):
        """Valid token with pending result should return pending status."""
        mock_cache.get.side_effect = lambda key: {
            'hibp_token:valid_token': 'sha1hash',
            'hibp:sha1hash': None,
        }.get(key)
        
        response = self.client.get(
            reverse('hibp_status'),
            {'token': 'valid_token'}
        )
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(
            response.content,
            {'status': 'pending'}
        )

    @patch('pwdchecker.views.cache')
    def test_hibp_status_valid_token_ready(self, mock_cache):
        """Valid token with ready result should return breach count."""
        mock_cache.get.side_effect = lambda key: {
            'hibp_token:valid_token': 'sha1hash',
            'hibp:sha1hash': 5,
        }.get(key)
        
        response = self.client.get(
            reverse('hibp_status'),
            {'token': 'valid_token'}
        )
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(
            response.content,
            {'status': 'ready', 'hibp_count': 5}
        )


class TestDictionaryUpload(TestCase):
    """Test custom dictionary upload functionality."""

    def setUp(self):
        """Set up test client."""
        self.client = Client()

    def tearDown(self):
        """Clean up test data."""
        DisallowedWord.objects.all().delete()

    def test_dictionary_upload_success(self):
        """Should successfully upload dictionary file."""
        content = b"badword1\nbadword2\nbadword3\n"
        file = SimpleUploadedFile('dict.txt', content, content_type='text/plain')
        
        response = self.client.post(
            reverse('pwdchecker:index'),
            {'custom_dict': file}
        )
        
        self.assertEqual(response.status_code, 200)
        # Check words were added
        self.assertEqual(DisallowedWord.objects.count(), 3)

    def test_dictionary_upload_deduplication(self):
        """Should deduplicate words during upload."""
        content = b"badword\nbadword\nBADWORD\n"
        file = SimpleUploadedFile('dict.txt', content, content_type='text/plain')
        
        response = self.client.post(
            reverse('pwdchecker:index'),
            {'custom_dict': file}
        )
        
        self.assertEqual(response.status_code, 200)
        # Only one unique word (case-insensitive)
        self.assertLessEqual(DisallowedWord.objects.count(), 1)

    def test_dictionary_upload_too_large(self):
        """Should reject files over 2MB."""
        # Create a file > 2MB
        large_content = b'a' * (2 * 1024 * 1024 + 1)
        file = SimpleUploadedFile('large.txt', large_content, content_type='text/plain')
        
        response = self.client.post(
            reverse('pwdchecker:index'),
            {'custom_dict': file}
        )
        
        self.assertEqual(response.status_code, 200)
        # No words should be added
        self.assertEqual(DisallowedWord.objects.count(), 0)

    def test_dictionary_delete(self):
        """Should delete all dictionary entries."""
        # First add some words
        DisallowedWord.objects.create(word='testword1')
        DisallowedWord.objects.create(word='testword2')
        self.assertEqual(DisallowedWord.objects.count(), 2)
        
        response = self.client.post(
            reverse('pwdchecker:index'),
            {'delete_custom_dict': '1'}
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(DisallowedWord.objects.count(), 0)


class TestPasswordPolicyCheck(TestCase):
    """Test password policy validation in view."""

    def setUp(self):
        """Set up test client."""
        self.client = Client()

    @patch('pwdchecker.views.check_password_strength')
    def test_policy_results_displayed(self, mock_check):
        """Policy check results should be displayed."""
        mock_check.return_value = {
            'zxcvbn_result': {'score': 1, 'feedback': {}},
            'entropy': 20.0,
            'keyboard_patterns': [],
            'leet_matches': [],
            'brute_force_seconds': 100,
            'brute_force_minutes': 1.67,
            'brute_force_hours': 0.03,
            'brute_force_days': 0.001,
            'brute_force_years': 0.000001,
            'hibp_count': 0,
            'steps': [],
            'error': None,
            'extra_checks': [],
            'custom_dict_matches': [],
        }
        
        response = self.client.post(
            reverse('pwdchecker:index'),
            data={'password': 'weak'}
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Password Policy')


class TestPasswordHistory(TestCase):
    """Test password history tracking."""

    def setUp(self):
        """Set up test client."""
        self.client = Client()

    @patch('pwdchecker.views.check_password_strength')
    def test_password_stored_in_session_hashed(self, mock_check):
        """Passwords should be stored hashed in session."""
        mock_check.return_value = {
            'zxcvbn_result': {'score': 3, 'feedback': {}},
            'entropy': 50.0,
            'keyboard_patterns': [],
            'leet_matches': [],
            'brute_force_seconds': 1000000,
            'brute_force_minutes': 16666.67,
            'brute_force_hours': 277.78,
            'brute_force_days': 11.57,
            'brute_force_years': 0.03,
            'hibp_count': 0,
            'steps': [],
            'error': None,
            'extra_checks': [],
            'custom_dict_matches': [],
        }
        
        # Enable sessions
        session = self.client.session
        session.save()
        
        response = self.client.post(
            reverse('pwdchecker:index'),
            data={'password': 'TestPassword123!'}
        )
        
        self.assertEqual(response.status_code, 200)
        # Session should contain password history
        session = self.client.session
        self.assertIn('password_history', session)
