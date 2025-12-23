"""
pytest configuration and shared fixtures for pwdchecker tests.
"""
import os
import django
import pytest

# Configure Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'password_tester.settings')
django.setup()


@pytest.fixture
def sample_passwords():
    """Collection of sample passwords for testing."""
    return {
        'weak': 'password',
        'medium': 'Password1',
        'strong': 'MyS3cur3P@ssw0rd!',
        'very_strong': 'X$9mK#pL@2nQ8wRz!',
        'short': 'abc',
        'numbers_only': '12345678',
        'lowercase_only': 'abcdefgh',
        'uppercase_only': 'ABCDEFGH',
        'with_spaces': 'my pass word',
        'leet_speak': 'p4$$w0rd',
        'keyboard_pattern': 'qwerty123',
        'with_year': 'password1990',
    }


@pytest.fixture
def common_words():
    """Common words for dictionary testing."""
    return {
        'password', 'admin', 'letmein', 'welcome', 
        'monkey', 'dragon', 'master', 'qwerty',
        'login', 'sunshine', 'princess', 'football'
    }


@pytest.fixture
def custom_dictionary():
    """Custom dictionary for testing."""
    return ['company', 'secret', 'confidential', 'internal']


@pytest.fixture
def mock_hibp_response():
    """Mock HIBP API response."""
    def _mock_response(breach_count):
        class MockPassword:
            def check(self, anonymous=True):
                return breach_count
        return MockPassword()
    return _mock_response


@pytest.fixture
def sample_dictionary_file():
    """Create a sample dictionary file content."""
    return b"forbidden\nsecret\npassword\nadmin\n"


@pytest.fixture
def large_dictionary_file():
    """Create a file that exceeds the 2MB limit."""
    return b'a' * (2 * 1024 * 1024 + 100)
