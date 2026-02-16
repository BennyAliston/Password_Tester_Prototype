"""
Unit tests for pwdchecker utility functions.

Tests cover:
- Entropy calculation
- Keyboard pattern detection  
- Leet speak conversion
- Brute force time estimation
- Password strength analysis
"""
import pytest
from unittest.mock import patch, MagicMock
from django.test import TestCase

from pwdchecker.utils import (
    calculate_entropy,
    check_keyboard_patterns,
    leet_to_plain,
    check_leet_dictionary,
    brute_force_time,
    check_password_strength,
    generate_passphrase,
    quick_score,
)


class TestCalculateEntropy(TestCase):
    """Test the entropy calculation function."""

    def test_empty_password(self):
        """Empty password should have 0 entropy."""
        self.assertEqual(calculate_entropy(''), 0)

    def test_lowercase_only(self):
        """Lowercase only password uses charset of 26."""
        entropy = calculate_entropy('password')
        # 8 chars * log2(26) ≈ 37.6
        self.assertAlmostEqual(entropy, 37.60, places=1)

    def test_uppercase_only(self):
        """Uppercase only password uses charset of 26."""
        entropy = calculate_entropy('PASSWORD')
        self.assertAlmostEqual(entropy, 37.60, places=1)

    def test_mixed_case(self):
        """Mixed case password uses charset of 52."""
        entropy = calculate_entropy('PassWord')
        # 8 chars * log2(52) ≈ 45.6
        self.assertAlmostEqual(entropy, 45.60, places=1)

    def test_with_digits(self):
        """Alphanumeric password uses charset of 62."""
        entropy = calculate_entropy('Pass1234')
        # 8 chars * log2(62) ≈ 47.6
        self.assertAlmostEqual(entropy, 47.63, places=1)

    def test_with_symbols(self):
        """Password with symbols uses charset of 94."""
        entropy = calculate_entropy('Pass@123')
        # 8 chars * log2(94) ≈ 52.4
        self.assertAlmostEqual(entropy, 52.44, places=1)

    def test_longer_password(self):
        """Longer password should have higher entropy."""
        short_entropy = calculate_entropy('Pass@1')
        long_entropy = calculate_entropy('Pass@123Word!')
        self.assertGreater(long_entropy, short_entropy)


class TestCheckKeyboardPatterns(TestCase):
    """Test keyboard pattern detection."""

    def test_no_patterns(self):
        """Random password should have no detected patterns."""
        result = check_keyboard_patterns('Xk9$mZpL')
        self.assertEqual(result, [])

    def test_qwerty_pattern(self):
        """Should detect qwerty pattern."""
        result = check_keyboard_patterns('myqwertypass')
        self.assertIn('qwerty', result)

    def test_12345_pattern(self):
        """Should detect 12345 pattern."""
        result = check_keyboard_patterns('test12345')
        self.assertIn('12345', result)

    def test_asdf_pattern(self):
        """Should detect asdf pattern."""
        result = check_keyboard_patterns('asdfTest')
        self.assertIn('asdf', result)

    def test_case_insensitive(self):
        """Pattern detection should be case insensitive."""
        result = check_keyboard_patterns('QWERTY')
        self.assertIn('qwerty', result)

    def test_password_pattern(self):
        """Should detect 'password' as a pattern."""
        result = check_keyboard_patterns('mypassword123')
        self.assertIn('password', result)

    def test_multiple_patterns(self):
        """Should detect multiple patterns."""
        result = check_keyboard_patterns('qwerty12345')
        self.assertIn('qwerty', result)
        self.assertIn('12345', result)


class TestLeetToPlain(TestCase):
    """Test leet speak to plain text conversion."""

    def test_no_leet(self):
        """Plain text should remain unchanged."""
        result = leet_to_plain('password')
        self.assertEqual(result, 'password')

    def test_common_substitutions(self):
        """Should convert common leet substitutions."""
        result = leet_to_plain('p4$$w0rd')
        self.assertEqual(result, 'password')

    def test_at_symbol(self):
        """@ should convert to 'a'."""
        result = leet_to_plain('p@ssword')
        self.assertEqual(result, 'password')

    def test_exclamation(self):
        """! should convert to 'i'."""
        result = leet_to_plain('adm!n')
        self.assertEqual(result, 'admin')

    def test_mixed(self):
        """Should handle mixed leet and plain."""
        result = leet_to_plain('h3ll0')
        self.assertEqual(result, 'hello')


class TestCheckLeetDictionary(TestCase):
    """Test leet dictionary checking."""

    def test_no_match(self):
        """Random password should have no matches."""
        common_words = {'password', 'admin', 'letmein'}
        result = check_leet_dictionary('xK9mZpL', common_words)
        self.assertEqual(result, [])

    def test_plain_match(self):
        """Should find plain word matches."""
        common_words = {'password', 'admin', 'letmein'}
        result = check_leet_dictionary('mypassword', common_words)
        self.assertIn('password', result)

    def test_leet_match(self):
        """Should find leet-encoded word matches."""
        common_words = {'password', 'admin', 'letmein'}
        result = check_leet_dictionary('p4$$w0rd', common_words)
        self.assertIn('password', result)


class TestBruteForceTime(TestCase):
    """Test brute force time estimation."""

    def test_short_lowercase(self):
        """Short lowercase password should be crackable quickly."""
        seconds = brute_force_time('abc')
        # 26^3 / 1e9 = very small
        self.assertLess(seconds, 1)

    def test_longer_password_takes_longer(self):
        """Longer passwords should take more time."""
        short_time = brute_force_time('abc')
        long_time = brute_force_time('abcdefghij')
        self.assertGreater(long_time, short_time)

    def test_complex_password_takes_longer(self):
        """More complex charset should take longer."""
        simple_time = brute_force_time('aaaa')
        complex_time = brute_force_time('aA1!')
        self.assertGreater(complex_time, simple_time)


class TestCheckPasswordStrength(TestCase):
    """Test the main password strength checking function."""

    @patch('pwdchecker.utils.pwnedpasswords')
    def test_returns_all_fields(self, mock_hibp):
        """Should return all expected result fields."""
        mock_hibp.Password.return_value.check.return_value = 0
        result = check_password_strength('TestPassword123!')
        
        expected_keys = [
            'zxcvbn_result',
            'hibp_count',
            'entropy',
            'keyboard_patterns',
            'leet_matches',
            'brute_force_seconds',
            'brute_force_minutes',
            'brute_force_hours',
            'brute_force_days',
            'brute_force_years',
            'steps',
            'error',
            'extra_checks',
            'custom_dict_matches',
        ]
        for key in expected_keys:
            self.assertIn(key, result)

    @patch('pwdchecker.utils.pwnedpasswords')
    def test_weak_password_detection(self, mock_hibp):
        """Should detect weak password characteristics."""
        mock_hibp.Password.return_value.check.return_value = 0
        result = check_password_strength('password', deep=True)
        
        # Should detect keyboard pattern
        self.assertIn('password', result['keyboard_patterns'])

    @patch('pwdchecker.utils.pwnedpasswords')
    def test_custom_dictionary_check(self, mock_hibp):
        """Should check against custom dictionary."""
        mock_hibp.Password.return_value.check.return_value = 0
        custom_dict = ['secret', 'forbidden']
        result = check_password_strength('mysecretpassword', custom_dict=custom_dict)
        
        self.assertIn('secret', result['custom_dict_matches'])

    @patch('pwdchecker.utils.pwnedpasswords')
    def test_deep_checks_sequential(self, mock_hibp):
        """Deep mode should detect sequential patterns."""
        mock_hibp.Password.return_value.check.return_value = 0
        result = check_password_strength('abc123test', deep=True)
        
        extra_checks = result.get('extra_checks', [])
        sequential_found = any('sequential' in check.lower() for check in extra_checks)
        self.assertTrue(sequential_found)

    @patch('pwdchecker.utils.pwnedpasswords')
    def test_deep_checks_short_password(self, mock_hibp):
        """Deep mode should flag short passwords."""
        mock_hibp.Password.return_value.check.return_value = 0
        result = check_password_strength('short', deep=True)
        
        extra_checks = result.get('extra_checks', [])
        short_found = any('short' in check.lower() for check in extra_checks)
        self.assertTrue(short_found)

    @patch('pwdchecker.utils.pwnedpasswords')
    def test_deep_checks_year_pattern(self, mock_hibp):
        """Deep mode should detect year patterns."""
        mock_hibp.Password.return_value.check.return_value = 0
        result = check_password_strength('mypassword1990', deep=True)
        
        extra_checks = result.get('extra_checks', [])
        year_found = any('year' in check.lower() for check in extra_checks)
        self.assertTrue(year_found)

    @patch('pwdchecker.utils.pwnedpasswords')
    def test_steps_populated(self, mock_hibp):
        """Steps should be populated with analysis log."""
        mock_hibp.Password.return_value.check.return_value = 0
        result = check_password_strength('test123')
        
        self.assertIsInstance(result['steps'], list)
        self.assertGreater(len(result['steps']), 0)


class TestGeneratePassphrase(TestCase):
    """Test Diceware-style passphrase generation."""

    def test_default_passphrase(self):
        """Default passphrase should have 4 words separated by dashes."""
        result = generate_passphrase()
        self.assertIn('passphrase', result)
        self.assertIn('entropy', result)
        pp = result['passphrase']
        self.assertEqual(len(pp.split('-')), 4)
        self.assertGreater(result['entropy'], 0)

    def test_custom_word_count(self):
        """Should respect custom word count."""
        result = generate_passphrase(word_count=6)
        self.assertEqual(len(result['passphrase'].split('-')), 6)
        self.assertEqual(result['word_count'], 6)

    def test_custom_separator(self):
        """Should use the given separator."""
        result = generate_passphrase(separator='.')
        self.assertEqual(result['separator'], '.')
        self.assertIn('.', result['passphrase'])

    def test_capitalize(self):
        """Each word should be capitalized when requested."""
        result = generate_passphrase(capitalize=True)
        words = result['passphrase'].split('-')
        for w in words:
            self.assertTrue(w[0].isupper(), f"'{w}' should start uppercase")

    def test_word_count_clamped_low(self):
        """Word count below 3 should be clamped to 3."""
        result = generate_passphrase(word_count=1)
        self.assertEqual(len(result['passphrase'].split('-')), 3)

    def test_word_count_clamped_high(self):
        """Word count above 10 should be clamped to 10."""
        result = generate_passphrase(word_count=20)
        self.assertEqual(len(result['passphrase'].split('-')), 10)

    def test_entropy_increases_with_words(self):
        """More words should produce higher entropy."""
        e4 = generate_passphrase(word_count=4)['entropy']
        e8 = generate_passphrase(word_count=8)['entropy']
        self.assertGreater(e8, e4)

    def test_randomness(self):
        """Two generated passphrases should (almost certainly) differ."""
        pp1 = generate_passphrase()['passphrase']
        pp2 = generate_passphrase()['passphrase']
        # Extremely unlikely they're equal with a large word list
        # Allow a rare collision but test several to be safe
        results = set(generate_passphrase()['passphrase'] for _ in range(5))
        self.assertGreater(len(results), 1)


class TestQuickScore(TestCase):
    """Test the quick_score utility function."""

    def test_weak_password(self):
        result = quick_score('123456')
        self.assertIn('score', result)
        self.assertIn('label', result)
        self.assertIn('entropy', result)
        self.assertIn('suggestions', result)
        self.assertLessEqual(result['score'], 1)

    def test_strong_password(self):
        result = quick_score('Xk9#mP!2vL@wQz$4')
        self.assertGreaterEqual(result['score'], 3)

    def test_returns_suggestions(self):
        result = quick_score('aaa')
        self.assertIsInstance(result['suggestions'], list)
        self.assertGreater(len(result['suggestions']), 0)
