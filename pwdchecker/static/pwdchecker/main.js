/**
 * Password Analyzer - Main JavaScript
 * =====================================
 * Handles password strength analysis, UI interactions, and HIBP breach checking.
 */

(function () {
    'use strict';

    // ==========================================================================
    // Configuration
    // ==========================================================================
    const CONFIG = {
        TOAST_DURATION: 2000,
        TYPEWRITER_CHAR_DELAY: 15,
        TYPEWRITER_LINE_DELAY: 250,
        HIBP_POLL_INTERVAL: 5000,
        HIBP_MAX_POLLS: 12,
        DEFAULT_PASSWORD_LENGTH: 14
    };

    // ==========================================================================
    // Password Visibility Toggle
    // ==========================================================================

    /**
     * Toggle password input visibility between text and password types.
     * @param {string} inputId - The ID of the input element
     * @param {HTMLInputElement} checkbox - The checkbox element
     */
    window.togglePassword = function (inputId, checkbox) {
        const input = document.getElementById(inputId);
        if (input) {
            input.type = checkbox.checked ? 'text' : 'password';
        }
    };

    // ==========================================================================
    // Password Generation
    // ==========================================================================

    /**
     * Build character set based on selected options.
     * @returns {string} The character set to use for generation
     */
    function buildCharset() {
        let charset = '';
        const optUpper = document.getElementById('opt_upper');
        const optLower = document.getElementById('opt_lower');
        const optNum = document.getElementById('opt_num');
        const optSym = document.getElementById('opt_sym');

        if (optUpper && optUpper.checked) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (optLower && optLower.checked) charset += 'abcdefghijklmnopqrstuvwxyz';
        if (optNum && optNum.checked) charset += '0123456789';
        if (optSym && optSym.checked) charset += '!@#$%^&*()-_=+[]{}';

        // Fallback charset if none selected
        if (!charset) {
            charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        }

        return charset;
    }

    /**
     * Generate a random password of specified length.
     * @param {number} length - Password length
     * @param {string} charset - Character set to use
     * @returns {string} Generated password
     */
    function generatePassword(length, charset) {
        let password = '';
        for (let i = 0; i < length; i++) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        return password;
    }

    /**
     * Suggest a strong password for the main password field.
     */
    window.suggestPassword = function () {
        const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}";
        const password = generatePassword(CONFIG.DEFAULT_PASSWORD_LENGTH, charset);

        const pwInput = document.getElementById('password');
        if (pwInput) {
            pwInput.value = password;
            if (typeof window.updateStrengthMeter === 'function') {
                window.updateStrengthMeter();
            }
        }
    };

    /**
     * Suggest a password for the comparison field based on user options.
     */
    window.suggestComparePassword = function () {
        const charset = buildCharset();
        const lenInput = document.getElementById('opt_len');
        const len = lenInput ? (parseInt(lenInput.value, 10) || CONFIG.DEFAULT_PASSWORD_LENGTH) : CONFIG.DEFAULT_PASSWORD_LENGTH;

        const password = generatePassword(len, charset);
        const pwInput = document.getElementById('compare_password');
        if (pwInput) {
            pwInput.value = password;
        }
    };

    // ==========================================================================
    // Clipboard Functions
    // ==========================================================================

    /**
     * Show the copy toast notification.
     */
    window.showCopyToast = function () {
        const toast = document.getElementById('copy-toast');
        if (toast) {
            toast.style.display = 'block';
            setTimeout(function () {
                toast.style.display = 'none';
            }, CONFIG.TOAST_DURATION);
        }
    };

    /**
     * Copy text from an element to clipboard.
     * @param {string} id - The ID of the element to copy from
     */
    window.copyToClipboard = function (id) {
        const el = document.getElementById(id);
        if (!el || !el.value) return;

        // Try modern clipboard API first
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(el.value)
                .then(window.showCopyToast)
                .catch(fallbackCopy);
        } else {
            fallbackCopy();
        }

        function fallbackCopy() {
            const temp = document.createElement('textarea');
            temp.value = el.value;
            temp.setAttribute('readonly', '');
            temp.style.position = 'absolute';
            temp.style.left = '-9999px';
            document.body.appendChild(temp);
            temp.select();
            try {
                document.execCommand('copy');
                window.showCopyToast();
            } catch (err) {
                console.error('Failed to copy:', err);
            }
            document.body.removeChild(temp);
        }
    };

    /**
     * Copy generated password.
     */
    window.copyGenerated = function () {
        const el = document.getElementById('genpw');
        if (el && el.textContent) {
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(el.textContent)
                    .then(window.showCopyToast)
                    .catch(function (err) {
                        console.error('Failed to copy:', err);
                    });
            }
        }
    };

    // ==========================================================================
    // File Upload
    // ==========================================================================

    /**
     * Display the selected filename for file uploads.
     * @param {HTMLInputElement} input - The file input element
     */
    window.showFilename = function (input) {
        const filenameEl = document.getElementById('filename');
        if (filenameEl && input.files.length > 0) {
            filenameEl.textContent = input.files[0].name;
        }
    };

    // ==========================================================================
    // Strength Meter (zxcvbn integration)
    // ==========================================================================

    /**
     * Update the password strength meter based on current input.
     */
    window.updateStrengthMeter = function () {
        const passwordInput = document.getElementById('password');
        const strengthBar = document.getElementById('strength-bar');
        const strengthFeedback = document.getElementById('strength-feedback');
        const policyList = document.getElementById('policy-list');
        const entropyDisplay = document.getElementById('entropy-display');

        if (!passwordInput || !strengthBar) return;

        const password = passwordInput.value;

        if (!password) {
            strengthBar.style.width = '0%';
            strengthBar.style.background = '#39ff14';
            if (strengthFeedback) strengthFeedback.textContent = '';
            if (policyList) policyList.innerHTML = '';
            if (entropyDisplay) entropyDisplay.textContent = '';
            return;
        }

        // Use zxcvbn if available
        if (typeof zxcvbn === 'function') {
            const result = zxcvbn(password);
            const score = result.score;
            const percent = ((score + 1) / 5) * 100;

            const colors = ['#ff3333', '#ff6600', '#ffcc00', '#66cc00', '#39ff14'];
            const labels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];

            strengthBar.style.width = percent + '%';
            strengthBar.style.background = colors[score];

            if (strengthFeedback) {
                strengthFeedback.textContent = labels[score];
                strengthFeedback.style.color = colors[score];
            }

            // Display suggestions
            if (policyList) {
                let html = '';
                if (result.feedback.warning) {
                    html += '<li style="color:#ffcc00;">⚠️ ' + result.feedback.warning + '</li>';
                }
                result.feedback.suggestions.forEach(function (s) {
                    html += '<li>💡 ' + s + '</li>';
                });
                policyList.innerHTML = html;
            }

            // Display entropy estimate
            if (entropyDisplay) {
                const crackTime = result.crack_times_display.offline_slow_hashing_1e4_per_second;
                entropyDisplay.innerHTML = '<b>Crack time estimate:</b> ' + crackTime;
            }
        }
    };

    // ==========================================================================
    // Typewriter Effect
    // ==========================================================================

    /**
     * Initialize typewriter effect for hacker steps display.
     */
    window.initTypewriter = function () {
        const stepsElement = document.getElementById('hackerSteps');
        const output = document.getElementById('terminal-output');

        if (!stepsElement || !output) return;

        let steps;
        try {
            steps = JSON.parse(stepsElement.textContent);
        } catch (e) {
            console.error('Failed to parse hacker steps:', e);
            return;
        }

        let line = 0, char = 0;

        function typeStep() {
            if (line < steps.length) {
                if (char < steps[line].length) {
                    output.textContent += steps[line][char++];
                    setTimeout(typeStep, CONFIG.TYPEWRITER_CHAR_DELAY);
                } else {
                    output.textContent += '\n';
                    line++;
                    char = 0;
                    setTimeout(typeStep, CONFIG.TYPEWRITER_LINE_DELAY);
                }
            }
        }

        typeStep();
    };

    // ==========================================================================
    // HIBP Polling
    // ==========================================================================

    /**
     * Initialize HIBP status polling.
     * @param {string} token - The HIBP token to poll for
     * @param {string} statusUrl - The URL to poll for status
     */
    window.initHibpPolling = function (token, statusUrl) {
        if (!token) return;

        async function pollOnce() {
            const url = statusUrl + '?token=' + encodeURIComponent(token);
            try {
                const response = await fetch(url, { cache: 'no-store' });
                if (!response.ok) return false;

                const data = await response.json();
                if (data.status === 'ready') {
                    const count = data.hibp_count;
                    const el = document.getElementById('breach-warning');
                    if (!el) return true;

                    if (count && count > 0) {
                        el.textContent = 'Found in ' + count + ' breaches!';
                        el.className = 'breach-indicator breached';
                    } else if (count === 0) {
                        el.textContent = 'Not found in breaches.';
                        el.className = 'breach-indicator not-breached';
                    } else {
                        el.textContent = 'HIBP check error.';
                        el.className = 'error';
                    }
                    return true;
                }
            } catch (e) {
                console.error('HIBP poll error:', e);
            }
            return false;
        }

        (async function pollLoop() {
            for (let i = 0; i < CONFIG.HIBP_MAX_POLLS; i++) {
                const done = await pollOnce();
                if (done) break;
                await new Promise(function (resolve) {
                    setTimeout(resolve, CONFIG.HIBP_POLL_INTERVAL);
                });
            }
        })();
    };

    // ==========================================================================
    // Dark Web Scan Animation
    // ==========================================================================

    /**
     * Initialize the dark web scan animation.
     * @param {number} hibpCount - The HIBP breach count
     */
    window.initDarkwebScan = function (hibpCount) {
        const scanContainer = document.getElementById('darkwebScanContainer');
        const indicatorContainer = document.getElementById('breachIndicatorContainer');

        if (!scanContainer || !indicatorContainer) return;

        scanContainer.innerHTML = '<div class="darkweb-scan"><div class="darkweb-spinner"></div>Scanning the dark web for breaches...</div>';

        setTimeout(function () {
            scanContainer.innerHTML = '';
            indicatorContainer.style.display = 'flex';

            if (hibpCount > 0) {
                indicatorContainer.innerHTML =
                    '<div class="breach-indicator breached">🛡️ <span style="font-size:1.1em;">' +
                    '<b>Warning!</b><br>Your password has been found in known data leaks.<br><br>' +
                    '<b>What does this mean?</b><br>Hackers may already know your password.<br><br>' +
                    '<b>What should you do?</b><ul style="text-align:left; margin: 0 0 0 1.2em;">' +
                    '<li>Stop using this password immediately.</li>' +
                    '<li>Create a new, strong password that you have never used before.</li>' +
                    '<li>Never reuse passwords across different websites.</li>' +
                    '</ul></span></div>';
            } else if (hibpCount === 0) {
                indicatorContainer.innerHTML =
                    '<div class="breach-indicator not-breached">🔒 <span style="font-size:1.1em;">' +
                    '<b>Good news!</b><br>Your password was not found in any known data leaks.<br><br>' +
                    'This does not guarantee it is 100% safe.<br>' +
                    '<b>Tips:</b> Make sure your password is long, unique, and hard to guess.</span></div>';
            } else {
                indicatorContainer.innerHTML =
                    '<div class="breach-indicator" style="color:#ffcc00;border:1.5px solid #ffcc00;background:rgba(255,204,0,0.09);">' +
                    '🔎 <span style="font-size:1.1em;"><b>Scan result unknown</b><br>' +
                    'We couldn\'t check your password due to a network error. Please try again later.</span></div>';
            }
        }, 1800);
    };

    // ==========================================================================
    // Initialization
    // ==========================================================================

    // Add input event listener for real-time strength updates
    document.addEventListener('DOMContentLoaded', function () {
        const passwordInput = document.getElementById('password');
        if (passwordInput) {
            passwordInput.addEventListener('input', window.updateStrengthMeter);
        }

        // Initialize typewriter if hacker steps exist
        if (document.getElementById('hackerSteps')) {
            window.initTypewriter();
        }
    });

})();
