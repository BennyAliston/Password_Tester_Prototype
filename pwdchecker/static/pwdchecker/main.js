/**
 * Password Breach Analyzer - Main JavaScript
 * =============================================
 * Handles password strength analysis, UI interactions, navigation,
 * animations, and HIBP breach checking.
 */

(function () {
    'use strict';

    // ==========================================================================
    // Configuration
    // ==========================================================================
    var CONFIG = {
        TOAST_DURATION: 2000,
        TYPEWRITER_CHAR_DELAY: 15,
        TYPEWRITER_LINE_DELAY: 250,
        HIBP_POLL_INTERVAL: 5000,
        HIBP_MAX_POLLS: 12,
        DEFAULT_PASSWORD_LENGTH: 14,
        NAV_SCROLL_THRESHOLD: 80,
        SCROLL_TO_RESULTS_DELAY: 400
    };

    // ==========================================================================
    // Navigation
    // ==========================================================================

    /**
     * Initialize sticky navigation, active link tracking, and hamburger menu.
     */
    function initNavigation() {
        var nav = document.getElementById('site-nav');
        var links = document.querySelectorAll('.site-nav__link');
        var sections = document.querySelectorAll('section[id]');
        var hamburger = document.querySelector('.site-nav__hamburger');

        if (!nav) return;

        // Sticky nav background on scroll
        function updateNav() {
            if (window.scrollY > CONFIG.NAV_SCROLL_THRESHOLD) {
                nav.classList.add('site-nav--scrolled');
            } else {
                nav.classList.remove('site-nav--scrolled');
            }
        }
        window.addEventListener('scroll', updateNav, { passive: true });
        updateNav();

        // Active link tracking via Intersection Observer
        if ('IntersectionObserver' in window && sections.length > 0) {
            var observer = new IntersectionObserver(function (entries) {
                entries.forEach(function (entry) {
                    if (entry.isIntersecting) {
                        links.forEach(function (link) {
                            link.classList.remove('site-nav__link--active');
                            if (link.getAttribute('href') === '#' + entry.target.id) {
                                link.classList.add('site-nav__link--active');
                            }
                        });
                    }
                });
            }, { rootMargin: '-40% 0px -50% 0px', threshold: 0 });

            sections.forEach(function (section) {
                observer.observe(section);
            });
        }

        // Hamburger toggle
        if (hamburger) {
            hamburger.addEventListener('click', function () {
                nav.classList.toggle('site-nav--open');
                var expanded = hamburger.getAttribute('aria-expanded') === 'true';
                hamburger.setAttribute('aria-expanded', String(!expanded));
            });

            // Close menu on link click (mobile)
            links.forEach(function (link) {
                link.addEventListener('click', function () {
                    nav.classList.remove('site-nav--open');
                    hamburger.setAttribute('aria-expanded', 'false');
                });
            });
        }
    }

    // ==========================================================================
    // Scroll Animations
    // ==========================================================================

    /**
     * Initialize entrance animations using Intersection Observer.
     */
    function initScrollAnimations() {
        var elements = document.querySelectorAll('.animate-on-scroll');
        if (!elements.length || !('IntersectionObserver' in window)) {
            // If no IntersectionObserver, show all elements immediately
            elements.forEach(function (el) {
                el.classList.add('is-visible');
            });
            return;
        }

        var observer = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (entry.isIntersecting) {
                    entry.target.classList.add('is-visible');
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.1 });

        elements.forEach(function (el) {
            observer.observe(el);
        });
    }

    // ==========================================================================
    // Auto-scroll to Results
    // ==========================================================================

    /**
     * Smoothly scroll to results section if it exists (after POST).
     */
    function scrollToResultsIfPresent() {
        var resultsSection = document.getElementById('results');
        if (resultsSection) {
            setTimeout(function () {
                resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }, CONFIG.SCROLL_TO_RESULTS_DELAY);
        }
    }

    // ==========================================================================
    // Score Badge Animation
    // ==========================================================================

    /**
     * Animate the score badge ring fill based on data-score attribute.
     */
    function initScoreBadge() {
        var badges = document.querySelectorAll('.score-badge');
        badges.forEach(function (badge) {
            var score = parseInt(badge.getAttribute('data-score'), 10);
            if (isNaN(score)) return;
            var fill = badge.querySelector('.score-badge__fill');
            if (!fill) return;
            // circumference = 2 * PI * r = 2 * 3.14159 * 45 = ~283
            var circumference = 283;
            var offset = circumference - (circumference * (score + 1) / 5);
            setTimeout(function () {
                fill.style.strokeDashoffset = offset;
            }, 300);
        });
    }

    // ==========================================================================
    // Password Visibility Toggle
    // ==========================================================================

    /**
     * Toggle password input visibility with SVG icon swap.
     * @param {string} inputId - The ID of the input element
     * @param {HTMLElement} button - The toggle button element
     */
    window.togglePasswordVisibility = function (inputId, button) {
        var input = document.getElementById(inputId);
        if (!input) return;

        var isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';

        // Swap icon
        var use = button.querySelector('use');
        if (use) {
            use.setAttribute('href', isPassword ? '#icon-eye-off' : '#icon-eye');
        }
    };

    // Keep backward compatibility
    window.togglePassword = function (inputId, checkbox) {
        var input = document.getElementById(inputId);
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
        var charset = '';
        var optUpper = document.getElementById('opt_upper');
        var optLower = document.getElementById('opt_lower');
        var optNum = document.getElementById('opt_num');
        var optSym = document.getElementById('opt_sym');

        if (optUpper && optUpper.checked) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (optLower && optLower.checked) charset += 'abcdefghijklmnopqrstuvwxyz';
        if (optNum && optNum.checked) charset += '0123456789';
        if (optSym && optSym.checked) charset += '!@#$%^&*()-_=+[]{}';

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
        var password = '';
        for (var i = 0; i < length; i++) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        return password;
    }

    /**
     * Suggest a strong password for the main password field.
     */
    window.suggestPassword = function () {
        var charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}';
        var password = generatePassword(CONFIG.DEFAULT_PASSWORD_LENGTH, charset);

        var pwInput = document.getElementById('password');
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
        var charset = buildCharset();
        var lenInput = document.getElementById('opt_len');
        var len = lenInput ? (parseInt(lenInput.value, 10) || CONFIG.DEFAULT_PASSWORD_LENGTH) : CONFIG.DEFAULT_PASSWORD_LENGTH;

        var password = generatePassword(len, charset);
        var pwInput = document.getElementById('compare_password');
        if (pwInput) {
            pwInput.value = password;
        }
    };

    // ==========================================================================
    // Range Slider
    // ==========================================================================

    /**
     * Initialize range slider with live readout.
     */
    function initRangeSlider() {
        var rangeInput = document.getElementById('opt_len');
        var rangeReadout = document.getElementById('opt_len_readout');
        if (rangeInput && rangeReadout) {
            rangeReadout.textContent = rangeInput.value;
            rangeInput.addEventListener('input', function () {
                rangeReadout.textContent = this.value;
            });
        }
    }

    // ==========================================================================
    // Clipboard Functions
    // ==========================================================================

    /**
     * Show the copy toast notification.
     */
    window.showCopyToast = function () {
        var toast = document.getElementById('copy-toast');
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
        var el = document.getElementById(id);
        if (!el || !el.value) return;

        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(el.value)
                .then(window.showCopyToast)
                .catch(fallbackCopy);
        } else {
            fallbackCopy();
        }

        function fallbackCopy() {
            var temp = document.createElement('textarea');
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
        var el = document.getElementById('genpw');
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
        var filenameEl = document.getElementById('filename');
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
        var passwordInput = document.getElementById('password');
        var strengthBar = document.getElementById('strength-bar');
        var strengthFeedback = document.getElementById('strength-feedback');
        var policyList = document.getElementById('policy-list');
        var entropyDisplay = document.getElementById('entropy-display');

        if (!passwordInput || !strengthBar) return;

        var password = passwordInput.value;

        if (!password) {
            strengthBar.style.width = '0%';
            strengthBar.style.background = '#39ff14';
            if (strengthFeedback) strengthFeedback.textContent = '';
            if (policyList) policyList.innerHTML = '';
            if (entropyDisplay) entropyDisplay.textContent = '';
            return;
        }

        if (typeof zxcvbn === 'function') {
            var result = zxcvbn(password);
            var score = result.score;
            var percent = ((score + 1) / 5) * 100;

            var colors = ['#ff3333', '#ff6600', '#ffcc00', '#66cc00', '#39ff14'];
            var labels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];

            strengthBar.style.width = percent + '%';
            strengthBar.style.background = colors[score];

            if (strengthFeedback) {
                strengthFeedback.textContent = labels[score];
                strengthFeedback.style.color = colors[score];
            }

            if (policyList) {
                var html = '';
                if (result.feedback.warning) {
                    html += '<li style="color:var(--color-warning);">' + result.feedback.warning + '</li>';
                }
                result.feedback.suggestions.forEach(function (s) {
                    html += '<li>' + s + '</li>';
                });
                policyList.innerHTML = html;
            }

            if (entropyDisplay) {
                var crackTime = result.crack_times_display.offline_slow_hashing_1e4_per_second;
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
        var stepsElement = document.getElementById('hackerSteps');
        var output = document.getElementById('terminal-output');

        if (!stepsElement || !output) return;

        var steps;
        try {
            steps = JSON.parse(stepsElement.textContent);
        } catch (e) {
            console.error('Failed to parse hacker steps:', e);
            return;
        }

        var line = 0, char = 0;

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
            var url = statusUrl + '?token=' + encodeURIComponent(token);
            try {
                var response = await fetch(url, { cache: 'no-store' });
                if (!response.ok) return false;

                var data = await response.json();
                if (data.status === 'ready') {
                    var count = data.hibp_count;
                    var el = document.getElementById('breach-warning');
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
            for (var i = 0; i < CONFIG.HIBP_MAX_POLLS; i++) {
                var done = await pollOnce();
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
        var scanContainer = document.getElementById('darkwebScanContainer');
        var indicatorContainer = document.getElementById('breachIndicatorContainer');

        if (!scanContainer || !indicatorContainer) return;

        scanContainer.innerHTML = '<div class="darkweb-scan"><div class="darkweb-spinner"></div>Scanning dark web for breaches...</div>';

        setTimeout(function () {
            scanContainer.innerHTML = '';
            indicatorContainer.style.display = 'flex';

            if (hibpCount > 0) {
                indicatorContainer.innerHTML =
                    '<div class="breach-indicator breached">' +
                    '<span style="font-size:1.5em;line-height:1;">&#128721;</span>' +
                    '<span>' +
                    '<b>Warning!</b><br>Your password has been found in known data leaks.<br><br>' +
                    '<b>What does this mean?</b><br>Hackers may already know your password.<br><br>' +
                    '<b>What should you do?</b><ul>' +
                    '<li>Stop using this password immediately.</li>' +
                    '<li>Create a new, strong password that you have never used before.</li>' +
                    '<li>Never reuse passwords across different websites.</li>' +
                    '</ul></span></div>';
            } else if (hibpCount === 0) {
                indicatorContainer.innerHTML =
                    '<div class="breach-indicator not-breached">' +
                    '<span style="font-size:1.5em;line-height:1;">&#128274;</span>' +
                    '<span>' +
                    '<b>Good news!</b><br>Your password was not found in any known data leaks.<br><br>' +
                    'This does not guarantee it is 100% safe.<br>' +
                    '<b>Tips:</b> Make sure your password is long, unique, and hard to guess.</span></div>';
            } else {
                indicatorContainer.innerHTML =
                    '<div class="breach-indicator" style="color:var(--color-warning);border:1px solid rgba(255,204,0,0.3);background:rgba(255,204,0,0.08);">' +
                    '<span style="font-size:1.5em;line-height:1;">&#128270;</span>' +
                    '<span><b>Scan result unknown</b><br>' +
                    'We couldn\'t check your password due to a network error. Please try again later.</span></div>';
            }
        }, 1800);
    };

    // ==========================================================================
    // Initialization
    // ==========================================================================

    document.addEventListener('DOMContentLoaded', function () {
        // Navigation
        initNavigation();

        // Scroll animations
        initScrollAnimations();

        // Range slider
        initRangeSlider();

        // Password strength meter
        var passwordInput = document.getElementById('password');
        if (passwordInput) {
            passwordInput.addEventListener('input', window.updateStrengthMeter);
        }

        // Typewriter effect
        if (document.getElementById('hackerSteps')) {
            window.initTypewriter();
        }

        // Score badge animation
        initScoreBadge();

        // Auto-scroll to results after POST
        scrollToResultsIfPresent();
    });

})();
