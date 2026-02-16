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
    // Passphrase Generator
    // ==========================================================================

    /**
     * Generate a Diceware-style passphrase via AJAX.
     */
    window.generatePassphrase = function () {
        var wordCount = document.getElementById('pp_word_count');
        var separator = document.getElementById('pp_separator');
        var capitalize = document.getElementById('pp_capitalize');
        var outputText = document.getElementById('passphrase-text');
        var entropyEl = document.getElementById('passphrase-entropy');

        if (!outputText) return;

        var params = new URLSearchParams();
        params.set('word_count', wordCount ? wordCount.value : '4');
        params.set('separator', separator ? separator.value : '-');
        if (capitalize && capitalize.checked) params.set('capitalize', 'on');

        var url = (window.PBA_URLS && window.PBA_URLS.generatePassphrase) || '/generate-passphrase/';

        outputText.textContent = 'Generating...';
        if (entropyEl) entropyEl.textContent = '';

        fetch(url, {
            method: 'POST',
            headers: {
                'X-CSRFToken': window.PBA_CSRF || '',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: params.toString(),
        })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                outputText.textContent = 'Error: ' + data.error;
                return;
            }
            outputText.textContent = data.passphrase || '';
            if (entropyEl && data.entropy) {
                entropyEl.innerHTML = '<svg class="icon" style="width:14px;height:14px;vertical-align:middle;"><use href="#icon-zap"/></svg> ' +
                    '<b>' + data.entropy + '</b> bits of entropy &mdash; ' + data.word_count + ' words';
            }
        })
        .catch(function (err) {
            outputText.textContent = 'Network error.';
            console.error('Passphrase generation error:', err);
        });
    };

    /**
     * Copy passphrase to clipboard.
     */
    window.copyPassphrase = function () {
        var el = document.getElementById('passphrase-text');
        if (!el || !el.textContent || el.textContent.startsWith('Click') || el.textContent.startsWith('Generating')) return;
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(el.textContent)
                .then(window.showCopyToast)
                .catch(function () {});
        }
    };

    /**
     * Initialize passphrase word-count slider readout.
     */
    function initPassphraseSlider() {
        var slider = document.getElementById('pp_word_count');
        var readout = document.getElementById('pp_word_count_readout');
        if (slider && readout) {
            readout.textContent = slider.value;
            slider.addEventListener('input', function () {
                readout.textContent = this.value;
            });
        }
    }

    // ==========================================================================
    // Score History Chart (Canvas-based)
    // ==========================================================================

    /**
     * Draw a simple line/bar chart of score history on a canvas.
     * @param {number[]} scores - Array of scores (0-4)
     */
    window.initScoreHistoryChart = function (scores) {
        var canvas = document.getElementById('score-chart');
        var infoEl = document.getElementById('score-history-info');
        if (!canvas) return;

        var ctx = canvas.getContext('2d');
        if (!ctx) return;

        // Use actual display size
        var dpr = window.devicePixelRatio || 1;
        var rect = canvas.parentElement.getBoundingClientRect();
        var w = rect.width || 600;
        var h = 200;
        canvas.width = w * dpr;
        canvas.height = h * dpr;
        canvas.style.width = w + 'px';
        canvas.style.height = h + 'px';
        ctx.scale(dpr, dpr);

        // Clear
        ctx.clearRect(0, 0, w, h);

        if (!scores || scores.length === 0) {
            ctx.fillStyle = 'rgba(255,255,255,0.3)';
            ctx.font = '14px Inter, sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('No scores yet. Analyze some passwords to see your trend.', w / 2, h / 2);
            if (infoEl) infoEl.textContent = '';
            return;
        }

        var colors = ['#ff3333', '#ff6600', '#ffcc00', '#66cc00', '#39ff14'];
        var labels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
        var padding = { top: 30, right: 20, bottom: 40, left: 40 };
        var chartW = w - padding.left - padding.right;
        var chartH = h - padding.top - padding.bottom;

        // Draw grid lines
        ctx.strokeStyle = 'rgba(255,255,255,0.08)';
        ctx.lineWidth = 1;
        for (var g = 0; g <= 4; g++) {
            var gy = padding.top + chartH - (g / 4) * chartH;
            ctx.beginPath();
            ctx.moveTo(padding.left, gy);
            ctx.lineTo(w - padding.right, gy);
            ctx.stroke();

            // Y-axis labels
            ctx.fillStyle = 'rgba(255,255,255,0.4)';
            ctx.font = '11px Inter, sans-serif';
            ctx.textAlign = 'right';
            ctx.fillText(String(g), padding.left - 8, gy + 4);
        }

        // Draw bars
        var barMaxWidth = 40;
        var gap = 4;
        var totalBarSpace = chartW / scores.length;
        var barWidth = Math.min(barMaxWidth, totalBarSpace - gap);

        for (var i = 0; i < scores.length; i++) {
            var s = scores[i];
            var barH = (s / 4) * chartH;
            if (barH < 4) barH = 4; // minimum visible height
            var x = padding.left + i * totalBarSpace + (totalBarSpace - barWidth) / 2;
            var y = padding.top + chartH - barH;

            // Bar with color
            ctx.fillStyle = colors[s] || '#888';
            ctx.beginPath();
            // Rounded top
            var radius = Math.min(4, barWidth / 2);
            ctx.moveTo(x, y + radius);
            ctx.arcTo(x, y, x + barWidth, y, radius);
            ctx.arcTo(x + barWidth, y, x + barWidth, y + barH, radius);
            ctx.lineTo(x + barWidth, padding.top + chartH);
            ctx.lineTo(x, padding.top + chartH);
            ctx.closePath();
            ctx.fill();

            // Score label on top
            ctx.fillStyle = 'rgba(255,255,255,0.7)';
            ctx.font = '10px Inter, sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText(String(s), x + barWidth / 2, y - 6);

            // X-axis: test number
            ctx.fillStyle = 'rgba(255,255,255,0.35)';
            ctx.fillText('#' + (i + 1), x + barWidth / 2, padding.top + chartH + 18);
        }

        // Title
        ctx.fillStyle = 'rgba(255,255,255,0.5)';
        ctx.font = '12px Inter, sans-serif';
        ctx.textAlign = 'left';
        ctx.fillText('Score (0-4)', padding.left, 16);

        // Info text
        if (infoEl) {
            var avg = scores.reduce(function (a, b) { return a + b; }, 0) / scores.length;
            var latest = scores[scores.length - 1];
            infoEl.innerHTML =
                '<span style="color:' + colors[latest] + ';">Latest: ' + labels[latest] + ' (' + latest + '/4)</span>' +
                ' &bull; Average: ' + avg.toFixed(1) + '/4' +
                ' &bull; Tests: ' + scores.length;
        }
    };

    /**
     * Clear score history via AJAX and redraw chart.
     */
    window.clearScoreHistory = function () {
        var url = (window.PBA_URLS && window.PBA_URLS.clearScoreHistory) || '/clear-score-history/';
        fetch(url, {
            method: 'POST',
            headers: { 'X-CSRFToken': window.PBA_CSRF || '' },
        })
        .then(function () {
            window.initScoreHistoryChart([]);
        })
        .catch(function (err) {
            console.error('Clear history error:', err);
        });
    };

    // ==========================================================================
    // Bulk Password Audit
    // ==========================================================================

    /**
     * Show selected filename for bulk file upload.
     */
    window.showBulkFilename = function (input) {
        var el = document.getElementById('bulk-filename');
        if (el && input.files.length > 0) {
            el.textContent = input.files[0].name;
        }
    };

    /**
     * Run bulk password audit via AJAX.
     */
    window.runBulkAudit = function () {
        var textarea = document.getElementById('bulk_passwords');
        var fileInput = document.getElementById('bulk_file');
        var statusEl = document.getElementById('bulk-audit-status');
        var resultsEl = document.getElementById('bulk-audit-results');

        if (!statusEl || !resultsEl) return;

        var formData = new FormData();
        var hasText = textarea && textarea.value.trim();
        var hasFile = fileInput && fileInput.files.length > 0;

        if (!hasText && !hasFile) {
            statusEl.innerHTML = '<span class="error">Please enter passwords or upload a file.</span>';
            return;
        }

        if (hasText) formData.append('bulk_passwords', textarea.value);
        if (hasFile) formData.append('bulk_file', fileInput.files[0]);

        statusEl.innerHTML = '<div class="darkweb-scan"><div class="darkweb-spinner"></div>Analyzing passwords...</div>';
        resultsEl.innerHTML = '';

        var url = (window.PBA_URLS && window.PBA_URLS.bulkAudit) || '/bulk-audit/';

        fetch(url, {
            method: 'POST',
            headers: { 'X-CSRFToken': window.PBA_CSRF || '' },
            body: formData,
        })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                statusEl.innerHTML = '<span class="error">' + data.error + '</span>';
                return;
            }

            var colors = ['#ff3333', '#ff6600', '#ffcc00', '#66cc00', '#39ff14'];
            var labelMap = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];

            statusEl.innerHTML = '<b>' + data.count + '</b> password(s) analyzed.' +
                (data.truncated ? ' <span class="error">(Truncated to 100)</span>' : '');

            var html = '<div class="bulk-table-wrap"><table class="bulk-table">' +
                '<thead><tr><th>#</th><th>Password</th><th>Length</th><th>Score</th><th>Entropy</th><th>Suggestions</th></tr></thead><tbody>';

            data.results.forEach(function (r) {
                var color = colors[r.score] || '#888';
                html += '<tr>' +
                    '<td>' + r.index + '</td>' +
                    '<td class="mono">' + escapeHtml(r.masked) + '</td>' +
                    '<td>' + r.length + '</td>' +
                    '<td><span class="bulk-score" style="background:' + color + ';">' + r.score + '/4 ' + r.label + '</span></td>' +
                    '<td>' + r.entropy + ' bits</td>' +
                    '<td>' + (r.suggestions.length > 0 ? escapeHtml(r.suggestions.join('; ')) : '<span style="color:var(--color-primary);">OK</span>') + '</td>' +
                    '</tr>';
            });

            html += '</tbody></table></div>';
            resultsEl.innerHTML = html;
        })
        .catch(function (err) {
            statusEl.innerHTML = '<span class="error">Network error. Please try again.</span>';
            console.error('Bulk audit error:', err);
        });
    };

    /**
     * Escape HTML to prevent XSS in bulk results.
     */
    function escapeHtml(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

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

        // Passphrase slider
        initPassphraseSlider();

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
