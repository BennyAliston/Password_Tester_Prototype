// Password Analyzer JS - extracted from inline HTML

function togglePassword(inputId, checkbox) {
    const input = document.getElementById(inputId);
    if (input) {
        input.type = checkbox.checked ? 'text' : 'password';
    }
}

function suggestPassword() {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=~';
    let pwd = '';
    for (let i = 0; i < 16; i++) {
        pwd += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    document.getElementById('password').value = pwd;
    updateStrengthMeter();
}

function suggestComparePassword() {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=~';
    let pwd = '';
    for (let i = 0; i < 16; i++) {
        pwd += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    document.getElementById('compare_password').value = pwd;
}

function checkBreach(password) {
    // Placeholder for breach check logic
    return false;
}

function updateStrengthMeter() {
    // Placeholder for strength meter logic (zxcvbn integration, etc.)
    // You may want to call zxcvbn here if available
}

function copyToClipboard(id) {
    const el = document.getElementById(id);
    if (el) {
        navigator.clipboard.writeText(el.value || el.innerText);
        showCopyToast();
    }
}

function copyGenerated() {
    copyToClipboard('password');
}

function showFilename(input) {
    const label = document.getElementById('dict-upload-label');
    if (label && input.files.length > 0) {
        label.textContent = input.files[0].name;
    }
}

function showCopyToast() {
    const toast = document.getElementById('copy-toast');
    if (toast) {
        toast.style.display = 'block';
        toast.style.opacity = '0.97';
        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => { toast.style.display = 'none'; }, 400);
        }, 1100);
    }
}

function typeStep() {
    // Placeholder for typewriter effect logic
}
typeStep();
