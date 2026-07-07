
// ============================================================
// HashFunction enum (matches backend)
// ============================================================
var HashFunction = {
    FN_NOTFOUND: 500,
    FN_PLAIN: 0,
    FN_SHA256: 1,
    FN_SHA512: 2,
    FN_SSHA256: 3,
    FN_SSHA512: 4,
    FN_GAUTHTIME: 5
};

/**
 * Get human-readable name for the hash function
 */
function formatFunctionName(fn) {
    switch (fn) {
        case 0: return 'Plain Text';
        case 1: return 'SHA-256';
        case 2: return 'SHA-512';
        case 3: return 'SSHA-256';
        case 4: return 'SSHA-512';
        case 5: return 'Time-based OTP Token (TOTP)';
        default: return 'Unknown';
    }
}

function generateRandomSalt() {
    var crypto = window.crypto || window.msCrypto;
    var bytes = new Uint8Array(4);
    crypto.getRandomValues(bytes);
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex.toUpperCase();
}

/**
 * Calcula el hash replicando exactamente la lógica de C++:
 * Hash(password_bytes + salt_bytes)
 */
function computePasswordHash(password, passwordFunction, existingSalt = null) {
    var result = {
        hash: '',
        ssalt: 'FFFFFFFF'
    };

    // Helper: convierte un string a cadena hex (bytes UTF-8).
    // Para contraseñas ASCII (como "abc123") coincide exactamente con C++ std::string.
    function strToHex(str) {
        if (typeof TextEncoder !== 'undefined') {
            var bytes = new TextEncoder().encode(str); // Uint8Array
            var hex = '';
            for (var i = 0; i < bytes.length; i++) {
                var b = bytes[i];
                hex += (b < 16 ? '0' : '') + b.toString(16);
            }
            return hex.toUpperCase();
        } else {
            // Fallback para entornos muy antiguos (ASCII puro)
            var hex = '';
            for (var i = 0; i < str.length; i++) {
                var b = str.charCodeAt(i);
                hex += (b < 16 ? '0' : '') + b.toString(16);
            }
            return hex.toUpperCase();
        }
    }

    switch (passwordFunction) {
        case HashFunction.FN_SHA256:
        case HashFunction.FN_SHA512:
            var algo = passwordFunction === HashFunction.FN_SHA256 ? 'SHA-256' : 'SHA-512';
            var sha = new jsSHA(algo, 'TEXT');
            sha.update(password);
            result.hash = sha.getHash('HEX').toUpperCase();
            result.ssalt = 'FFFFFFFF';
            break;

        case HashFunction.FN_SSHA256:
        case HashFunction.FN_SSHA512:
            var sAlgo = passwordFunction === HashFunction.FN_SSHA256 ? 'SHA-256' : 'SHA-512';

            // Validar que sea exactamente 8 caracteres hexadecimales (4 bytes)
            var saltHex = (existingSalt && /^[0-9A-Fa-f]{8}$/.test(existingSalt))
                ? existingSalt.toUpperCase()
                : generateRandomSalt();
            result.ssalt = saltHex;

            var combinedHex = strToHex(password) + saltHex;
            var ssha = new jsSHA(sAlgo, 'HEX');
            ssha.update(combinedHex);
            result.hash = ssha.getHash('HEX').toUpperCase();
            break;

        case HashFunction.FN_PLAIN:
            result.hash = password;
            result.ssalt = 'FFFFFFFF';
            break;

        default:
            throw new Error('Unsupported password function: ' + passwordFunction);
    }
    return result;
}



// ============================================================
// Helper Functions
// ============================================================

/**
 * Check if the function is a password-type function (0-4)
 */
function isFunctionPassword(fn) {
    return fn >= 0 && fn <= 4;
}

/**
 * Check if the function is a TOTP/OTP function (5)
 */
function isFunctionOTP(fn) {
    return fn === 5;
}

/**
 * Get FontAwesome icon for the credential type
 */
function getCredentialIcon(fn) {
    if (isFunctionOTP(fn)) {
        return '<i class="fa-solid fa-clock text-success"></i>';
    }
    return '<i class="fa-solid fa-lock text-primary"></i>';
}

// ============================================================
// Common Passwords List (Client-Side Validation)
// ============================================================
var COMMON_PASSWORDS = [
    'password', '123456', '123456789', '12345678', '12345',
    'qwerty', 'abc123', 'monkey', '1234567', 'letmein',
    'trustno1', 'dragon', 'baseball', 'iloveyou', 'master',
    'sunshine', 'ashley', 'bailey', 'shadow', '123123',
    '654321', 'superman', 'qazwsx', 'michael', 'football',
    'password1', 'password123', '1234', '1234567890', '111111',
    '12345678910', '000000', '123456789a', 'admin', 'admin123',
    'welcome', 'welcome1', 'login', 'passw0rd', 'starwars',
    'solo', 'mustang', 'matrix', 'princess', 'flower',
    'hannah', 'amateur', 'jordan', 'hunter', 'freedom',
    'computer', 'batman', 'pepper', 'whatever', 'summer',
    'corvette', 'jessica', 'hardcore', 'ginger', 'secret',
    'test', 'test123', 'guest', 'changeme', 'please'
];

/**
 * Set for O(1) common-password lookup (case-insensitive).
 * Built once at module load for fast repeated checks.
 */
var COMMON_PASSWORDS_SET = (function() {
    var set = {};
    for (var i = 0; i < COMMON_PASSWORDS.length; i++) {
        set[COMMON_PASSWORDS[i].toLowerCase()] = true;
    }
    return set;
})();

// ============================================================
// Password Strength Validation (Client-Side)
// ============================================================

/**
 * Validate password against strength rules JSON.
 * Returns an object with:
 *   - valid: boolean
 *   - checks: array of { id, label, passed, failed }
 */
function validatePasswordAgainstStrength(currentPassword, password, rules, userLogins) {
    var checks = [];

    if (!rules || !rules.enabled) {
        return { valid: true, checks: checks };
    }

    // 1. Min Length
    if (rules.minLength > 0) {
        var passed = password.length >= rules.minLength;
        checks.push({
            id: 'minLength',
            label: 'At least ' + rules.minLength + ' characters',
            passed: passed
        });
    }

    // 2. Max Length
    if (rules.maxLength > 0) {
        var passed = password.length <= rules.maxLength;
        checks.push({
            id: 'maxLength',
            label: 'At most ' + rules.maxLength + ' characters',
            passed: passed
        });
    }

    // 3. Uppercase
    if (rules.requireUppercase && rules.minUppercase > 0) {
        var count = (password.match(/[A-Z]/g) || []).length;
        var passed = count >= rules.minUppercase;
        checks.push({
            id: 'uppercase',
            label: 'At least ' + rules.minUppercase + ' uppercase letter(s)',
            passed: passed
        });
    }

    // 4. Lowercase
    if (rules.requireLowercase && rules.minLowercase > 0) {
        var count = (password.match(/[a-z]/g) || []).length;
        var passed = count >= rules.minLowercase;
        checks.push({
            id: 'lowercase',
            label: 'At least ' + rules.minLowercase + ' lowercase letter(s)',
            passed: passed
        });
    }

    // 5. Digits
    if (rules.requireDigits && rules.minDigits > 0) {
        var count = (password.match(/[0-9]/g) || []).length;
        var passed = count >= rules.minDigits;
        checks.push({
            id: 'digits',
            label: 'At least ' + rules.minDigits + ' digit(s)',
            passed: passed
        });
    }

    // 6. Special Characters
    if (rules.requireSpecial && rules.minSpecial > 0 && rules.specialCharacters) {
        var escaped = rules.specialCharacters.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
        var regex = new RegExp('[' + escaped + ']');
        var count = (password.match(regex) || []).length;
        var passed = count >= rules.minSpecial;
        checks.push({
            id: 'special',
            label: 'At least ' + rules.minSpecial + ' special character(s)',
            passed: passed
        });
    }

    // 7. Max Consecutive same character
    if (rules.maxConsecutiveChars > 0) {
        var maxCons = 1;
        var current = 1;
        for (var i = 1; i < password.length; i++) {
            if (password[i] === password[i - 1]) {
                current++;
                if (current > maxCons) maxCons = current;
            } else {
                current = 1;
            }
        }
        var passed = maxCons <= rules.maxConsecutiveChars;
        checks.push({
            id: 'consecutive',
            label: 'Max ' + rules.maxConsecutiveChars + ' same character(s) in a row',
            passed: passed
        });
    }

    // 8. Min Unique characters
    if (rules.minUniqueChars > 0) {
        var unique = new Set(password).size;
        var passed = unique >= rules.minUniqueChars;
        checks.push({
            id: 'unique',
            label: 'At least ' + rules.minUniqueChars + ' unique character(s)',
            passed: passed
        });
    }

    // 9. Max Same Character Percentage
    if (rules.maxSameCharPercentage > 0 && rules.maxSameCharPercentage < 100 && password.length > 0) {
        var freq = {};
        for (var i = 0; i < password.length; i++) {
            freq[password[i]] = (freq[password[i]] || 0) + 1;
        }
        var maxFreq = 0;
        for (var ch in freq) {
            if (freq[ch] > maxFreq) maxFreq = freq[ch];
        }
        var pct = (maxFreq / password.length) * 100;
        var passed = pct <= rules.maxSameCharPercentage;
        checks.push({
            id: 'samePercent',
            label: 'Max ' + rules.maxSameCharPercentage + '% same character',
            passed: passed
        });
    }

    // Must differ from current password (always validated if _currentPassword is provided)
    if (currentPassword && password.length > 0) {
        var passed = password !== currentPassword;
        checks.push({
            id: 'sameAsCurrent',
            label: 'Must differ from current password',
            passed: passed
        });
    }

    // 10. Disallow Sequential (abc, 123, xyz, 321)
    if (rules.disallowSequential && rules.maxSequentialCount > 0) {
        var seqLen = rules.maxSequentialCount;
        var hasSequential = false;
        var lower = password.toLowerCase();
        for (var i = 0; i <= lower.length - seqLen; i++) {
            var isAsc = true;
            var isDesc = true;
            for (var j = 1; j < seqLen; j++) {
                if (lower.charCodeAt(i + j) !== lower.charCodeAt(i + j - 1) + 1) isAsc = false;
                if (lower.charCodeAt(i + j) !== lower.charCodeAt(i + j - 1) - 1) isDesc = false;
            }
            if (isAsc || isDesc) {
                hasSequential = true;
                break;
            }
        }
        var passed = !hasSequential;
        checks.push({
            id: 'sequential',
            label: 'No sequential patterns (min ' + seqLen + ')',
            passed: passed
        });
    }

    // 11. Disallow Username (check against all user login identifiers)
    if (rules.disallowUsername && userLogins && userLogins.length > 0 && password.length > 0) {
        var passLower = password.toLowerCase();
        var passed = true;
        for (var i = 0; i < userLogins.length; i++) {
            if (passLower.indexOf(userLogins[i].toLowerCase()) !== -1) {
                passed = false;
                break;
            }
        }
        checks.push({
            id: 'username',
            label: 'Must not contain username',
            passed: passed
        });
    }

    // 12. Disallow Common Passwords
    if (rules.disallowCommonPasswords && password.length > 0) {
        var passed = !COMMON_PASSWORDS_SET[password.toLowerCase()];
        checks.push({
            id: 'commonPassword',
            label: 'Must not be a commonly used password',
            passed: passed
        });
    }

    // Overall validity
    var valid = true;
    for (var i = 0; i < checks.length; i++) {
        if (!checks[i].passed) {
            valid = false;
            break;
        }
    }

    return { valid: valid, checks: checks };
}

/**
 * Check if all strength requirements are met from a validation result.
 * Logs detailed explanation to console when requirements are not met.
 * @param {Object} result - result from validatePasswordAgainstStrength
 * @returns {boolean}
 */
function allStrengthRequirementsMet(result) {
    if (!result || !result.checks || result.checks.length === 0) return true;

    if (result.valid) {
        return true;
    }

    // Collect failed requirements
    var failedChecks = result.checks.filter(function(c) { return !c.passed; });

    // Log detailed explanation
    console.log('⚠️  The password does not meet the following strength requirements:');
    for (var i = 0; i < failedChecks.length; i++) {
        console.log('   • ' + failedChecks[i].label);
    }

    return false;
}

/**
 * Render strength checklist UI into a container element.
 * Updates checkmarks/crosses and enables/disables the submit button.
 *
 * @param {Object} result - result from validatePasswordAgainstStrength
 * @param {string} containerId - HTML element id to inject checklist
 * @param {string} buttonId - ID of the submit button to enable/disable
 * @param {boolean} [compactMode=false] - If true, only render failed checks
 */
function renderStrengthChecklist(result, containerId, buttonId, compactMode) {
    var $container = $('#' + containerId);
    $container.empty();
    compactMode = compactMode || false;

    if (!result || result.checks.length === 0) {
        $container.addClass('d-none');
        if (buttonId) $('#' + buttonId).prop('disabled', false);
        return;
    }

    // In compact mode, filter to only failed checks
    var checksToShow = compactMode
        ? result.checks.filter(function(c) { return !c.passed; })
        : result.checks;

    // If compact mode and all checks pass, hide container
    if (compactMode && checksToShow.length === 0) {
        $container.addClass('d-none');
        if (buttonId) $('#' + buttonId).prop('disabled', false);
        return;
    }

    $container.removeClass('d-none');

    var html = '<div class="mb-2 fw-semibold small"><i class="fa-solid fa-shield-halved"></i> Password Requirements</div>';
    html += '<ul class="list-unstyled mb-0 small">';

    for (var i = 0; i < checksToShow.length; i++) {
        var c = checksToShow[i];
        var iconClass = c.passed ? 'text-success' : 'text-muted';
        var icon = c.passed ? 'fa-circle-check' : 'fa-circle';
        var itemClass = c.passed ? 'text-success' : 'text-muted';

        html += '<li class="' + itemClass + ' mb-1">';
        html += '<i class="fa-solid ' + icon + ' ' + iconClass + ' me-1"></i> ';
        html += c.label;
        html += '</li>';
    }

    html += '</ul>';

    $container.html(html);

    // Enable/disable submit button
    if (buttonId) {
        $('#' + buttonId).prop('disabled', !result.valid);
    }
}
