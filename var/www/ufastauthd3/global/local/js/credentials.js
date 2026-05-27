
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
