// ============================================================
// Login Change OTP - Change OTP flow
// ============================================================

var changeOtpGeneratedSecret = '';

/**
 * Show the Change OTP screen (direct - generate QR and show input)
 */
function showChangeOTPScreen() {
    changeOtpGeneratedSecret = '';

    // Reset fields
    $("#changeOtpVerificationCode").val('');
    $("#changeOtpQrCanvas").addClass('d-none');
    $("#changeOtpSecretText").addClass('d-none');

    // Show the screen
    $("#changeOtpScreen").removeClass('d-none');

    updateMessage("Change OTP - " + currentSlot.details.description);
    $("#changeOtpVerificationCode").focus();

    var label = $("#username").val() + ' - ' + currentSlot.details.description;
    var issuer = window.location.hostname;

    // Generate OTP secret client-side using otplib v13
    var secret = otplib.generateSecret();
    changeOtpGeneratedSecret = secret;

    // Build the OTPAUTH URI
    var uri = otplib.generateURI({
        secret: secret,
        issuer: issuer,
        label: label
    });

    // Generate QR code on canvas
    var canvas = document.getElementById('changeOtpQrCanvas');
    QRCode.toCanvas(canvas, uri, { width: 200 }, function (error) {
        if (error) {
            console.error('QR Code generation failed:', error);
            updateMessage('Error: Failed to generate QR code.');
        } else {
            $("#changeOtpQrCanvas").removeClass('d-none');
        }
    });
}

/**
 * Cancel Change OTP and go back to the credential input screen
 */
function cancelChangeOTP() {
    $("#changeOtpScreen").addClass('d-none');
    showNextSlot();
}

/**
 * Validate new OTP and submit change via changeCredential with Bearer token
 */
function submitChangeOTP() {
    var verificationCode = $("#changeOtpVerificationCode").val().trim();

    if (!verificationCode || verificationCode.length !== 6) {
        updateMessage('Error: Please enter a valid 6-digit OTP code.');
        return;
    }

    // Client-side validation using otplib v13 verifySync
    var result = otplib.verifySync({
        token: verificationCode,
        secret: changeOtpGeneratedSecret
    });

    if (!result || !result.valid) {
        updateMessage('Error: Invalid OTP code. Please scan the QR code again and try.');
        return;
    }

    var payload = {
        newCredential: {
            hash: changeOtpGeneratedSecret,
            ssalt: "",
            mustChange: false,
            slotDetails: {
                passwordFunction: 5
            }
        },
        slotId: parseInt(currentSlot.slotId)
    };

    $.ajax({
        url: '/api/v1/changeCredential',
        type: 'PUT',
        contentType: 'application/json',
        headers: {
            'Authorization': 'Bearer ' + transientToken
        },
        data: JSON.stringify(payload),
        success: function (response) {
            transientToken = response.transientToken;

            // OTP changed successfully
            $("#changeOtpScreen").addClass('d-none');
            updateMessage('OTP credential changed successfully. Continuing login...');
            // Handle response same as authorize (nextSlot, changeCredential, etc.)
            handleAuthorizeResponse(cachedLastAuthorizeResponse);
        },
        error: function (xhr, status, error) {
            var msg = 'Error: Failed to change OTP credential.';
            if (xhr.responseJSON && xhr.responseJSON.message) {
                msg = 'Error: ' + xhr.responseJSON.message;
            }
            updateMessage(msg);
        }
    });
}