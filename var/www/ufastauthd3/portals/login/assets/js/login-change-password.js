// ============================================================
// Login Change Password - Change password flow
// ============================================================

var changePasswordFunction = 0;

/**
 * Show the Change Password screen (direct - no step 1 verification needed)
 */
function showChangePasswordScreen() {
    changePasswordFunction = currentSlot.details.passwordFunction;

    // Reset fields
    $("#changeNewPassword").val('');
    $("#changeConfirmPassword").val('');

    // Show the screen
    $("#changePasswordScreen").removeClass('d-none');

    updateMessage("Change Password - " + currentSlot.details.description);
    $("#changeNewPassword").focus();
}

/**
 * Cancel Change Password and go back to the credential input screen
 */
function cancelChangePassword() {
    $("#changePasswordScreen").addClass('d-none');
    showNextSlot();
}

/**
 * Submit new password via changeCredential with Bearer token
 */
function submitChangePassword() {
    var newPassword = $("#changeNewPassword").val();
    var confirmPassword = $("#changeConfirmPassword").val();

    // Validations
    if (!newPassword) {
        updateMessage('Error: New password is required.');
        return;
    }
    if (newPassword !== confirmPassword) {
        updateMessage('Error: Passwords do not match.');
        return;
    }

    // Compute hash using the shared function from credentials.js
    var hashResult = computePasswordHash(newPassword, changePasswordFunction, null);

    var payload = {
        newCredential: {
            hash: hashResult.hash,
            ssalt: hashResult.ssalt,
            mustChange: false,
            slotDetails: {
                passwordFunction: changePasswordFunction
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

            // Password changed successfully
            $("#changePasswordScreen").addClass('d-none');
            updateMessage('Password changed successfully. Continuing login...');
            // Handle response same as authorize (nextSlot, changeCredential, etc.)
            handleAuthorizeResponse(cachedLastAuthorizeResponse);
        },
        error: function (xhr, status, error) {
            var msg = 'Error: Failed to change password.';
            if (xhr.responseJSON && xhr.responseJSON.message) {
                msg = 'Error: ' + xhr.responseJSON.message;
            }
            updateMessage(msg);
        }
    });
}