// ============================================================
// Login Change Password - Change password flow with strength validation
// ============================================================
// Note: Password strength validation functions are provided by credentials.js:
//   - validatePasswordAgainstStrength(password, rules)
//   - allStrengthRequirementsMet(result)
//   - renderStrengthChecklist(result, containerId, buttonId)
// ============================================================

var changePasswordFunction = 0;
var currentStrengthValidator = null;

/**
 * Validate new password and confirm password against strength rules
 */
function validateChangePasswordFields() {
    const newPassword = $('#changeNewPassword').val();
    const confirmPassword = $('#changeConfirmPassword').val();
    const currentPassword = $('#genericPassword').val();
    const username = $("#username").val();

    var canSubmit = true;

    // Basic checks
    if (!newPassword) {
        canSubmit = false;
    }

    // Must match confirmation
    if (newPassword !== confirmPassword) {
        canSubmit = false;
    }

    // Strength validation (using shared function from credentials.js)
    var strengthResult = null;
    if (currentStrengthValidator && newPassword) {
        strengthResult = validatePasswordAgainstStrength(currentPassword, newPassword, currentStrengthValidator, username);
        renderStrengthChecklist(strengthResult, 'changePasswordStrengthItems', null, true);
        // Show the outer wrapper when displaying strength checklist
        $('#changePasswordStrengthChecklist').removeClass('d-none');
        if (!allStrengthRequirementsMet(strengthResult)) {
            canSubmit = false;
        }
    } else {
        // Hide the checklist when no validator or empty password
        $('#changePasswordStrengthChecklist').addClass('d-none');
    }

    // Enable/disable submit button
    $('#changePasswordSubmitBtn').prop('disabled', !canSubmit);

    return canSubmit;
}

/**
 * Show the Change Password screen (direct - no step 1 verification needed)
 */
function showChangePasswordScreen() {
    changePasswordFunction = currentSlot.details.passwordFunction;

    // Get the strength validator from slot details
    currentStrengthValidator = null;
    if (currentSlot.details && currentSlot.details.strengthJSONValidator) {
        currentStrengthValidator = currentSlot.details.strengthJSONValidator;
    }

    // Reset fields
    $("#changeNewPassword").val('');
    $("#changeConfirmPassword").val('');
    $("#changePasswordStrengthItems").empty();
    $("#changePasswordStrengthChecklist").addClass('d-none');
    $("#changePasswordSubmitBtn").prop('disabled', true);

    // Show the screen
    $("#changePasswordScreen").removeClass('d-none');

    updateMessage("Change Password - " + currentSlot.details.description);
    $("#changeNewPassword").focus();

    // Show/hide skip button based on canSkipPasswordChange
    if (window.canSkipPasswordChange) {
        $('#skipPasswordChangeBtnContainer').removeClass('d-none');
    } else {
        $('#skipPasswordChangeBtnContainer').addClass('d-none');
    }

    // Attach input event listeners for real-time validation
    $('#changeNewPassword').off('input').on('input', validateChangePasswordFields);
    $('#changeConfirmPassword').off('input').on('input', validateChangePasswordFields);
}

/**
 * Cancel Change Password - same as Restart (logout and start over)
 */
function cancelChangePassword() {
    logout();
}

/**
 * Skip password change (when canSkipPasswordChange is true)
 */
function skipPasswordChange() {
    currentStrengthValidator = null;
    $("#changePasswordScreen").addClass('d-none');
    updateMessage('Password change skipped. Continuing login...');
    // Continue with the cached authorization response, skipping strength validation to avoid infinite loop
    handleAuthorizeResponse(cachedLastAuthorizeResponse, true);
}

/**
 * Submit new password via changeCredential with Bearer token
 */
function submitChangePassword() {
    const newPassword = $("#changeNewPassword").val();
    const confirmPassword = $("#changeConfirmPassword").val();
    const currentPassword = $('#genericPassword').val();
    const username = $("#username").val();

    // Validations
    if (!newPassword) {
        updateMessage('Error: New password is required.');
        return;
    }
    if (newPassword !== confirmPassword) {
        updateMessage('Error: Passwords do not match.');
        return;
    }

    // Final strength validation check (using shared function from credentials.js)
    if (currentStrengthValidator) {
        var strengthResult = validatePasswordAgainstStrength(currentPassword, newPassword, currentStrengthValidator, username);
        if (!allStrengthRequirementsMet(strengthResult)) {
            updateMessage('Error: Password does not meet all strength requirements.');
            return;
        }
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
        url: 'api/v1/changeCredential',
        type: 'PUT',
        contentType: 'application/json',
        headers: {
            'Authorization': 'Bearer ' + transientToken
        },
        data: JSON.stringify(payload),
        success: function (response) {
            //transientToken = response.transientToken;
            currentStrengthValidator = null;

            // Password changed successfully
            $("#changePasswordScreen").addClass('d-none');
            updateMessage('Password changed successfully. Continuing login...');
            // Handle response same as authorize (nextSlot, changeCredential, etc.)
            handleAuthorizeResponse(cachedLastAuthorizeResponse, true);
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