// ============================================================
// Login Auth - Main authentication flow
// ============================================================

let currentSlot = null;
let transientToken = null;
let cachedLastAuthorizeResponse = null;

/**
 * Initialize authentication flow using preAuthorize API
 */
function initializeAuthentication(username) {
    $.ajax({
        url: "/api/v1/preAuthorize",
        type: "POST",
        contentType: "application/json",
        data: JSON.stringify({
            accountName: username,
            app: appName,
            activity: "LOGIN"
        }),
        success: function (response) {
            const defaultSchemeIndex = response.defaultScheme;
            if (defaultSchemeIndex == null) {
                updateMessage('ERROR: No available authentication scheme found for this user.');
                return;
            }
            schemesAvailable = response.availableSchemes;

            currentScheme = response.availableSchemes[defaultSchemeIndex];
            currentSlot = currentScheme.firstSlot;

            $("#schemeDescription").text(currentScheme.description + " Authentication");
            $("#currentSchemeId").val(defaultSchemeIndex);
            showNextSlot();
        },
        error: showErrorWithXHR
    });
}

/**
 * Handle authorize/changeCredential response
 */
function handleAuthorizeResponse(response) {
    if (response.changeCredential === false) {
        cachedLastAuthorizeResponse = null;
        if (response.nextSlot === null) {
            loggedIn = true;
            updateMessage("Authenticated! Redirecting...");
            loadTokenAndRedirect();
        } else {
            currentSlot = response.nextSlot;
            showNextSlot();
        }
    } else if (response.changeCredential === true) {
        cachedLastAuthorizeResponse = response;
        cachedLastAuthorizeResponse.changeCredential = false;
        // This credential that has just been authenticated, NEEDS to be changed.
        // don´t go to the next slot.
        var pwFunc = currentSlot.details.passwordFunction;
        if (pwFunc === 5) {
            hideAllScreens();
            showChangeOTPScreen();
        } else {
            hideAllScreens();
            showChangePasswordScreen();
        }
    }
}

/**
 * Send authorization request for each slot
 */
function authorizeCredential(username, schemeId, password) {
    $.ajax({
        url: "/api/v1/authorize",
        type: "POST",
        contentType: "application/json",
        headers: {
            'Authorization': 'Bearer ' + transientToken
        },
        data: JSON.stringify({
            preAuthUser: username,
            keepAuthenticated: sessionKeepAuthenticated,
            app: appName,
            schemeId: parseInt($("#currentSchemeId").val()),
            password: password,
            authMode: "MODE_PLAIN",
            currentSlotId: currentSlot.slotId,
            challengeSalt: ""
        }),
        success: function (response) {
            transientToken = response.transientToken;
            handleAuthorizeResponse(response);
        },
        error: function (xhr, status, error) {
            // Clear password and OTP fields on authorization error
            $("#genericPassword").val('').trigger('input');
            $("#otp").val('');
            // Show the error message
            showErrorWithXHR(xhr, status, error);
            loggedIn = false;
        }
    });
}

/**
 * Hide all screens
 */
function hideAllScreens() {
    $("#usernameForm").addClass("d-none");
    $("#genericPasswordForm").addClass("d-none");
    $("#otpForm").addClass("d-none");
    $("#authWaiting").addClass("d-none");
    $("#logoutForm").addClass("d-none");
    $("#changePasswordScreen").addClass("d-none");
    $("#changeOtpScreen").addClass("d-none");
}

/**
 * Update the content based on the current slot
 */
function showNextSlot() {
    if (currentSlot == null) {
        updateMessage("Authenticated! Redirecting...");
        loadTokenAndRedirect();
        return;
    }

    // Update readonly "Keep me signed in" switches and labels on both forms
    $("#keepAuthenticatedPassword").prop("checked", sessionKeepAuthenticated);
    $("#keepAuthenticatedOtp").prop("checked", sessionKeepAuthenticated);

    const { description, passwordFunction } = currentSlot.details;

    updateMessage("Please enter your " + description);

    if (passwordFunction === 5) {
        // OTP input
        $("#genericPasswordForm").addClass("d-none");
        $("#otpForm").removeClass("d-none");
        $("#otp").focus();
    } else if ([1, 2].includes(passwordFunction)) {
        // Password input
        $("#otpForm").addClass("d-none");
        $("#genericPasswordForm").removeClass("d-none");
        $("#genericPassword").focus();
    } else {
        alert("Password function not implemented.");
    }
}