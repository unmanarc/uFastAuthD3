// Helpers:

function updateMessage(text) {
    $("#message").text(text);
}

function showError(error) {
    updateMessage(`${error}`);
}

function showErrorWithDetails(error, message) {
    showError(`${error}: ${message}`);
}

function showErrorWithXHR(xhr, status, error) {
    showErrorWithDetails(error, xhr.responseJSON["message"]);
}


// Helper to create and submit form
function createAndSubmitRedirectForm(actionUrl, data, method = 'POST') {
    const form = document.createElement('form');
    form.method = method;
    form.action = actionUrl;
    Object.entries(data).forEach(([name, value]) => {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = name;
        input.value = value;
        form.appendChild(input);
    });
    document.body.appendChild(form);
    form.submit();
}

////////////////////////////////////////////////////////////////////////////////////

let decodedRedirectURI = "";
let loggedIn = false;
let loggedInGETParsedParam = true;
let currentScheme = null;
let schemesAvailable = [];
const urlParams = new URLSearchParams(window.location.search);

// Retrieve the 'redirectURI' and 'app' parameter from the URL
const mode = urlParams.get('mode');
const appName = urlParams.get('app');
const encodedRedirectURI = urlParams.get('redirectURI');

function logout() {
    $.ajax({
        url: "/api/v1/logout",
        type: "POST",
        contentType: "application/json",
        data: JSON.stringify({}),
        headers: {
            "X-Logout": "1" // This prevents CSRF logout attacks.
        },
        success: function (response) {
            // Recargar la página con los mismos parámetros GET
            loggedIn = false;
            location.reload();
        },
        error: showErrorWithXHR
    });
}

function loadTokenAndRedirect() {
    // Perform the AJAX request
    $.ajax({
        url: "/api/v1/token",
        type: "POST",
        contentType: "application/json",
        data: JSON.stringify(
            {
                redirectURI: decodedRedirectURI,
                activity: "LOGIN",
                app: appName,
                schemeId: parseInt($("#currentSchemeId").val())
            }
        ),
        headers: {
            "X-Logout": "1" // This prevents CSRF logout attacks.
        },
        success: function (response) {
            // submit the token to the app.
            const callbackURI = response.callbackURI;
            createAndSubmitRedirectForm(callbackURI, response, mode === 'app' ? 'GET' : 'POST');
        },
        error: showErrorWithXHR
    });
}

$(document).ready(function () {
    let currentSlot = null;
    let transientToken = null;
    let cachedLastAuthorizeResponse = null;

    $("#version").text(softwareVersion);

    // Focus on username input when the page loads
    $("#username").focus();

    updateMessage('Please enter your username');

    const loggedInGETParam = urlParams.get('loggedIn');

    if (loggedInGETParam === "false") {
        // Remove the 'loggedIn' parameter from the URL
        const newUrlSearchParams = new URLSearchParams(window.location.search);
        newUrlSearchParams.delete('loggedIn');
        window.history.replaceState(null, '', `${window.location.pathname}?${newUrlSearchParams.toString()}${window.location.hash}`);
        loggedInGETParsedParam = false;
    }

    if (!appName) {
        // Override appName to IAM_USRPORTAL
        window.location.href = "/?app=IAM_USRPORTAL";
    }

    // Validate if 'redirectURI' exists and is a valid base64 string
    if (!encodedRedirectURI) {
        decodedRedirectURI = "";
    } else {
        try {
            decodedRedirectURI = atob(encodedRedirectURI);
        } catch (error) {
            updateMessage('ERROR: Invalid redirect URI.');
            $("#usernameForm").addClass("d-none");
            return;
        }
    }

    // Load refresh token from cookie
    const cookies = document.cookie.split(';');
    cookies.forEach(cookie => {
        const [name, value] = cookie.trim().split('=');
        if (name === 'loggedIn') {
            loggedIn = true;

            $("#usernameForm").addClass("d-none");
            $("#logoutForm").removeClass("d-none");

            updateMessage('Already logged in.');
        }
    });

    // Function to initialize authentication flow using preAuthorize API
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

                $("#schemeDescription").text(currentScheme.description).css("font-weight", "bold");
                $("#currentSchemeId").val(defaultSchemeIndex);
                showNextSlot();
            },
            error: showErrorWithXHR
        });
    }

    // Function to handle authorize/changeCredential response
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

    // Function to send authorization request for each slot
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
                keepAuthenticated: $("#keepAuthenticated").is(":checked"),
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

    // Hide all screens
    function hideAllScreens() {
        $("#usernameForm").addClass("d-none");
        $("#genericPasswordForm").addClass("d-none");
        $("#otpForm").addClass("d-none");
        $("#authWaiting").addClass("d-none");
        $("#logoutForm").addClass("d-none");
        $("#changePasswordScreen").addClass("d-none");
        $("#changeOtpScreen").addClass("d-none");
    }

    // Update the content based on the current slot
    function showNextSlot() {
        if (currentSlot == null) {
            updateMessage("Authenticated! Redirecting...");
            loadTokenAndRedirect();
            // Here we have to get the application token
            return;
        }

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

    // Event listener for username submission
    $("#usernameForm").on("submit", function (e) {
        e.preventDefault();
        const username = $("#username").val();
        $("#usernameForm").addClass("d-none");
        initializeAuthentication(username);
    });

    // Event listener for generic input submission
    $("#genericPasswordForm").on("submit", function (e) {
        e.preventDefault();
        const username = $("#username").val();
        const schemeId = $("#currentSchemeId").val();
        const password = $("#genericPassword").val();

        authorizeCredential(username, schemeId, password);
    });

    // Event listener for OTP submission
    $("#otpForm").on("submit", function (e) {
        e.preventDefault();
        const username = $("#username").val();
        const schemeId = $("#currentSchemeId").val();
        const otp = $("#otp").val();

        authorizeCredential(username, schemeId, otp);
    });

    // ============================================================
    // Change Password Screen Functions
    // ============================================================

    // Change Password button handlers
    $("#changePasswordSubmitBtn").on("click", function (e) {
        e.preventDefault();
        submitChangePassword();
    });

    $("#changePasswordCancelBtn").on("click", function (e) {
        e.preventDefault();
        cancelChangePassword();
    });

    // Change OTP button handlers
    $("#changeOtpSubmitBtn").on("click", function (e) {
        e.preventDefault();
        submitChangeOTP();
    });

    $("#changeOtpCancelBtn").on("click", function (e) {
        e.preventDefault();
        cancelChangeOTP();
    });

    // Handle Enter key in change password fields
    $("#changeNewPassword").on("keypress", function (e) {
        if (e.which === 13) {
            e.preventDefault();
            $("#changeConfirmPassword").focus();
        }
    });

    $("#changeConfirmPassword").on("keypress", function (e) {
        if (e.which === 13) {
            e.preventDefault();
            submitChangePassword();
        }
    });

    // Handle Enter key in change OTP field
    $("#changeOtpVerificationCode").on("keypress", function (e) {
        if (e.which === 13) {
            e.preventDefault();
            submitChangeOTP();
        }
    });

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

    // ============================================================
    // Change OTP Screen Functions
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
});
