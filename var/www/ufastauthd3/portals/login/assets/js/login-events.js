// ============================================================
// Login Events - Event handlers and page initialization
// ============================================================

$(document).ready(function () {

    // Fetch and display app description
    /*    
        $.ajax({
            url: "api/v1/getAppDescription",
            type: "GET",
            data: JSON.stringify(
                {
                    app: appName
                }
            ),
            success: function (response) {
                if (response.description) {
                    $("#appDescription").text(response.description).css("font-weight", "bold");
                }
            },
            error: function (xhr, status, error) {
                // Silently fail - app description is optional
                console.error('Failed to load app description:', error);
            }
        });
    */


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

    if (loginMode.body.app.name === null || loginMode.body.app.name === "") {
        // Override appName to IAM_USRPORTAL
        window.location.href = "./?app=IAM_USRPORTAL";
    }
    appName = loginMode.body.app.name;

    $("#appDescription").text(loginMode.body.app.description).css("font-weight", "bold");
    document.title = loginMode.body.app.description + " Login";

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

    // Load refresh token from cookie and validate session
    cachedCookieData = parseLoginCookie();
    if (cachedCookieData) {
        // Instead of immediately showing "Already logged in", validate the session first
        // by calling /api/v1/token with mock: true to check if authentication is complete
        validateSessionAndShowScreen();
        // Start monitoring the cookie in background (cookie exists, detect if it disappears)
        startCookieMonitor(true);
    } else {
        // No cookie, start monitoring to detect if a cookie appears
        startCookieMonitor(false);
    }

    // ============================================================
    // Form Submission Handlers
    // ============================================================

    // Event listener for username submission
    $("#usernameForm").on("submit", function (e) {
        e.preventDefault();
        const username = $("#username").val();
        // Capture the "Keep me signed in" state as a readonly session variable
        sessionKeepAuthenticated = $("#keepAuthenticated").is(":checked");
        $("#usernameForm").addClass("d-none");
        initializeAuthentication(username);
    });

    // Event listener for generic password submission
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
    // Change Password Screen Handlers
    // ============================================================

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
});