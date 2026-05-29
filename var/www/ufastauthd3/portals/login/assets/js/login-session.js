// ============================================================
// Login Session - Session validation, logout, and token loading
// ============================================================

/**
 * Validate the current session by calling /api/v1/token with mock: true.
 * Based on the result, either show the normal "Already logged in" screen
 * or the "Authentication incomplete" screen with a button to continue authentication.
 */
function validateSessionAndShowScreen() {
    $.ajax({
        url: "/api/v1/token",
        type: "POST",
        contentType: "application/json",
        data: JSON.stringify({
            redirectURI: decodedRedirectURI,
            activity: "LOGIN",
            app: appName,
            schemeId: 0,
            mock: true
        }),
        success: function (response) {
            // Session is valid - show normal "Already logged in" screen
            loggedIn = true;
            $("#usernameForm").addClass("d-none");
            $("#logoutForm").removeClass("d-none");
            updateMessage('Welcome back ' + cachedCookieData.subject + '!');
        },
        error: function (xhr, status, error) {
            // Session is incomplete - show only logout button (hide "Continue to application" button)
            loggedIn = true;
            $("#usernameForm").addClass("d-none");
            $("#logoutForm").removeClass("d-none");
            // Hide the "Continue to the application" button
            $("#continueToAppBtn").addClass("d-none");
            updateMessage('Authentication incomplete for this Application.\nPlease logout and authenticate again.');
        }
    });
}

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