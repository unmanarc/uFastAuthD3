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
    let intermediateToken = null;

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

    // Function to send authorization request for each slot
    function authorizeCredential(username, schemeId, password) {
        $.ajax({
            url: "/api/v1/authorize",
            type: "POST",
            contentType: "application/json",
            headers: {
                'Authorization': 'Bearer ' + intermediateToken
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
                intermediateToken = response.intermediateToken;
                if (response.nextSlot == null) {
                    loggedIn = true;
                    updateMessage("Authenticated! Redirecting...");
                    loadTokenAndRedirect();
                } else {
                    currentSlot = response.nextSlot;
                    showNextSlot();
                }
            },
            error: function (xhr, status, error) {
                // Clear password and OTP fields on authorization error
                $("#genericPassword").val('').trigger('input');
                $("#otp").val('');
                // Focus on generic password field after clearing it
                $("#genericPassword").focus();
                // Show the error message
                showErrorWithXHR(xhr, status, error);
                loggedIn = false;

                // MUST CHANGE CREDENTIAL.
                if (xhr.responseJSON["error"] == 'AUTH_ERR_113')
                {
                    // TODO:
                    alert('MUST CHANGE CREDENTIAL');
                }

            }
        });
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
});
