/**
 * This script manages session timeout and automatic token refresh for a web application.
 *
 * It uses the following variables:
 * 
 * - maxAge: Holds the maximum age of the session in seconds, updated from server response.
 * - sessionTimeout: Stores the ID of the setTimeout function used to manage session countdown.
 */

//<%jvar/ufad3_maxAge:maxAge%>//
//<%jvar/ufad3_user:user%>//
//<%jvar/ufad3_domain:domain%>//
//<%jfunc/ufad3_loginMode:GET/v1/getLoginMode({})%>//

let maxAgeVar = ufad3_maxAge;
let sessionTimeout = null;

function updateSessionFailed() {
  alert("Session Update Failed");
}

/**
 * Retrieves the value of a cookie by its name.
 * @param {string} name - The name of the cookie to retrieve.
 * @returns {string|null} The cookie value, or null if not found.
 */
function getCookie(name) {
  const value = "; " + document.cookie;
  const parts = value.split("; " + name + "=");
  if (parts.length === 2) {
    return parts.pop().split(";").shift();
  }
  return null;
}

/**
 * Sends an AJAX request to the server to refresh the access token.
 * Upon successful response, it updates maxAgeVar and restarts the session timer.
 */
function refreshAccessToken() {
  $.ajax({
    url: '/auth/api/v1/refreshAccessToken',
    type: 'POST',
    success: function (response) {
      // Update maxAgeVar with the new value from server
      maxAgeVar = response["maxAge"];

      // Start or restart the session timer based on the new maxAgeVar value
      startAccessRetokenizerTimer();
    },
    error: updateSessionFailed
  });
}

/**
 * Logs out the user by submitting the LogoutToken via a form POST to the callback URL.
 * This causes the browser to navigate away from the current page.
 */
function logout() {
  // Check if login mode is EMBEDDED
  if (ufad3_loginMode.body && ufad3_loginMode.body.mode === "EMBEDDED") {
    $.ajax({
      url: '/auth/api/v1/logout',
      type: 'POST',
      success: function (response) {
        window.location.href = '/login/';
      },
      error: function () {
        alert('Failed to logout');
      }
    });
    return;
  }
  else {
    // Step 1: Get the logout callback URL from the server (synchronous to ensure we have the URL before proceeding)
    $.ajax({
      url: '/auth/api/v1/getLogoutCallbackURL',
      type: 'GET',
      async: false,
      success: function (response) {
        var logoutURL = response["url"];
        var appName = response["appName"];

        // Step 2: Create a hidden form dynamically
        var form = document.createElement('form');
        form.method = 'POST';
        form.action = logoutURL;
        form.style.display = 'none';

        // Step 3: Add the appName as a hidden input field
        var tokenInput = document.createElement('input');
        tokenInput.type = 'hidden';
        tokenInput.name = 'appName';
        tokenInput.value = appName;
        form.appendChild(tokenInput);

        // Step 3b: Add the KeepAuthentication cookie value as a hidden input field
        var keepAuthInput = document.createElement('input');
        keepAuthInput.type = 'hidden';
        keepAuthInput.name = 'keepAuthentication';
        keepAuthInput.value = getCookie('KeepAuthentication') || '';
        form.appendChild(keepAuthInput);
        //alert(keepAuthInput.value);

        // Step 4: Append the form to the document body and submit it
        document.body.appendChild(form);
        form.submit();
      },
      error: function () {
        alert('Failed to retrieve logout URL');
      }
    });
  }

}

/**
 * Starts a countdown timer for the session.
 * When the countdown reaches zero, it triggers an AJAX request to refresh the access token.
 */
function startAccessRetokenizerTimer() {
  // Countdown is set to 10 seconds before maxAgeVar to ensure timely token refresh
  const countdown = maxAgeVar - 10;

  if (countdown > 0) {
    // Clear any existing timeout to avoid multiple timers running simultaneously
    clearTimeout(sessionTimeout);

    // Set a new timeout for session expiration and automatic renewal
    sessionTimeout = setTimeout(() => {
      refreshAccessToken();
    }, countdown * 1000);
  }
}

// Initialize the session timer when the script loads, starting the countdown
startAccessRetokenizerTimer();

/**
 * Monitors the KeepAuthentication cookie.
 * If the cookie is missing, redirects the user to /login.
 * Checks every 1 second.
 */
function startKeepAuthenticationMonitor() {
  setInterval(function () {
    if (!getCookie('KeepAuthentication')) {
      window.location.href = '/login';
    }
  }, 1000);
}

// Start the KeepAuthentication cookie monitor
startKeepAuthenticationMonitor();

//refreshAccessToken();

