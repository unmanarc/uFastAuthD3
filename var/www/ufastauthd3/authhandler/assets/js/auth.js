/**
 * This script manages session timeout and automatic token refresh for a web application.
 *
 * It uses the following variables:
 * 
 * - maxAge: Holds the maximum age of the session in seconds, updated from server response.
 * - sessionTimeout: Stores the ID of the setTimeout function used to manage session countdown.
 */

//<%jvar/ufad3_maxAge:maxAge%>//
//<%jvar/ufad3_accountUUID:user%>//
//<%jfunc/ufad3_applicationPublicData:GET/v1/getApplicationPublicData({})%>//
//<%jfunc/ufad3_accountPublicData:GET/v1/getUserPublicData({})%>//

let maxAgeVar = ufad3_maxAge;
let sessionTimeout = null;

function updateSessionFailed() {
  alert("Session Update Failed");
  window.location.href = '/login/';
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
  fetch('/auth/api/v1/refreshAccessToken', {
    method: 'POST',
  })
  .then(response => {
    if (!response.ok) throw new Error('Network response was not ok');
    return response.json();
  })
  .then(data => {
    // Success handler: update maxAgeVar with the new value from server
    maxAgeVar = data["maxAge"];

    // Start or restart the session timer based on the new maxAgeVar value
    startAccessRetokenizerTimer();
  })
  .catch(() => {
    updateSessionFailed();
  });
}
/**
 * Sends an AJAX request to the server to refresh the access token.
 * Upon successful response, it will go back to the site.
 */
function retokenizeAccessToken() {
  fetch('/auth/api/v1/refreshAccessToken', {
    method: 'POST',
  })
  .then(response => {
    if (!response.ok) throw new Error('Network response was not ok');
    window.location.href = '/';
  })
  .catch(() => {
    window.location.href = '/login/';
  });
}

/**
 * Logs out the user by submitting the LogoutToken via a form POST to the callback URL.
 * This causes the browser to navigate away from the current page.
 */
function logout() {
  // Check if login mode is EMBEDDED
  if (ufad3_applicationPublicData && ufad3_applicationPublicData.body.loginMode === "EMBEDDED") {
    fetch('/auth/api/v1/logout', {
      method: 'POST',
    })
    .then(response => {
      if (!response.ok) throw new Error('Network response was not ok');
      window.location.href = '/login/';
    })
    .catch(() => {
      alert('Failed to logout');
    });
    return;
  }
  else {
    // Step 1: Get the logout callback URL from the server
    fetch('/auth/api/v1/getLogoutCallbackURL', {
      method: 'GET',
    })
    .then(response => {
      if (!response.ok) throw new Error('Network response was not ok');
      return response.json();
    })
    .then(response => {
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
      keepAuthInput.name = 'sessionPublicData';
      keepAuthInput.value = getCookie('SessionPublicData') || '';
      form.appendChild(keepAuthInput);
      //alert(keepAuthInput.value);

      // Step 4: Append the form to the document body and submit it
      document.body.appendChild(form);
      form.submit();
    })
    .catch(() => {
      alert('Failed to retrieve logout URL');
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
 * Monitors the SessionPublicData cookie.
 * If the cookie is missing, redirects the user to /login.
 * Checks every 1 second.
 */
function startSessionPublicDataMonitor() {
  setInterval(function () {
    if (!getCookie('SessionPublicData')) {
      window.location.href = '/login';
    }
  }, 1000);
}

// Start the SessionPublicData cookie monitor
startSessionPublicDataMonitor();

/**
 * Session Inactivity Timeout System
 * Monitors user activity and shows a warning overlay when the user is inactive.
 * If the user does not respond, they will be logged out.
 */
(function() {
    // Extract session configuration from ufad3_applicationPublicData
    const sessionConfig = ufad3_applicationPublicData && 
                          ufad3_applicationPublicData.body && 
                          ufad3_applicationPublicData.body.session;
    
    const enableInactivityTimeout = sessionConfig && sessionConfig.enableInactivityTimeout;
    const inactivityTimeoutSeconds = (sessionConfig && sessionConfig.inactivityTimeout) ? sessionConfig.inactivityTimeout : 30;
    const inactivityGraceTime = (sessionConfig && sessionConfig.inactivityGraceTime) ? sessionConfig.inactivityGraceTime : 10;
    
    let inactivityTimer = null;
    let graceTimer = null;
    let graceTimeRemaining = inactivityGraceTime;
    let isOverlayVisible = false;
    
    // Activity events to monitor
    const activityEvents = [
        'mousemove',
        'mousedown',
        'mouseup',
        'keydown',
        'keypress',
        'keyup',
        'scroll',
        'touchstart',
        'touchmove',
        'click',
        'wheel'
    ];
    
    /**
     * Creates and shows the inactivity warning overlay.
     */
    function showInactivityOverlay() {
        if (isOverlayVisible) return;
        isOverlayVisible = true;
        graceTimeRemaining = inactivityGraceTime;
        
        // Create overlay element
        const overlay = document.createElement('div');
        overlay.id = 'ufad3-inactivity-overlay';
        overlay.innerHTML = `
            <div id="ufad3-inactivity-card">
                <div class="ufad3-inactivity-icon">⏱️</div>
                <h2 id="ufad3-inactivity-title">Session Expiring</h2>
                <p id="ufad3-inactivity-message">Your session is about to expire due to inactivity. Do you want to stay in session?</p>
                <div id="ufad3-inactivity-timer">
                    <span id="ufad3-inactivity-countdown">${graceTimeRemaining}</span> seconds remaining
                </div>
                <div class="ufad3-inactivity-buttons">
                    <button id="ufad3-stay-logged-in-btn" class="ufad3-btn ufad3-btn-primary">Yes, Stay Logged In</button>
                    <button id="ufad3-logout-btn" class="ufad3-btn ufad3-btn-secondary">No, Log Out</button>
                </div>
            </div>
        `;
        
        // Add CSS styles
        if (!document.getElementById('ufad3-inactivity-styles')) {
            const style = document.createElement('style');
            style.id = 'ufad3-inactivity-styles';
            style.textContent = `
                #ufad3-inactivity-overlay {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background-color: rgba(0, 0, 0, 0.7);
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    z-index: 999999;
                }
                
                #ufad3-inactivity-card {
                    background: white;
                    border-radius: 12px;
                    padding: 40px;
                    max-width: 450px;
                    width: 90%;
                    text-align: center;
                    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                }
                
                .ufad3-inactivity-icon {
                    font-size: 48px;
                    margin-bottom: 20px;
                }
                
                #ufad3-inactivity-title {
                    color: #333;
                    font-size: 24px;
                    margin-bottom: 15px;
                    font-weight: 600;
                }
                
                #ufad3-inactivity-message {
                    color: #666;
                    font-size: 16px;
                    margin-bottom: 25px;
                    line-height: 1.5;
                }
                
                #ufad3-inactivity-timer {
                    background: #fff3cd;
                    border: 1px solid #ffc107;
                    border-radius: 8px;
                    padding: 15px;
                    margin-bottom: 25px;
                    font-size: 18px;
                    color: #856404;
                }
                
                #ufad3-inactivity-countdown {
                    font-weight: bold;
                    font-size: 24px;
                    color: #dc3545;
                }
                
                .ufad3-inactivity-buttons {
                    display: flex;
                    gap: 15px;
                    justify-content: center;
                    flex-wrap: wrap;
                }
                
                .ufad3-btn {
                    padding: 12px 24px;
                    border: none;
                    border-radius: 6px;
                    font-size: 16px;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    font-weight: 500;
                }
                
                .ufad3-btn-primary {
                    background-color: #28a745;
                    color: white;
                }
                
                .ufad3-btn-primary:hover {
                    background-color: #218838;
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(40, 167, 69, 0.4);
                }
                
                .ufad3-btn-secondary {
                    background-color: #dc3545;
                    color: white;
                }
                
                .ufad3-btn-secondary:hover {
                    background-color: #c82333;
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(220, 53, 69, 0.4);
                }
            `;
            document.head.appendChild(style);
        }
        
        document.body.appendChild(overlay);
        
        // Bind button events
        document.getElementById('ufad3-stay-logged-in-btn').addEventListener('click', stayLoggedIn);
        document.getElementById('ufad3-logout-btn').addEventListener('click', handleLogout);
        
        // Start grace period countdown
        startGraceCountdown();
    }
    
    /**
     * Starts the countdown during the grace period.
     */
    function startGraceCountdown() {
        clearInterval(graceTimer);
        graceTimeRemaining = inactivityGraceTime;
        updateCountdownDisplay();
        
        graceTimer = setInterval(() => {
            graceTimeRemaining--;
            updateCountdownDisplay();
            
            if (graceTimeRemaining <= 0) {
                clearInterval(graceTimer);
                handleLogout();
            }
        }, 1000);
    }
    
    /**
     * Updates the countdown display in the overlay.
     */
    function updateCountdownDisplay() {
        const countdownElement = document.getElementById('ufad3-inactivity-countdown');
        if (countdownElement) {
            countdownElement.textContent = graceTimeRemaining;
        }
    }
    
    /**
     * Hides the inactivity overlay and resets timers.
     */
    function hideInactivityOverlay() {
        clearInterval(graceTimer);
        const overlay = document.getElementById('ufad3-inactivity-overlay');
        if (overlay) {
            overlay.remove();
        }
        isOverlayVisible = false;
    }
    
    /**
     * Called when user chooses to stay logged in.
     */
    function stayLoggedIn() {
        hideInactivityOverlay();
        resetInactivityTimer();
    }
    
    /**
     * Handles logout when user chooses to log out or grace period expires.
     */
    function handleLogout() {
        hideInactivityOverlay();
        clearTimeout(inactivityTimer);
        // Call the existing logout function
        if (typeof logout === 'function') {
            logout();
        } else {
            window.location.href = '/login/';
        }
    }
    
    /**
     * Resets the inactivity timer.
     */
    function resetInactivityTimer() {
        clearTimeout(inactivityTimer);
        inactivityTimer = setTimeout(() => {
            showInactivityOverlay();
        }, inactivityTimeoutSeconds * 1000);
    }
    
    /**
     * Handles activity events - resets timer if overlay is not visible.
     */
    function handleActivity() {
        if (!isOverlayVisible) {
            resetInactivityTimer();
        }
    }
    
    /**
     * Initializes the inactivity monitoring system.
     */
    function initInactivityMonitor() {
        if (!enableInactivityTimeout) {
            return;
        }
        
        // Attach event listeners for activity monitoring
        activityEvents.forEach(event => {
            document.addEventListener(event, handleActivity, { passive: true });
        });
        
        // Start the initial inactivity timer
        resetInactivityTimer();
    }
    
    // Expose functions globally if needed
    window.ufad3HideInactivityOverlay = hideInactivityOverlay;
    window.ufad3StayLoggedIn = stayLoggedIn;
    
    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initInactivityMonitor);
    } else {
        initInactivityMonitor();
    }
})();