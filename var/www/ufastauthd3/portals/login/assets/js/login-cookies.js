// ============================================================
// Login Cookies - Cookie management functions
// ============================================================

/**
 * Parse the loggedIn cookie and return the decoded JSON content.
 * Returns null if cookie not found or invalid.
 */
function parseLoginCookie() {
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'loggedIn') {
            try {
                const decoded = JSON.parse(atob(value));
                return decoded;
            } catch (e) {
                return null;
            }
        }
    }
    return null;
}

/**
 * Start a background interval that checks every second if the loggedIn cookie status changed.
 * - If the cookie existed and disappears, refresh the page.
 * - If the cookie did not exist and appears, refresh the page.
 */
var cookieMonitorInterval = null;
var cookieMonitorInitiallyExists = null;

function startCookieMonitor(initialCookieExists) {
    cookieMonitorInitiallyExists = initialCookieExists;
    cookieMonitorInterval = setInterval(function () {
        const cookieData = parseLoginCookie();
        const cookieNowExists = (cookieData !== null);

        if (cookieMonitorInitiallyExists && !cookieNowExists) {
            // Cookie disappeared - refresh the page
            clearInterval(cookieMonitorInterval);
            cookieMonitorInterval = null;
            location.reload();
        } else if (!cookieMonitorInitiallyExists && cookieNowExists) {
            // Cookie appeared - refresh the page
            clearInterval(cookieMonitorInterval);
            cookieMonitorInterval = null;
            location.reload();
        }
    }, 1000); // Check every 1 second
}

function stopCookieMonitor() {
    if (cookieMonitorInterval !== null) {
        clearInterval(cookieMonitorInterval);
        cookieMonitorInterval = null;
    }
}