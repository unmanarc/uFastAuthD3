console.log('=== Logout Script Started ===');

// Decode the loggedIn cookie to get callback URLs
function getLoggedInCookie() {
    //console.log('[getLoggedInCookie] Reading all cookies:', document.cookie);
    var cookies = document.cookie.split(';');
    var loggedInCookie = null;
    for (var i = 0; i < cookies.length; i++) {
        var cookie = cookies[i].trim();
        // console.log('[getLoggedInCookie] Checking cookie:', cookie);
        if (cookie.startsWith('loggedIn=')) {
            loggedInCookie = cookie.substring('loggedIn='.length);
            //            console.log('[getLoggedInCookie] Found loggedIn cookie with value:', loggedInCookie);
            break;
        }
    }
    if (!loggedInCookie) {
        console.log('[getLoggedInCookie] loggedIn cookie NOT found');
    }
    return loggedInCookie;
}

function decodeBase64(str) {
    console.log('[decodeBase64] Attempting to decode Base64 string, length:', str ? str.length : 0);
    try {
        var result = decodeURIComponent(atob(str).split('').map(function (c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        //        console.log('[decodeBase64] Decoded successfully:', result);
        return result;
    } catch (e) {
        console.error('[decodeBase64] Failed to decode Base64:', e);
        return null;
    }
}

// Perform logout
(function () {
    console.log('[Main] Starting logout process...');
    var callbackURLs = [];

    if (!data.keepAuthentication) {
        // When data.keepAuthentication is false, only use data.defaultCallbackURL (ignore cookie)
        callbackURLs = [data.defaultCallbackURL];
        console.log('[Main] data.keepAuthentication is false. Using only data.defaultCallbackURL:', callbackURLs);
    } else {
        // When data.keepAuthentication is true, use cookie data + ensure data.defaultCallbackURL is included
        var cookieData = getLoggedInCookie();

        if (cookieData) {
            console.log('[Main] Cookie data found, attempting to decode and parse...');
            var decoded = decodeBase64(cookieData);
            if (decoded) {
                try {
                    console.log('[Main] Parsing JSON from decoded cookie:', decoded);
                    var jsonData = JSON.parse(decoded);
                    console.log('[Main] Parsed JSON object:', jsonData);
                    if (jsonData.authenticatedAppsCallbackURLs) {
                        callbackURLs = jsonData.authenticatedAppsCallbackURLs;
                        console.log('[Main] Extracted callbackURLs from cookie:', callbackURLs);
                    } else {
                        console.log('[Main] No authenticatedAppsCallbackURLs found in JSON object');
                    }
                } catch (e) {
                    console.error('[Main] Failed to parse cookie JSON:', e);
                }
            } else {
                console.log('[Main] Decoded string is null, skipping JSON parse');
            }
        } else {
            console.log('[Main] No cookie data available');
        }

        // Ensure data.defaultCallbackURL is included when data.keepAuthentication is true
        if (callbackURLs.indexOf(data.defaultCallbackURL) === -1) {
            callbackURLs.push(data.defaultCallbackURL);
            console.log('[Main] data.defaultCallbackURL was not in cookie, adding it:', data.defaultCallbackURL);
        } else {
            console.log('[Main] data.defaultCallbackURL already present in cookie URLs:', data.defaultCallbackURL);
        }
    }

    console.log('[Main] Current callbackURLs array length:', callbackURLs.length);
    console.log('[Main] Final callbackURLs list:', callbackURLs);

    // Create promises for all external logouts
    var logoutPromises = [];
    console.log('[Main] Creating AJAX logout promises for', callbackURLs.length, 'URL(s)...');
    for (var i = 0; i < callbackURLs.length; i++) {
        (function (index, url) {
            console.log('[Main] Sending external logout POST to URL[' + index + ']:', url);
            var promise = $.ajax({
                url: url,
                type: "POST",
                contentType: "application/x-www-form-urlencoded",
                data: "mode=logout",
                xhrFields: {
                    withCredentials: true
                },
                success: function (xhr, status, url) {
                    console.log('[External Logout] SUCCESS for URL[' + index + ']:', url);
                },
                error: function (xhr, status, error) {
                    console.error('[External Logout] FAILED for URL[' + index + '] (' + url + '):', error, 'XHR status:', xhr.status);
                }
            });
            logoutPromises.push(promise);
        })(i, callbackURLs[i]);
    }

    console.log('[Main] Waiting for all', logoutPromises.length, 'external logout promise(s) to complete...');

    // Wait for all external logouts, then perform local logout only if data.keepAuthentication is true
    $.when.apply($, logoutPromises).always(function () {
        if (data.keepAuthentication) {
            console.log('[Main] All external logouts completed (success or failure). Proceeding with local logout...');
            $.ajax({
                url: "/api/v1/logout",
                type: "POST",
                contentType: "application/json",
                data: JSON.stringify({}),
                headers: {
                    "X-Logout": "1"
                },
                success: function (response) {
                    console.log('[Local Logout] SUCCESS. Reloading page...');
                    window.location.href = "./?app=" + data.appName;
                },
                error: function (xhr, status, error) {
                    console.error('[Local Logout] FAILED:', error, 'XHR status:', xhr.status);
                    console.log('[Local Logout] Reloading page anyway...');
//                  window.location.href = "/?app=" + data.appName;

                }
            });
        } else {
            console.log('[Main] All external logouts completed. data.keepAuthentication is false, skipping local logout.');
            window.location.href = "./?app=" + data.appName ;

        }
    });
    console.log('[Main] Logout script initialized. Waiting for AJAX callbacks...');
})();
console.log('=== Logout Script IIFE Executed ===');
