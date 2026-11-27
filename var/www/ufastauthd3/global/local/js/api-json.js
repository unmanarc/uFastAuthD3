/**
 * @brief Encode portal API GET arguments as the single JSON query expected by Mantids30.
 * @param {Object} options The normalized jQuery AJAX options.
 * @param {Object} originalOptions The caller's AJAX options.
 * @param {Object} request The jQuery request receiving cache control headers.
 */
$.ajaxPrefilter(function (options, originalOptions, request) {
    const url = new URL(options.url, window.location.href);
    if (options.type !== 'GET' || url.origin !== window.location.origin ||
        !/^\/(?:auth\/)?api\/v\d+\//.test(url.pathname)) {
        return;
    }

    // Mantids30 decodes the entire query as JSON. An appended jQuery cache
    // buster makes it invalid; unescaped JSON also corrupts '+' and '%' values.
    options.cache = true;
    options.data = encodeURIComponent(options.data || '{}');

    // Keep reads fresh without adding non-JSON parameters to the URL.
    request.setRequestHeader('Cache-Control', 'no-cache');
});
