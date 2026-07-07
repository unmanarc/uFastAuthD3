// ============================================================
// Login Helpers - Utility functions
// ============================================================

function updateTextMessage(text) {
    $("#message").text(text);
}

function showError(error) {
    updateTextMessage(`${error}`);
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