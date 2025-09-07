function showToast(htmlMessage, type) {
    // Sanitize htmlMessage to prevent XSS
    const sanitizedMessage = htmlMessage
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');


    const toastType = type === 'error' ? '#ff2a00' : '#00ff7a';
    const toastTitle = type === 'error' ? 'Notification Error' : 'Notification';
    const toast = $(`
          <div class="toast" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header">
                <svg aria-hidden="true" class="bd-placeholder-img rounded me-2" height="20" preserveAspectRatio="xMidYMid slice" width="20" xmlns="http://www.w3.org/2000/svg"><rect width="100%" height="100%" fill="${toastType}"></rect></svg>
                <strong class="me-auto">${toastTitle}</strong>
              <small>now</small>
              <button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body">
              ${sanitizedMessage}
            </div>
          </div>
        `);

    $('.toast-container').append(toast);
    const bsToast = new bootstrap.Toast(toast[0]);
    bsToast.show();
}

function showToastSuccess(htmlMessage) {
    showToast(htmlMessage, 'success');
}

function showToastError(htmlMessage) {
    showToast(htmlMessage, 'error');
}



function showYesNoDialog(message, callback) {
    const dialog = $(`
        <div class="modal fade" id="yesNoDialog" tabindex="-1" aria-labelledby="yesNoLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="yesNoLabel">Confirm Action</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        ${message}
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">No</button>
                        <button type="button" class="btn btn-success" id="confirmYes">Yes</button>
                    </div>
                </div>
            </div>
        </div>
    `);

    $('body').append(dialog);

    dialog.on('click', '#confirmYes', function() {
        callback(true);
        dialog.modal('hide');
    });

    dialog.on('hidden.bs.modal', function () {
        $(this).remove();
    });

    const bsDialog = new bootstrap.Modal(dialog[0]);
    bsDialog.show();
}