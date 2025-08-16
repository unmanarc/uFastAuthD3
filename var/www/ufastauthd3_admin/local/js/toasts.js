function showToast(htmlMessage, type) {
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
              ${htmlMessage}
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
