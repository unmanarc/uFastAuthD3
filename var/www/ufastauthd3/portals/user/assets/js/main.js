
function commonFunctionError(xhr, status, error) {
  if (xhr.responseJSON && xhr.responseJSON.error && xhr.responseJSON.message) {
    showToastError("Error: " + xhr.responseJSON.error + " - " + xhr.responseJSON.message);
  } else {
    showToastError("Error " + xhr.status);
  }
}

function ajaxLoadInfo() {
  $('#welcome').text(ufad3_userPublicData.body.displayName);
  $("#version").text(softwareVersion);
}

function updatePrettyTime(inputId, outputId) {
  const seconds = parseInt(document.getElementById(inputId).value);
  if (isNaN(seconds) || seconds <= 0) {
      document.getElementById(outputId).textContent = '';
      return;
  }

  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainingSeconds = seconds % 60;

  let prettyTime = '';
  if (days > 0) prettyTime += days + (days === 1 ? ' day' : ' days');
  if (hours > 0) prettyTime += (prettyTime ? ', ' : '') + hours + (hours === 1 ? ' hour' : ' hours');
  if (minutes > 0) prettyTime += (prettyTime ? ' and ' : '') + minutes + (minutes === 1 ? ' minute' : ' minutes');
  if (remainingSeconds > 0) prettyTime += (prettyTime ? ' and ' : '') + remainingSeconds + (remainingSeconds === 1 ? ' second' : ' seconds');

  document.getElementById(outputId).textContent = 'Equivalent: ' + prettyTime;
}
