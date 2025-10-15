/*
function logoutOK(response) {
  window.location = "/login";
}
function logoutFAILED(response) {
  console.log("Your sessionId is not working anymore in the remote side");
  window.location = "/login";
}
function logout() {
  $.ajax({
    url: '/japi_session?mode=LOGOUT',
    type: 'POST',
    headers: { "CSRFToken": csrfToken },
    success: logoutOK,
    error: logoutFAILED
  });
}


var intervalId = -1;

function ajaxAuthReCheck() 
{
  $.ajax({
    url: '/japi_session?mode=AUTHINFO',
    headers: { "CSRFToken": csrfToken },
    type: 'POST',
    success: function (response)
    {
      // Reestablish the interval with the new maxAge.
      clearInterval(intervalId);
      var intTime = parseInt(response["maxAge"],10)+1;
      console.log("Setting up the next session check to " + intTime + " sec's in future.");
      intervalId = setInterval(ajaxAuthReCheck, (intTime)*1000);
      console.log("Session renewed: " + response["maxAge"] + " sec's left" );
    },
    error: function (xhr, ajaxOptions, thrownError) {
      if(xhr.status==404) 
      {
        // Session is gone...
        clearInterval(intervalId);
        showToastError("Session Expired");
        logout();
      }
      else
      {
        console.log("Network error " + xhr.status);
      }
    }
  });
}

function ajaxLoadInfo() {
 $('#welcome').text("Welcome " + user);
 $("#version").text(softwareVersion);

  // Check the authentication when the session is supposed to expire, and logout if there is no session.
  var intTime = maxAge+1;
  console.log("Setting up the next session check to " + intTime + " sec's in future.");
  intervalId = setInterval(ajaxAuthReCheck,intTime*1000);

  csrfReady();
}

function ajaxRemoteExecuteMethod( methodPermLevel, target, endpointName, payload, successFunction  ) {
  var method = "remote." + methodPermLevel;
  var payloadData = { "target": target, "remoteMethod": methodPermLevel + "." + endpointName, "payload" : payload }
  $.ajax({
    url: '/japi_exec?method=' + method,
    type: 'POST',
    headers: { "CSRFToken": csrfToken },
    data: { payload: JSON.stringify(payloadData) },
    success: successFunction,
    error: function (result) {
      console.log("ERR");
      showToastError("Error Executing Remote Method...\nInsufficient Scopes");
    }
  });
}

function ajaxExecuteMethod( endpointName, payloadData, successFunction ) {
  $.ajax({
    url: '/japi_exec?method=' + endpointName,
    type: 'POST',
    headers: { "CSRFToken": csrfToken },
    data: { payload: JSON.stringify(payloadData) },
    success: successFunction,
    error: function (result) {
      console.log("ERR");
      showToastError("Error Executing Remote Method...\nInsufficient Scopes");
    }
  });
}
*/

/*
function commonFunctionError(xhr, ajaxOptions, thrownError) {
  if (xhr.status == 404) {
    // Session is gone...
    console.log("Session expired or unauthorized access attempted. Status code: " + xhr.status + ". The user may have been logged out, or the requested resource might not be accessible due to scope restrictions.");
  }
  else {
    console.log("Network error " + xhr.status);
  }
}*/

function commonFunctionError(xhr, status, error) {
  if (xhr.responseJSON && xhr.responseJSON.error && xhr.responseJSON.message) {
    showToastError("Error: " + xhr.responseJSON.error + " - " + xhr.responseJSON.message);
  } else {
    showToastError("Error " + xhr.status);
  }
}

function ajaxLoadInfo() {
  $('#welcome').text(user);
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
