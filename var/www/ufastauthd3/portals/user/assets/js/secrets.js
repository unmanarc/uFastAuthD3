
// Default Main View:
/*
function cancel(pos) {
    document.getElementById('chpasswd-' + pos).style.visibility = "collapse";
    document.getElementById('testpasswd-' + pos).style.visibility = "collapse";
    document.getElementById('passwdbtns-' + pos).style.visibility = "visible";
}
function changePassword(pos) {

    var pwdCheck = checkPasswordReq($("#newpass0-" + pos).val(), 12);

    if ($("#newpass0-" + pos).val() != $("#newpass1-" + pos).val()) {
        alert("Password does not match.");
        $("#newpass0-" + pos).focus();
    }
    else if (pwdCheck != "") {
        alert(pwdCheck);
        $("#newpass0-" + pos).focus();
    }
    else {
        document.getElementById('chpasswd-' + pos).style.visibility = "collapse";
        document.getElementById('passwdbtns-' + pos).style.visibility = "visible";

        $.ajax({
            url: '/japi_session?mode=CHPASSWD',
            type: 'POST',
            data: {
                auth: JSON.stringify({ pass: $("#oldpass-" + pos).val(), idx: pos }),
                newAuth: JSON.stringify({ pass: $("#newpass0-" + pos).val(), idx: pos })
            },
            headers: { "CSRFToken": csrfToken },
            success: function (result) {
                alert(`Password ${pos} Changed OK.`);
                // Reload screen info here...
                csrfReady();
            },
            error: function (result) {
                alert("Error changing password. Logging out.");
                logout();
            }
        });
    }
}

function openChangePassword(pos) {
    document.getElementById('chpasswd-' + pos).style.visibility = "visible";
    document.getElementById('passwdbtns-' + pos).style.visibility = "collapse";
}

function testPassword(pos) {
    document.getElementById('testpasswd-' + pos).style.visibility = "collapse";
    document.getElementById('passwdbtns-' + pos).style.visibility = "visible";

    $.ajax({
        url: '/japi_session?mode=TESTPASSWD',
        type: 'POST',
        data: {
            auth: JSON.stringify({ pass: $("#pass-" + pos).val(), idx: pos })
        },
        headers: { "CSRFToken": csrfToken },
        success: function (result) {
            alert(`Password ${pos} validated OK.`);
        },
        error: function (result) {
            alert("Incorrect Password.\nLogging out.");
            logout();
        }
    });
}
function openTestPassword(pos) {
    document.getElementById('testpasswd-' + pos).style.visibility = "visible";
    document.getElementById('passwdbtns-' + pos).style.visibility = "collapse";
}

function drawPasswordList(inputPasswords) {
    document.getElementById("passwdlist-body").innerHTML = "";
    var i = 0;
    for (let input of inputPasswords) {

        idx = input["idx"];

        var passFunction = "Not Defined";
        var isRequiredAtLogin = (input["isRequiredAtLogin"] == true) ? "true" : "false";
        var badAtttempts = parseInt(input["badAtttempts"], 10);

        if (input["passwordFunction"] == 0) passFunction = "Password";
        else if (input["passwordFunction"] == 1) passFunction = "Password, SHA256";
        else if (input["passwordFunction"] == 2) passFunction = "Password, SHA512";
        else if (input["passwordFunction"] == 3) passFunction = "Password, SSHA256";
        else if (input["passwordFunction"] == 4) passFunction = "Password, SSHA512";
        else if (input["passwordFunction"] == 5) passFunction = "Google Authenticator";

        var statusColor = "black";
        var status = "Operational";
        if (input["isLocked"] == true) {
            status = "Locked (Bad Attempts)";
            statusColor = "red";
        }
        else if (input["isExpired"] == true) {
            status = "Expired";
            statusColor = "red";
        }

        $("#passwdlist-body").append(

            '<div class="row  justify-content-center align-items-center">' +
            ' <div class="col-md-5 my-auto">' +
            '   <div class="card card-block d-flex login-card">' +
            '    <div class="card-body align-items-center justify-content-center">' +
            '     <table width=100%>' +
            `      <tr valign=top><td ><b>Description:</b></td><td align="right"><span style="font-weight: bolder;" id="passwdlist-description-${idx}"></span></td></tr>` +
            `      <tr valign=top><td ><b>Type:</b></td><td align="right">  ${passFunction} (ID=${idx})</td></tr>` +
            `      <tr valign=top><td ><b>Required for Login:</b></td><td align="right"> ${isRequiredAtLogin}</td></tr>` +
            `      <tr valign=top><td ><b>Bad Attempts Count:</b></td><td align="right"> ${badAtttempts}</td></tr>` +
            `      <tr valign=top><td ><b>Status:</b></td><td align="right"> <font color=${statusColor}>${status}</font></td></tr>` +

            `<tr valign=top id="chpasswd-${idx}" style="visibility: collapse;">` +
            '	<td colspan="2" align="right"><hr>' +
            '		<table width=100% style=" border-spacing: 10px;   border-collapse: separate;"><form action="#!">' +
            `				<tr valign=top><td>Old Password:</td><td align="right"><input type="password" name="password" id="oldpass-${idx}" class="form-control" placeholder="********"></td></tr>` +
            `				<tr valign=top><td>New Password:</td><td align="right"><input type="password" name="password" id="newpass0-${idx}" class="form-control" placeholder="********"></td></tr>` +
            `				<tr valign=top><td>Confirm New Password:</td><td align="right"><input type="password" name="password" id="newpass1-${idx}" class="form-control" placeholder="********"></td></tr>` +
            `				<tr valign=top><td></td><td align="right"><br><input name="login" id="login" class="btn btn-secondary" type="button" value="Cancel" onclick="javascript:cancel(${idx})"> ` +
            `                                                             <input name="login" id="login" class="btn btn-dark" type="button" value="Change" onclick="javascript:changePassword(${idx})"></td></tr>` +
            '		</form></table>' +
            '	</td>' +
            '</tr>' +
            `<tr valign=top id="testpasswd-${idx}" style="visibility: collapse;">` +
            '	<td colspan="2" align="right"><hr>' +
            '		<table width=100% style=" border-spacing: 10px;   border-collapse: separate;"><form action="#!">' +
            `			<tr valign=top><td>Password:</td><td align="right"><input type="password" name="password" id="pass-${idx}" class="form-control" placeholder="********"></td></tr>` +
            `				<tr valign=top><td></td><td align="right"><br><input name="login" id="login" class="btn btn-secondary" type="button" value="Cancel" onclick="javascript:cancel(${idx})"> ` +
            `                                                             <input name="login" id="login" class="btn btn-dark" type="button" value="Test" onclick="javascript:testPassword(${idx})"></td></tr>` +
            '		</form></table>' +
            '	</td>' +
            '</tr>' +
            `<tr valign=top id="passwdbtns-${idx}">` +
            '	<td colspan="2" align="right"><hr>' +
            `		<input name="login" id="login" class="btn btn-success" type="button" value="Test Password" onclick="javascript:openTestPassword(${idx})"> ` +
            `		<input name="login" id="login" class="btn btn-dark" type="button" value="Change Password" onclick="javascript:openChangePassword(${idx})">` +
            ' 	</td>' +
            '</tr>' +



            '</table>' +
            '   </div>' +
            '  </div>' +
            ' </div>' +
            '</div>' +
            '<br>'
        );
        $(`#passwdlist-description-${idx}`).text(input["description"]);
    }
}

*/

function drawPasswordList(inputPasswords) {
    document.getElementById("passwdlist-body").innerHTML = "";
    
    for (let idx in inputPasswords) {
        const input = inputPasswords[idx];
        
        // Get slot details
        const slotDetails = input.slotDetails || {};
        
        var passFunction = "Not Defined";
        var isRequiredAtLogin = slotDetails.isRequiredAtLogin ? "Yes" : "No";
        var badAttempts = parseInt(input.badAttempts || 0, 10);
        
        // Determine password function type
        switch(slotDetails.passwordFunction) {
            case 0: passFunction = "Password"; break;
            case 1: passFunction = "Password, SHA256"; break;
            case 2: passFunction = "Password, SHA512"; break;
            case 3: passFunction = "Password, SSHA256"; break;
            case 4: passFunction = "Password, SSHA512"; break;
            case 5: passFunction = "Google Authenticator"; break;
        }
        
        // Determine status
        var statusClass = "text-success";
        var status = "Operational";
        if (input.isLocked) {
            status = "Locked (Bad Attempts)";
            statusClass = "text-danger";
        } else if (input.isExpired) {
            status = "Expired";
            statusClass = "text-danger";
        }
        
        const cardHtml = `
        <div class="card shadow-sm">
            <div class="card-body">
                <!-- Main information -->
                <div class="row mb-2">
                    <div class="col-5 fw-bold">Description:</div>
                    <div class="col-7 text-end fw-bolder" id="passwdlist-description-${idx}"></div>
                </div>
                <div class="row mb-2">
                    <div class="col-5 fw-bold">Type:</div>
                    <div class="col-7 text-end">${passFunction} (ID=${idx})</div>
                </div>
                <div class="row mb-2">
                    <div class="col-5 fw-bold">Required for Login:</div>
                    <div class="col-7 text-end">${isRequiredAtLogin}</div>
                </div>
                <div class="row mb-2">
                    <div class="col-5 fw-bold">Bad Attempts Count:</div>
                    <div class="col-7 text-end">${badAttempts}</div>
                </div>
                <div class="row mb-3">
                    <div class="col-5 fw-bold">Status:</div>
                    <div class="col-7 text-end ${statusClass} fw-semibold">${status}</div>
                </div>
                
                <!-- Change password form (hidden initially) -->
                <div id="chpasswd-${idx}" class="collapse">
                    <hr>
                    <form onsubmit="return false;">
                        <div class="mb-3">
                            <label for="oldpass-${idx}" class="form-label">Old Password:</label>
                            <input type="password" id="oldpass-${idx}" class="form-control" placeholder="********">
                        </div>
                        <div class="mb-3">
                            <label for="newpass0-${idx}" class="form-label">New Password:</label>
                            <input type="password" id="newpass0-${idx}" class="form-control" placeholder="********">
                        </div>
                        <div class="mb-3">
                            <label for="newpass1-${idx}" class="form-label">Confirm New Password:</label>
                            <input type="password" id="newpass1-${idx}" class="form-control" placeholder="********">
                        </div>
                        <div class="d-flex justify-content-end gap-2">
                            <button type="button" class="btn btn-secondary" onclick="cancel(${idx})">Cancel</button>
                            <button type="button" class="btn btn-dark" onclick="changePassword(${idx})">Change</button>
                        </div>
                    </form>
                </div>
                
                <!-- Test password form (hidden initially) -->
                <div id="testpasswd-${idx}" class="collapse">
                    <hr>
                    <form onsubmit="return false;">
                        <div class="mb-3">
                            <label for="pass-${idx}" class="form-label">Password:</label>
                            <input type="password" id="pass-${idx}" class="form-control" placeholder="********">
                        </div>
                        <div class="d-flex justify-content-end gap-2">
                            <button type="button" class="btn btn-secondary" onclick="cancel(${idx})">Cancel</button>
                            <button type="button" class="btn btn-dark" onclick="testPassword(${idx})">Test</button>
                        </div>
                    </form>
                </div>
                
                <!-- Action buttons -->
                <div id="passwdbtns-${idx}">
                    <hr>
                    <div class="d-flex justify-content-end gap-2">
                        <button type="button" class="btn btn-success" onclick="openTestPassword(${idx})">Test Password</button>
                        <button type="button" class="btn btn-dark" onclick="openChangePassword(${idx})">Change Password</button>
                    </div>
                </div>
            </div>
        </div>`;
        
        // Add to DOM
        document.getElementById("passwdlist-body").insertAdjacentHTML('beforeend', cardHtml);
        
        // Set description securely
        document.getElementById(`passwdlist-description-${idx}`).textContent = slotDetails.description || "N/A";
    }
}

// Funciones auxiliares necesarias (asumiendo que ya existen)
function openChangePassword(idx) {
    // Ocultar botones y mostrar formulario de cambio
    document.getElementById(`passwdbtns-${idx}`).style.display = 'none';
    document.getElementById(`testpasswd-${idx}`).classList.remove('show');
    
    const changeForm = document.getElementById(`chpasswd-${idx}`);
    changeForm.classList.add('show');
}

function openTestPassword(idx) {
    // Ocultar botones y mostrar formulario de prueba
    document.getElementById(`passwdbtns-${idx}`).style.display = 'none';
    document.getElementById(`chpasswd-${idx}`).classList.remove('show');
    
    const testForm = document.getElementById(`testpasswd-${idx}`);
    testForm.classList.add('show');
}

function cancel(idx) {
    // Ocultar formularios y mostrar botones
    document.getElementById(`chpasswd-${idx}`).classList.remove('show');
    document.getElementById(`testpasswd-${idx}`).classList.remove('show');
    document.getElementById(`passwdbtns-${idx}`).style.display = 'block';
}


$(document).ready(function() {
    loadCredentials();
});

function loadCredentials()
{
     $.ajax({
            url: '/api/v1/listCredentials',
            type: 'GET',
            contentType: 'application/json',
            data: JSON.stringify(
                { 
                }),
            success: function (response) 
            {
                drawPasswordList(response);
            },
            error: function (result) 
            {
                window.location.href = "/index.html";
            }
        });

     $.ajax({
            url: '/api/v1/getSessionInfo',
            type: 'GET',
            contentType: 'application/json',
            data: JSON.stringify(
                { 
                }),
            success: function (response) 
            {
                // Update welcome message with user info
                if (response && response.user) {
                    $("#welcome").text("Welcome " + response.user);
                }
            },
            error: function (result) 
            {
                window.location.href = "/index.html";
            }
        });


}
