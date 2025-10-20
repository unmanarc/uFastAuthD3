// Global variables
let currentUser = null;
let passwordSlots = [];
let sessions = [];
let logs = [];
let ipAddresses = [];

// Initialize on document ready
$(document).ready(function() {
    loadUserInfo();
    loadDashboard();
    
    // Set up event listeners
    $('#logFilter').on('change', filterLogs);
    $('#newPassword').on('input', checkPasswordStrength);
});

// Navigation functions
function showSection(sectionName) {
    // Hide all sections
    $('.content-section').hide();
    
    // Remove active class from all nav links
    $('.nav-link').removeClass('active');
    
    // Show selected section
    $(`#${sectionName}-section`).show();
    
    // Add active class to clicked nav link
    $(`a[onclick="showSection('${sectionName}')"]`).addClass('active');
    
    // Load section-specific data
    switch(sectionName) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'profile':
            loadProfile();
            break;
        case 'passwords':
            loadPasswordSlots();
            break;
        case 'mfa':
            loadMFAStatus();
            break;
        case 'sessions':
            loadSessions();
            break;
        case 'logs':
            loadLogs();
            break;
        case 'ipaddresses':
            loadIPAddresses();
            break;
    }
}

// User info functions
function loadUserInfo() {
    $.ajax({
        url: '/api/v1/getCurrentUser',
        type: 'GET',
        success: function(response) {
            currentUser = response;
            $('#currentUserName').text(response.username);
        },
        error: handleError
    });
}

// Dashboard functions
function loadDashboard() {
    // Load active sessions count
    $.ajax({
        url: '/api/v1/getSelfSessions',
        type: 'GET',
        success: function(response) {
            $('#activeSessionsCount').text(response.sessions.length);
            $('#lastLoginTime').text(formatDateTime(response.lastLogin));
        },
        error: handleError
    });
    
    // Load password slots count
    $.ajax({
        url: '/api/v1/getSelfPasswordSlots',
        type: 'GET',
        success: function(response) {
            $('#passwordSlotsCount').text(response.slots.length);
        },
        error: handleError
    });
    
    // Load MFA status
    $.ajax({
        url: '/api/v1/getSelfMFAStatus',
        type: 'GET',
        success: function(response) {
            $('#mfaStatus').text(response.enabled ? 'ON' : 'OFF');
        },
        error: handleError
    });
}

// Profile functions
function loadProfile() {
    $.ajax({
        url: '/api/v1/getSelfProfile',
        type: 'GET',
        success: function(response) {
            $('#profileUsername').val(response.username);
            $('#profileEmail').val(response.email);
            $('#profileFullName').val(response.fullName);
            $('#profilePhone').val(response.phone);
            $('#profileDepartment').val(response.department);
        },
        error: handleError
    });
}

function toggleEditProfile() {
    const isReadonly = $('#profileEmail').prop('readonly');
    
    if (isReadonly) {
        // Enable editing
        $('#profileEmail, #profileFullName, #profilePhone, #profileDepartment').prop('readonly', false);
        $('#profileEditButtons').show();
    } else {
        // Disable editing
        $('#profileEmail, #profileFullName, #profilePhone, #profileDepartment').prop('readonly', true);
        $('#profileEditButtons').hide();
    }
}

function saveProfile() {
    const profileData = {
        email: $('#profileEmail').val(),
        fullName: $('#profileFullName').val(),
        phone: $('#profilePhone').val(),
        department: $('#profileDepartment').val()
    };
    
    $.ajax({
        url: '/api/v1/updateSelfProfile',
        type: 'PATCH',
        contentType: 'application/json',
        data: JSON.stringify(profileData),
        success: function(response) {
            showToast('Success', 'Profile updated successfully', 'success');
            toggleEditProfile();
        },
        error: handleError
    });
}

function cancelEditProfile() {
    loadProfile();
    toggleEditProfile();
}

// Password Management functions
function loadPasswordSlots() {
    $.ajax({
        url: '/api/v1/getSelfPasswordSlots',
        type: 'GET',
        success: function(response) {
            passwordSlots = response.slots;
            renderPasswordSlots(response.slots);
        },
        error: handleError
    });
}

function renderPasswordSlots(slots) {
    let html = '<div class="row">';
    
    slots.forEach(slot => {
        const functionType = getPasswordFunctionName(slot.function);
        const statusColor = getStatusColor(slot);
        const status = getStatusText(slot);
        
        html += `
            <div class="col-md-6 mb-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">${escapeHtml(slot.description)}</h5>
                        <table class="table table-sm">
                            <tr>
                                <td><strong>Type:</strong></td>
                                <td>${functionType} (ID: ${slot.slotId})</td>
                            </tr>
                            <tr>
                                <td><strong>Required for Login:</strong></td>
                                <td>${slot.isRequiredAtLogin ? 'Yes' : 'No'}</td>
                            </tr>
                            <tr>
                                <td><strong>Bad Attempts:</strong></td>
                                <td>${slot.badAttempts || 0}</td>
                            </tr>
                            <tr>
                                <td><strong>Status:</strong></td>
                                <td><span class="badge bg-${statusColor}">${status}</span></td>
                            </tr>
                            <tr>
                                <td><strong>Last Changed:</strong></td>
                                <td>${formatDateTime(slot.lastChange)}</td>
                            </tr>
                            ${slot.expiration ? `
                            <tr>
                                <td><strong>Expires:</strong></td>
                                <td>${formatDateTime(slot.expiration)}</td>
                            </tr>
                            ` : ''}
                        </table>
                        <div class="btn-group" role="group">
                            <button class="btn btn-sm btn-success" onclick="openTestPassword(${slot.slotId})">
                                <i class="bi bi-check-circle"></i> Test
                            </button>
                            <button class="btn btn-sm btn-primary" onclick="openChangePassword(${slot.slotId})">
                                <i class="bi bi-key"></i> Change
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    $('#passwordSlotsList').html(html);
}

function getPasswordFunctionName(func) {
    const functions = {
        0: 'Password',
        1: 'Password (SHA256)',
        2: 'Password (SHA512)',
        3: 'Password (SSHA256)',
        4: 'Password (SSHA512)',
        5: 'Google Authenticator'
    };
    return functions[func] || 'Unknown';
}

function getStatusColor(slot) {
    if (slot.isLocked) return 'danger';
    if (slot.isExpired) return 'warning';
    return 'success';
}

function getStatusText(slot) {
    if (slot.isLocked) return 'Locked (Bad Attempts)';
    if (slot.isExpired) return 'Expired';
    return 'Active';
}

function openChangePassword(slotId) {
    const slot = passwordSlots.find(s => s.slotId === slotId);
    if (!slot) return;
    
    $('#changePasswordSlotId').val(slotId);
    $('#changePasswordSlotDesc').val(slot.description);
    $('#currentPassword').val('');
    $('#newPassword').val('');
    $('#confirmPassword').val('');
    $('#passwordStrengthIndicator').html('');
    
    const modal = new bootstrap.Modal(document.getElementById('changePasswordModal'));
    modal.show();
}

function openTestPassword(slotId) {
    const slot = passwordSlots.find(s => s.slotId === slotId);
    if (!slot) return;
    
    $('#testPasswordSlotId').val(slotId);
    $('#testPasswordSlotDesc').val(slot.description);
    $('#testPassword').val('');
    
    const modal = new bootstrap.Modal(document.getElementById('testPasswordModal'));
    modal.show();
}

function submitPasswordChange() {
    const slotId = $('#changePasswordSlotId').val();
    const currentPassword = $('#currentPassword').val();
    const newPassword = $('#newPassword').val();
    const confirmPassword = $('#confirmPassword').val();
    
    if (newPassword !== confirmPassword) {
        showToast('Error', 'New passwords do not match', 'danger');
        return;
    }
    
    $.ajax({
        url: '/api/v1/changeSelfPassword',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            slotId: parseInt(slotId),
            currentPassword: currentPassword,
            newPassword: newPassword
        }),
        success: function(response) {
            showToast('Success', 'Password changed successfully', 'success');
            bootstrap.Modal.getInstance(document.getElementById('changePasswordModal')).hide();
            loadPasswordSlots();
        },
        error: handleError
    });
}

function submitPasswordTest() {
    const slotId = $('#testPasswordSlotId').val();
    const password = $('#testPassword').val();
    
    $.ajax({
        url: '/api/v1/testSelfPassword',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            slotId: parseInt(slotId),
            password: password
        }),
        success: function(response) {
            if (response.valid) {
                showToast('Success', 'Password is valid', 'success');
            } else {
                showToast('Error', 'Password is invalid', 'danger');
            }
            bootstrap.Modal.getInstance(document.getElementById('testPasswordModal')).hide();
        },
        error: handleError
    });
}

function checkPasswordStrength(e) {
    const password = $(e.target).val();
    const indicator = $('#passwordStrengthIndicator');
    
    if (password.length === 0) {
        indicator.html('');
        return;
    }
    
    let strength = 0;
    let feedback = [];
    
    // Length check
    if (password.length >= 8) strength++;
    if (password.length >= 12) strength++;
    else feedback.push('Use at least 12 characters');
    
    // Character variety checks
    if (/[a-z]/.test(password)) strength++;
    else feedback.push('Include lowercase letters');
    
    if (/[A-Z]/.test(password)) strength++;
    else feedback.push('Include uppercase letters');
    
    if (/[0-9]/.test(password)) strength++;
    else feedback.push('Include numbers');
    
    if (/[^a-zA-Z0-9]/.test(password)) strength++;
    else feedback.push('Include special characters');
    
    // Display strength
    let strengthText = '';
    let strengthClass = '';
    
    if (strength < 3) {
        strengthText = 'Weak';
        strengthClass = 'text-danger';
    } else if (strength < 5) {
        strengthText = 'Fair';
        strengthClass = 'text-warning';
    } else {
        strengthText = 'Strong';
        strengthClass = 'text-success';
    }
    
    let html = `<span class="${strengthClass}">Strength: ${strengthText}</span>`;
    if (feedback.length > 0) {
        html += '<br><small>' + feedback.join(', ') + '</small>';
    }
    
    indicator.html(html);
}

// MFA functions
function loadMFAStatus() {
    $.ajax({
        url: '/api/v1/getSelfMFAStatus',
        type: 'GET',
        success: function(response) {
            if (response.enabled) {
                $('#totpEnabled').show();
                $('#totpDisabled').hide();
                $('#totpSetup').hide();
            } else {
                $('#totpEnabled').hide();
                $('#totpDisabled').show();
                $('#totpSetup').hide();
            }
        },
        error: handleError
    });
}

function setupTOTP() {
    $.ajax({
        url: '/api/v1/setupSelfTOTP',
        type: 'POST',
        success: function(response) {
            $('#totpSecret').val(response.secret);
            // Here you would normally generate a QR code
            // For now, we'll just show the secret
            $('#qrcode').html(`<div class="alert alert-info">QR Code: ${response.qrCodeUrl}</div>`);
            $('#totpSetup').show();
            $('#totpDisabled').hide();
        },
        error: handleError
    });
}

function verifyTOTP() {
    const code = $('#totpVerifyCode').val();
    
    $.ajax({
        url: '/api/v1/verifySelfTOTP',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            code: code
        }),
        success: function(response) {
            showToast('Success', 'TOTP enabled successfully', 'success');
            loadMFAStatus();
        },
        error: handleError
    });
}

function disableTOTP() {
    if (!confirm('Are you sure you want to disable TOTP authentication?')) {
        return;
    }
    
    $.ajax({
        url: '/api/v1/disableSelfTOTP',
        type: 'DELETE',
        success: function(response) {
            showToast('Success', 'TOTP disabled successfully', 'success');
            loadMFAStatus();
        },
        error: handleError
    });
}

// Sessions functions
function loadSessions() {
    $.ajax({
        url: '/api/v1/getSelfSessions',
        type: 'GET',
        success: function(response) {
            sessions = response.sessions;
            renderSessions(response.sessions);
        },
        error: handleError
    });
}

function renderSessions(sessions) {
    let html = '';
    
    sessions.forEach(session => {
        const isCurrent = session.isCurrent ? '<span class="badge bg-success">Current</span>' : '';
        
        html += `
            <tr>
                <td>${session.sessionId}</td>
                <td>${session.ipAddress}</td>
                <td>${escapeHtml(session.userAgent)}</td>
                <td>${formatDateTime(session.loginTime)}</td>
                <td>${formatDateTime(session.lastActivity)}</td>
                <td>${isCurrent}</td>
                <td>
                    ${!session.isCurrent ? 
                        `<button class="btn btn-sm btn-danger" onclick="terminateSession('${session.sessionId}')">
                            <i class="bi bi-x-circle"></i> Terminate
                        </button>` : 
                        ''
                    }
                </td>
            </tr>
        `;
    });
    
    $('#sessionsTableBody').html(html || '<tr><td colspan="7" class="text-center">No active sessions</td></tr>');
}

function terminateSession(sessionId) {
    if (!confirm('Are you sure you want to terminate this session?')) {
        return;
    }
    
    $.ajax({
        url: '/api/v1/terminateSelfSession',
        type: 'DELETE',
        contentType: 'application/json',
        data: JSON.stringify({
            sessionId: sessionId
        }),
        success: function(response) {
            showToast('Success', 'Session terminated successfully', 'success');
            loadSessions();
        },
        error: handleError
    });
}

function terminateAllSessions() {
    if (!confirm('Are you sure you want to terminate all other sessions?')) {
        return;
    }
    
    $.ajax({
        url: '/api/v1/terminateAllSelfSessions',
        type: 'DELETE',
        success: function(response) {
            showToast('Success', 'All other sessions terminated successfully', 'success');
            loadSessions();
        },
        error: handleError
    });
}

// Logs functions
function loadLogs() {
    $.ajax({
        url: '/api/v1/getSelfLogs',
        type: 'GET',
        success: function(response) {
            logs = response.logs;
            renderLogs(response.logs);
        },
        error: handleError
    });
}

function renderLogs(logsToRender) {
    let html = '';
    
    logsToRender.forEach(log => {
        const statusBadge = log.status === 'success' ? 
            '<span class="badge bg-success">Success</span>' : 
            '<span class="badge bg-danger">Failed</span>';
        
        html += `
            <tr>
                <td>${formatDateTime(log.timestamp)}</td>
                <td>${log.activityType}</td>
                <td>${escapeHtml(log.description)}</td>
                <td>${log.ipAddress}</td>
                <td>${statusBadge}</td>
            </tr>
        `;
    });
    
    $('#logsTableBody').html(html || '<tr><td colspan="5" class="text-center">No logs available</td></tr>');
}

function filterLogs() {
    const filterValue = $('#logFilter').val();
    
    if (filterValue === 'all') {
        renderLogs(logs);
    } else {
        const filtered = logs.filter(log => log.activityType === filterValue);
        renderLogs(filtered);
    }
}

function refreshLogs() {
    loadLogs();
    showToast('Success', 'Logs refreshed', 'success');
}

// IP Addresses functions
function loadIPAddresses() {
    $.ajax({
        url: '/api/v1/getSelfIPAddresses',
        type: 'GET',
        success: function(response) {
            ipAddresses = response.ipAddresses;
            renderIPAddresses(response.ipAddresses);
        },
        error: handleError
    });
}

function renderIPAddresses(addresses) {
    let html = '';
    
    addresses.forEach(ip => {
        const statusBadge = ip.trusted ? 
            '<span class="badge bg-success">Trusted</span>' : 
            '<span class="badge bg-warning">Unknown</span>';
        
        html += `
            <tr>
                <td>${ip.address}</td>
                <td>${formatDateTime(ip.firstSeen)}</td>
                <td>${formatDateTime(ip.lastSeen)}</td>
                <td>${ip.location || 'Unknown'}</td>
                <td>${ip.accessCount}</td>
                <td>${statusBadge}</td>
            </tr>
        `;
    });
    
    $('#ipTableBody').html(html || '<tr><td colspan="6" class="text-center">No IP addresses recorded</td></tr>');
}

// Utility functions
function formatDateTime(dateString) {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return date.toLocaleString();
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text ? text.replace(/[&<>"']/g, m => map[m]) : '';
}

function showToast(title, message, type) {
    const toastEl = document.getElementById('liveToast');
    const toast = new bootstrap.Toast(toastEl);
    
    $('#toastTitle').text(title);
    $('#toastBody').text(message);
    
    // Set toast color based on type
    const header = $(toastEl).find('.toast-header');
    header.removeClass('bg-success bg-danger bg-warning bg-info');
    
    switch(type) {
        case 'success':
            header.addClass('bg-success text-white');
            break;
        case 'danger':
            header.addClass('bg-danger text-white');
            break;
        case 'warning':
            header.addClass('bg-warning');
            break;
        default:
            header.addClass('bg-info text-white');
    }
    
    toast.show();
}

function handleError(xhr, status, error) {
    let message = 'An error occurred';
    
    if (xhr.responseJSON && xhr.responseJSON.message) {
        message = xhr.responseJSON.message;
    } else if (xhr.responseText) {
        try {
            const response = JSON.parse(xhr.responseText);
            message = response.message || response.error || message;
        } catch(e) {
            message = xhr.responseText;
        }
    }
    
    showToast('Error', message, 'danger');
    
    // If unauthorized, redirect to login
    if (xhr.status === 401) {
        setTimeout(() => {
            window.location.href = '/login';
        }, 2000);
    }
}
/*
function logout() {
    $.ajax({
        url: '/api/v1/logout',
        type: 'POST',
        success: function(response) {
            window.location.href = '/login';
        },
        error: function() {
            // Even on error, redirect to login
            window.location.href = '/login';
        }
    });
}*/