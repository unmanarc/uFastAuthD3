#pragma once

/**
 * Event actions for account security events logging.
 * Represents the specific action taken within an event type.
 */
enum SecurityEventAction {
    CREATE = 0,              // Created/activated: account, slot, credential, scheme, session, role assignment
    UPDATE = 1,              // Updated: details, flags, expiration, scheme description, slot details
    DELETE = 2,              // Removed: account, slot, credential, scheme, session, role assignment
    LOCK = 3,                // Locked: account, credential slot, or blocked via token
    UNLOCK = 4,              // Unlocked: account or credential slot
    EXPIRE = 5,              // Expired: account, session, or forced credential expiry
    RENEW = 6,               // Renewed/refreshed: token or session
    FAILED = 7,              // Failed login attempt (triggers bad attempt counter)
    CONFIRM = 8,             // Confirmed account registration
    FORCE_CHANGE = 9,        // Set must-change flag on credential
    CANCEL_FORCE_CHANGE = 10,// Cleared must-change flag on credential
    DISABLE = 11,            // disableAccount()
    AUTO_LOCK = 12,          // incrementBadAttemptsOnAccountCredential() -> threshold exceeded
    LOGIN = 13,              // insertApplicationAccountAccessAuthLog()
    LOGOUT = 14,             // logoutApplicationAuthLog()
    ASSIGN_ACCOUNT = 15,     // addAccountToRole(), addApplicationScopeToAccount/Role()
    REVOKE_ACCOUNT = 16,     // removeAccountFromRole(), removeApplicationScopeFromAccount/Role()
    REVOKE_ROLE = 17,        // removeAccountFromRole(), removeApplicationScopeFromAccount/Role()
    ASSIGN_ROLE = 18,        // addAccountToRole(), addApplicationScopeToAccount/Role()
    ASSIGN_SCHEME = 19,
    REVOKE_SCHEME = 20,
    SET_DEFAULT_ACTIVITY = 21,
    ENABLE = 17
};
