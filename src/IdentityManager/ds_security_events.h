#pragma once

#include <Mantids30/Program_Logs/applog.h>

/**
 * Event actions for account security events logging.
 * Represents the specific action taken within an event type.
 */
enum SecurityEventAction
{
    CREATE = 0,               // Created/activated: account, slot, credential, scheme, session, role assignment
    UPDATE = 1,               // Updated: details, flags, expiration, scheme description, slot details
    DELETE = 2,               // Removed: account, slot, credential, scheme, session, role assignment
    LOCK = 3,                 // Locked: account, credential slot, or blocked via token
    UNLOCK = 4,               // Unlocked: account or credential slot
    EXPIRE = 5,               // Expired: account, session, or forced credential expiry
    RENEW = 6,                // Renewed/refreshed: token or session
    FAILED = 7,               // Failed login attempt (triggers bad attempt counter)
    CONFIRM = 8,              // Confirmed account registration
    FORCE_CHANGE = 9,         // Set must-change flag on credential
    CANCEL_FORCE_CHANGE = 10, // Cleared must-change flag on credential
    DISABLE = 11,             // disableAccount()
    AUTO_LOCK = 12,           // incrementBadAttemptsOnAccountCredential() -> threshold exceeded
    LOGIN = 13,               // insertApplicationAccountAccessAuthLog()
    LOGOUT = 14,              // logoutApplicationAuthLog()
    ASSIGN_ACCOUNT = 15,      // addAccountToRole(), addApplicationScopeToAccount/Role()
    REVOKE_ACCOUNT = 16,      // removeAccountFromRole(), removeApplicationScopeFromAccount/Role()
    REVOKE_ROLE = 17,         // removeAccountFromRole(), removeApplicationScopeFromAccount/Role()
    ASSIGN_ROLE = 18,         // addAccountToRole(), addApplicationScopeToAccount/Role()
    ASSIGN_SCHEME = 19,
    REVOKE_SCHEME = 20,
    SET_DEFAULT_ACTIVITY = 21,
    ENABLE = 22
};

inline const char *SecurityEventActionToString(SecurityEventAction action)
{
    switch (action)
    {
    case CREATE:
        return "CREATE";
    case UPDATE:
        return "UPDATE";
    case DELETE:
        return "DELETE";
    case LOCK:
        return "LOCK";
    case UNLOCK:
        return "UNLOCK";
    case EXPIRE:
        return "EXPIRE";
    case RENEW:
        return "RENEW";
    case FAILED:
        return "FAILED";
    case CONFIRM:
        return "CONFIRM";
    case FORCE_CHANGE:
        return "FORCE_CHANGE";
    case CANCEL_FORCE_CHANGE:
        return "CANCEL_FORCE_CHANGE";
    case DISABLE:
        return "DISABLE";
    case AUTO_LOCK:
        return "AUTO_LOCK";
    case LOGIN:
        return "LOGIN";
    case LOGOUT:
        return "LOGOUT";
    case ASSIGN_ACCOUNT:
        return "ASSIGN_ACCOUNT";
    case REVOKE_ACCOUNT:
        return "REVOKE_ACCOUNT";
    case REVOKE_ROLE:
        return "REVOKE_ROLE";
    case ASSIGN_ROLE:
        return "ASSIGN_ROLE";
    case ASSIGN_SCHEME:
        return "ASSIGN_SCHEME";
    case REVOKE_SCHEME:
        return "REVOKE_SCHEME";
    case SET_DEFAULT_ACTIVITY:
        return "SET_DEFAULT_ACTIVITY";
    case ENABLE:
        return "ENABLE";
    default:
        return "UNKNOWN";
    }
}

inline Mantids30::Program::Logs::eLogLevels SecurityEventActionToLogLevel(SecurityEventAction action)
{
    switch (action)
    {
    case LOGIN:
    case LOGOUT:
    case RENEW:
    case CONFIRM:
    case ENABLE:
    case ASSIGN_ACCOUNT:
    case ASSIGN_ROLE:
    case ASSIGN_SCHEME:
        return Mantids30::Program::Logs::eLogLevels::LEVEL_INFO;
    case FAILED:
    case AUTO_LOCK:
    case LOCK:
    case DISABLE:
        return Mantids30::Program::Logs::eLogLevels::LEVEL_ERR;
    case CREATE:
    case UPDATE:
    case DELETE:
    case REVOKE_ACCOUNT:
    case REVOKE_ROLE:
    case REVOKE_SCHEME:
        return Mantids30::Program::Logs::eLogLevels::LEVEL_WARN;
    default:
        return Mantids30::Program::Logs::eLogLevels::LEVEL_INFO;
    }
}
