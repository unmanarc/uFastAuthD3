#pragma once

#include <Mantids30/Program_Logs/applog.h>

/**
 * Event actions for account security events logging.
 * Represents the specific action taken within an event type.
 */
enum class SecurityEventAction : uint8_t
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
    case SecurityEventAction::CREATE:
        return "CREATE";
    case SecurityEventAction::UPDATE:
        return "UPDATE";
    case SecurityEventAction::DELETE:
        return "DELETE";
    case SecurityEventAction::LOCK:
        return "LOCK";
    case SecurityEventAction::UNLOCK:
        return "UNLOCK";
    case SecurityEventAction::EXPIRE:
        return "EXPIRE";
    case SecurityEventAction::RENEW:
        return "RENEW";
    case SecurityEventAction::FAILED:
        return "FAILED";
    case SecurityEventAction::CONFIRM:
        return "CONFIRM";
    case SecurityEventAction::FORCE_CHANGE:
        return "FORCE_CHANGE";
    case SecurityEventAction::CANCEL_FORCE_CHANGE:
        return "CANCEL_FORCE_CHANGE";
    case SecurityEventAction::DISABLE:
        return "DISABLE";
    case SecurityEventAction::AUTO_LOCK:
        return "AUTO_LOCK";
    case SecurityEventAction::LOGIN:
        return "LOGIN";
    case SecurityEventAction::LOGOUT:
        return "LOGOUT";
    case SecurityEventAction::ASSIGN_ACCOUNT:
        return "ASSIGN_ACCOUNT";
    case SecurityEventAction::REVOKE_ACCOUNT:
        return "REVOKE_ACCOUNT";
    case SecurityEventAction::REVOKE_ROLE:
        return "REVOKE_ROLE";
    case SecurityEventAction::ASSIGN_ROLE:
        return "ASSIGN_ROLE";
    case SecurityEventAction::ASSIGN_SCHEME:
        return "ASSIGN_SCHEME";
    case SecurityEventAction::REVOKE_SCHEME:
        return "REVOKE_SCHEME";
    case SecurityEventAction::SET_DEFAULT_ACTIVITY:
        return "SET_DEFAULT_ACTIVITY";
    case SecurityEventAction::ENABLE:
        return "ENABLE";
    default:
        return "UNKNOWN";
    }
}

inline Mantids30::Program::Logs::LogLevel SecurityEventActionToLogLevel(SecurityEventAction action)
{
    switch (action)
    {
    case SecurityEventAction::LOGIN:
    case SecurityEventAction::LOGOUT:
    case SecurityEventAction::RENEW:
    case SecurityEventAction::CONFIRM:
    case SecurityEventAction::ENABLE:
    case SecurityEventAction::ASSIGN_ACCOUNT:
    case SecurityEventAction::ASSIGN_ROLE:
    case SecurityEventAction::ASSIGN_SCHEME:
        return Mantids30::Program::Logs::LogLevel::INFO;
    case SecurityEventAction::FAILED:
    case SecurityEventAction::AUTO_LOCK:
    case SecurityEventAction::LOCK:
    case SecurityEventAction::DISABLE:
        return Mantids30::Program::Logs::LogLevel::ERR;
    case SecurityEventAction::CREATE:
    case SecurityEventAction::UPDATE:
    case SecurityEventAction::DELETE:
    case SecurityEventAction::REVOKE_ACCOUNT:
    case SecurityEventAction::REVOKE_ROLE:
    case SecurityEventAction::REVOKE_SCHEME:
        return Mantids30::Program::Logs::LogLevel::WARN;
    default:
        return Mantids30::Program::Logs::LogLevel::INFO;
    }
}
