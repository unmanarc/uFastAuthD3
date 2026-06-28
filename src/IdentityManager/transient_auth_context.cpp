#include "transient_auth_context.h"

#include "globals.h"

void TransientAuthenticationContext::loadUUIDFromAccountName()
{
    // Account UUID
    std::optional<std::string> _accountUUID = Globals::getIdentityManager()->accounts->getAccountUUIDByAccountName(accountName);
    accountUUID = _accountUUID.has_value()? _accountUUID.value() : "745bedd8-dfb5-439d-811b-1ad0a8d14a32";
}
