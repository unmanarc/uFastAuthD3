#include "identitymanager.h"

#include <Mantids30/Helpers/random.h>




bool IdentityManager::Accounts::isAccountExpired(std::string_view accountUUID)
{
    time_t tAccountExpirationTime = getAccountExpirationTime(accountUUID);
    if (!tAccountExpirationTime)
    {
        return false;
    }
    return tAccountExpirationTime < time(nullptr);
}

bool IdentityManager::Accounts::hasValidAdminAccount()
{
    std::set<std::string> accounts = listAccounts();
    for (const std::string &account : accounts)
    {
        if (getAccountFlags(account).admin)
        {
            return true;
        }
    }
    return false;
}
