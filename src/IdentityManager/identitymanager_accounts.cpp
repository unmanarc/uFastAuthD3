#include "identitymanager.h"

#include <Mantids30/Helpers/random.h>
#include <Mantids30/Threads/lock_shared.h>

IdentityManager::Accounts::Accounts(IdentityManager *m_parent)
{
    this->m_parent = m_parent;
}

bool IdentityManager::Accounts::isAccountExpired(const std::string &accountUUID)
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
