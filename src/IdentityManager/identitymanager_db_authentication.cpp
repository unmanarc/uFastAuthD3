#include "identitymanager_db.h"

#include <Mantids30/Helpers/datatables.h>
#include <Mantids30/Threads/lock_shared.h>

#include <Mantids30/Memory/a_bool.h>
#include <Mantids30/Memory/a_datetime.h>
#include <Mantids30/Memory/a_int32.h>
#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_uint32.h>
#include <Mantids30/Memory/a_uint64.h>
#include <Mantids30/Memory/a_var.h>
#include <optional>
#include <utility>

using namespace Mantids30::Memory;
using namespace Mantids30::Database;
using namespace Mantids30;

bool IdentityManager_DB::AuthController_DB::validateApplicationScopeOnRole(const std::string &roleName, const ApplicationScope &scope, bool lock)
{
    bool ret = false;
    if (lock)
        _parent->m_mutex.lockShared();

    ret = _parent->m_sqlConnector->qSelectSingleRow("SELECT `f_roleName` FROM iam.applicationRolesScopes WHERE `f_scopeId`=:scopeId AND `f_appName`=:appName AND `f_roleName`=:roleName;",
                                                    {{":scopeId", MAKE_VAR(STRING, scope.id)}, {":appName", MAKE_VAR(STRING, scope.appName)}, {":roleName", MAKE_VAR(STRING, roleName)}}, {});

    if (lock)
        _parent->m_mutex.unlockShared();

    return ret;
}

std::set<ApplicationScope> IdentityManager_DB::AuthController_DB::getRoleApplicationScopes(const std::string &appName, const std::string &roleName, bool lock)
{
    std::set<ApplicationScope> ret;

    if (lock)
        _parent->m_mutex.lockShared();

    Abstract::STRING sScopeName, sDescription;
    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT ars.`f_scopeId`,ascope.description FROM iam.applicationRolesScopes ars LEFT JOIN iam.applicationScopes ascope ON (ars.`f_scopeId` = "
                                              "ascope.scopeId AND ars.`f_appName` = ascope.f_appName) WHERE ars.`f_roleName`=:roleName AND ars.`f_appName`=:appName;",
                                              {{":roleName", MAKE_VAR(STRING, roleName)}, {":appName", MAKE_VAR(STRING, appName)}}, {&sScopeName, &sDescription});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert({appName, sScopeName.getValue(), sDescription.getValue()});
    }

    if (lock)
        _parent->m_mutex.unlockShared();

    return ret;
}

std::set<std::string> IdentityManager_DB::AuthController_DB::getApplicationRolesForScope(const ApplicationScope &applicationScope, bool lock)
{
    std::set<std::string> ret;
    if (lock)
        _parent->m_mutex.lockShared();

    Abstract::STRING roleName;
    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `f_roleName` FROM iam.applicationRolesScopes WHERE `f_scopeId`=:scopeId AND `f_appName`=:appName;",
                                              {{":appName", MAKE_VAR(STRING, applicationScope.appName)}, {":scopeId", MAKE_VAR(STRING, applicationScope.id)}}, {&roleName});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert(roleName.getValue());
    }

    if (lock)
        _parent->m_mutex.unlockShared();
    return ret;
}

std::string IdentityManager_DB::AuthController_DB::getAccountConfirmationToken(const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING token;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT confirmationToken FROM iam.accountsActivationToken WHERE `f_accountName`=:accountName LIMIT 1;",
                                                  {{":accountName", MAKE_VAR(STRING, accountName)}}, {&token}))
    {
        return token.getValue();
    }
    return "";
}
std::optional<std::pair<time_t, std::string>> IdentityManager_DB::AuthController_DB::getAccountLastAccess(const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    {
        Abstract::DATETIME lastLogin;
        Abstract::STRING appName;

        if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `lastLogin`,`f_appName`  FROM logs.applicationAccess_accountLastLogin WHERE `f_accountName`=:accountName ORDER BY `lastLogin` DESC LIMIT 1;",
                                                       {{":accountName", MAKE_VAR(STRING, accountName)}}, {&lastLogin, &appName}))
        {
            return std::make_pair(lastLogin.getValue(), appName.getValue());
        }
    }

    // no account? std::nullopt...
    return std::nullopt;
}

std::set<ApplicationScope> IdentityManager_DB::AuthController_DB::getAccountDirectApplicationScopes(const std::string &accountName, bool lock)
{
    std::set<ApplicationScope> ret;
    if (lock)
        _parent->m_mutex.lockShared();

    Abstract::STRING appName, scopeId;
    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `f_appName`,`f_scopeId` FROM iam.applicationScopeAccounts WHERE `f_accountName`=:accountName;", {{":accountName", MAKE_VAR(STRING, accountName)}},
                                              {&appName, &scopeId});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert({appName.getValue(), scopeId.getValue()});
    }

    if (lock)
        _parent->m_mutex.unlockShared();
    return ret;
}

// ------------------------------------------------------------------------
// Application Auth Log - Logout and Token tracking
// ------------------------------------------------------------------------
bool IdentityManager_DB::AuthController_DB::updateApplicationAuthLogAccessTokenId(const std::string &accountName, const std::string &appName, const std::string &refresherTokenId,
                                                                                  const std::string &accessTokenId, const time_t &accessTokenExpiration)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Update the log entry identified by the refresher token id
    return _parent->m_sqlConnector->qExecuteEx("UPDATE logs.applicationAccess_accountSessions "
                                               "SET `accessTokenId` = :accessTokenId, "
                                               "`accessTokenExpiration` = :accessTokenExpiration "
                                               "WHERE `f_accountName` = :accountName "
                                               "  AND `f_appName` = :appName "
                                               "  AND `refresherTokenId` = :refresherTokenId "
                                               "ORDER BY `loginDateTime` DESC "
                                               "LIMIT 1;",
                                               {{":accessTokenId", MAKE_VAR(STRING, accessTokenId)},
                                                {":accessTokenExpiration", MAKE_VAR(DATETIME, accessTokenExpiration)},
                                                {":accountName", MAKE_VAR(STRING, accountName)},
                                                {":appName", MAKE_VAR(STRING, appName)},
                                                {":refresherTokenId", MAKE_VAR(STRING, refresherTokenId)}});
}

bool IdentityManager_DB::AuthController_DB::logoutApplicationAuthLog(const std::string &accountName, const std::string &appName, const std::string &refresherTokenId, LogoutReason reason)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("UPDATE logs.applicationAccess_accountSessions "
                                               "SET `logoutDateTime` = CURRENT_TIMESTAMP, "
                                               "    `logoutReason` = :reason "
                                               "WHERE `f_accountName` = :accountName "
                                               "  AND `f_appName` = :appName "
                                               "  AND `refresherTokenId` = :refresherTokenId "
                                               "  AND `logoutDateTime` IS NULL "
                                               "ORDER BY `loginDateTime` DESC "
                                               "LIMIT 1;",
                                               {{":accountName", MAKE_VAR(STRING, accountName)},
                                                {":appName", MAKE_VAR(STRING, appName)},
                                                {":refresherTokenId", MAKE_VAR(STRING, refresherTokenId)},
                                                {":reason", MAKE_VAR(INT32, static_cast<int>(reason))}});
}


void IdentityManager_DB::AuthController_DB::insertApplicationAccountAccessAuthLog(const std::string &accountName, const std::string &appName, const uint32_t &schemeId,
                                                                                  const ClientDetails &clientDetails, const std::string &refresherTokenId, const std::string &accessTokenId,
                                                                                  const time_t &accessTokenExpiration, const time_t &refreshTokenExpiration)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Use INSERT OR REPLACE to handle upsert logic for accountsLastAccessToApplication
    _parent->m_sqlConnector->qExecuteEx("INSERT OR REPLACE INTO logs.applicationAccess_accountLastLogin (`f_accountName`, `f_appName`, `lastLogin`) "
                                         "VALUES (:accountName, :appName, CURRENT_TIMESTAMP);",
                                         {{":accountName", MAKE_VAR(STRING, accountName)}, {":appName", MAKE_VAR(STRING, appName)}});
    // Insert into the login history log
    _parent->m_sqlConnector->qExecuteEx("INSERT INTO logs.applicationAccess_accountSessions(`f_accountName`, `f_schemeId`, `f_appName`, `loginDateTime`, `loginIP`, `loginTLSCN`, `loginUserAgent`, `loginExtraData`, "
                                        "`refresherTokenId`, `accessTokenId`, `accessTokenExpiration`, `refreshTokenExpiration`) "
                                        "VALUES (:accountName, :schemeId, :appName, :loginDateTime, :loginIP, :loginTLSCN, :loginUserAgent, :loginExtraData, :refresherTokenId, :accessTokenId, "
                                        ":accessTokenExpiration, :refreshTokenExpiration);",
                                        {{":accountName", MAKE_VAR(STRING, accountName)},
                                         {":schemeId", MAKE_VAR(UINT32, schemeId)},
                                         {":appName", MAKE_VAR(STRING, appName)},
                                         {":loginDateTime", MAKE_VAR(DATETIME, time(nullptr))},
                                         {":loginIP", MAKE_VAR(STRING, clientDetails.ipAddress)},
                                         {":loginTLSCN", MAKE_VAR(STRING, clientDetails.tlsCommonName)},
                                         {":loginUserAgent", MAKE_VAR(STRING, clientDetails.userAgent)},
                                         {":loginExtraData", MAKE_VAR(STRING, clientDetails.extraData)},
                                         {":refresherTokenId", MAKE_VAR(STRING, refresherTokenId)},
                                         {":accessTokenId", MAKE_VAR(STRING, accessTokenId)},
                                         {":accessTokenExpiration", MAKE_VAR(DATETIME, accessTokenExpiration)},
                                         {":refreshTokenExpiration", MAKE_VAR(DATETIME, refreshTokenExpiration)}});
}
