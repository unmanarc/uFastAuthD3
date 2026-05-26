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
#include <memory>
#include <optional>
#include <utility>

using namespace Mantids30::Memory;
using namespace Mantids30::Database;
using namespace Mantids30;

Credential IdentityManager_DB::AuthController_DB::retrieveAccountCredential(const std::string &accountName, const uint32_t &slotId, bool *accountFound, bool *authSlotFound)
{
    Credential ret;
    *authSlotFound = false;
    *accountFound = false;

    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::UINT32 badAttempts;
    Abstract::BOOL mustChange,isLocked;
    Abstract::DATETIME expiration,lastChange;
    Abstract::STRING salt, hash;

    *accountFound = _parent->accounts->doesAccountExist(accountName);

    if (!*accountFound)
        return ret;

    auto authSlots = listAllAuthenticationSlots();

    if (authSlots.find(slotId) != authSlots.end())
    {
        ret.slotDetails = authSlots[slotId];
    }
    else
    {
        // Bad...
        return ret;
    }

    if (_parent->m_sqlConnector->qSelectSingleRow(R"(SELECT `mustChange`,`expiration`,`badAttempts`,`salt`,`hash`,`lastChange`,`isLocked`
                                                                        FROM iam.accountCredentials
                                                                        WHERE `f_accountName`=:accountName AND `f_AuthSlotId`=:slotId LIMIT 1;
                                                                        )",
                                                  {{":accountName", MAKE_VAR(STRING, accountName)}, {":slotId", MAKE_VAR(UINT32, slotId)}},
                                                  {&mustChange, &expiration, &badAttempts, &salt, &hash,&lastChange,&isLocked}))
    {
        *authSlotFound = true;
        ret.isLocked = isLocked.getValue();
        ret.lastChange = lastChange.getValue();
        ret.mustChange = mustChange.getValue();
        ret.expirationTimestamp = expiration.getValue();
        ret.badAttempts = badAttempts.getValue();
        Mantids30::Helpers::Encoders::fromHex(salt.getValue(), ret.ssalt, 4);
        ret.hash = hash.getValue();
    }
    return ret;
}

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
    auto i = _parent->m_sqlConnector->qSelect("SELECT ars.`f_scopeId`,ascope.description FROM iam.applicationRolesScopes ars LEFT JOIN iam.applicationScopes ascope ON (ars.`f_scopeId` = "
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
    auto i = _parent->m_sqlConnector->qSelect("SELECT `f_roleName` FROM iam.applicationRolesScopes WHERE `f_scopeId`=:scopeId AND `f_appName`=:appName;",
                                              {{":appName", MAKE_VAR(STRING, applicationScope.appName)}, {":scopeId", MAKE_VAR(STRING, applicationScope.id)}}, {&roleName});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert(roleName.getValue());
    }

    if (lock)
        _parent->m_mutex.unlockShared();
    return ret;
}

bool IdentityManager_DB::AuthController_DB::changeAccountCredential(const std::string &accountName, Credential passwordData, uint32_t slotId)
{
    auto authSlots = listAllAuthenticationSlots();
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (authSlots.find(slotId) == authSlots.end())
    {
        return false;
    }

    if (!authSlots[slotId].isCompatible(passwordData.slotDetails))
    {
        return false;
    }

    if (passwordData.expirationTimestamp == 1)
    {
        if (authSlots[slotId].defaultExpirationSeconds == 0)
            passwordData.expirationTimestamp = 0;
        else
            passwordData.expirationTimestamp = time(nullptr) + authSlots[slotId].defaultExpirationSeconds;
    }

    // Única operación SQL
    return _parent->m_sqlConnector->qExecuteEx(R"(
            INSERT OR REPLACE INTO iam.accountCredentials (f_AuthSlotId, f_accountName, hash, expiration, salt, mustChange, usedstrengthJSONValidator)
            VALUES (:slotId, :account, :hash, :expiration, :salt, :mustChange, :usedValidator);
        )",
           {{":slotId", MAKE_VAR(UINT32, slotId)},
            {":account", MAKE_VAR(STRING, accountName)},
            {":hash", MAKE_VAR(STRING, passwordData.hash)},
            {":expiration", MAKE_VAR(DATETIME, passwordData.expirationTimestamp)},
            {":salt", MAKE_VAR(STRING, Mantids30::Helpers::Encoders::toHex(passwordData.ssalt, 4))},
            {":mustChange", MAKE_VAR(BOOL, passwordData.mustChange)},
            {":usedValidator", MAKE_VAR(STRING, authSlots[slotId].strengthJSONValidator)}});
}

bool IdentityManager_DB::AuthController_DB::activateAccountCredential(const std::string &accountName, uint32_t slotId, const std::string &hash, const std::string &ssalt)
{
    auto authSlots = listAllAuthenticationSlots();
    // Validate slot exists
    if (authSlots.find(slotId) == authSlots.end())
    {
        return false;
    }

    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Check if credential already exists (already activated)
    Abstract::UINT32 count;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT COUNT(*) FROM iam.accountCredentials WHERE `f_accountName`=:accountName AND `f_AuthSlotId`=:slotId;",
                                                  {{":accountName", MAKE_VAR(STRING, accountName)}, {":slotId", MAKE_VAR(UINT32, slotId)}}, {&count}))
    {
        if (count.getValue() > 0)
        {
            // Credential already activated - return specific error
            return false;
        }
    }
    else
    {
        return false;
    }

    // Insert the new activated credential (no DELETE needed)
    time_t expiration = 0;
    if (authSlots[slotId].defaultExpirationSeconds > 0)
    {
        expiration = time(nullptr) + authSlots[slotId].defaultExpirationSeconds;
    }

    return _parent->m_sqlConnector->qExecuteEx(R"(INSERT INTO iam.accountCredentials
           (`f_AuthSlotId`, `f_accountName`, `hash`, `expiration`, `salt`, `mustChange`, `usedstrengthJSONValidator`)
           VALUES (:slotId, :account, :hash, :expiration, :salt, :mustChange, :usedValidator);)",
                                               {{":slotId", MAKE_VAR(UINT32, slotId)},
                                                {":account", MAKE_VAR(STRING, accountName)},
                                                {":hash", MAKE_VAR(STRING, hash)},
                                                {":expiration", MAKE_VAR(DATETIME, expiration)},
                                                {":salt", MAKE_VAR(STRING, ssalt)},
                                                {":mustChange", MAKE_VAR(BOOL, false)},
                                                {":usedValidator", MAKE_VAR(STRING, authSlots[slotId].strengthJSONValidator)}});
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

        if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `lastLogin`,`f_appName`  FROM logs.accountsLastAccessToApplication WHERE `f_accountName`=:accountName ORDER BY `lastLogin` DESC LIMIT 1;",
                                                      {{":accountName", MAKE_VAR(STRING, accountName)}}, {&lastLogin, &appName}))
        {
            return std::make_pair(lastLogin.getValue(), appName.getValue());
        }
    }

    // no account? std::nullopt...
    return std::nullopt;
}

uint32_t IdentityManager_DB::AuthController_DB::getAccountActiveSessionsCount(const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    time_t now = time(nullptr);
    Abstract::UINT32 count;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT COUNT(*) FROM logs.applicationAuthLog "
                                                  "WHERE `f_accountName`=:accountName "
                                                  "  AND `logoutDateTime` IS NULL "
                                                  "  AND `refreshTokenExpiration` > CURRENT_TIMESTAMP; ",
                                                  {{":accountName", MAKE_VAR(STRING, accountName)}, {":now", MAKE_VAR(DATETIME, now)}}, {&count}))
    {
        return count.getValue();
    }
    return 0;
}

Json::Value IdentityManager_DB::AuthController_DB::searchAccountSessions(const std::string &accountName, const json &dataTablesFilters)
{
    Json::Value ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    ret["draw"] = dataTablesFilters["draw"];

    uint64_t offset = JSON_ASUINT64(dataTablesFilters, "start", 0);
    uint64_t limit = JSON_ASUINT64(dataTablesFilters, "length", 0);

    std::string orderByStatement = Helpers::DataTables::getOrderByStatement(dataTablesFilters);
    std::string searchValue = JSON_ASSTRING(dataTablesFilters["search"], "value", "");
    std::string whereFilters = "`f_accountName` = :ACCOUNTNAME";

    std::string sqlQueryStr = R"(
           SELECT `f_accountName`, `f_schemeId`, `f_appName`,
                  `loginDateTime`, `loginIP`, `loginTLSCN`, `loginUserAgent`,
                  `refresherTokenId`, `accessTokenId`,
                  `accessTokenExpiration`, `refreshTokenExpiration`,
                  `logoutDateTime`, `logoutReason`
           FROM logs.applicationAuthLog
           )";

    // Build params map
    std::map<std::string, std::shared_ptr<Abstract::Var>> params;
    params[":ACCOUNTNAME"] = MAKE_VAR(STRING, accountName);

    if (!searchValue.empty())
    {
        searchValue = "%" + searchValue + "%";
        whereFilters += " AND (`f_appName` LIKE :SEARCH OR `loginIP` LIKE :SEARCH)";
        params[":SEARCH"] = MAKE_VAR(STRING, searchValue);
    }

    {
        Abstract::STRING f_accountName, f_schemeId, f_appName, loginDateTime, loginIP, loginTLSCN, loginUserAgent;
        Abstract::STRING refresherTokenId, accessTokenId;
        Abstract::DATETIME accessTokenExpiration, refreshTokenExpiration, logoutDateTime;
        Abstract::UINT32 logoutReason;

        auto i = _parent->m_sqlConnector->qSelectWithFilters(sqlQueryStr, whereFilters, params,
                                                             {&f_accountName, &f_schemeId, &f_appName, &loginDateTime, &loginIP, &loginTLSCN, &loginUserAgent, &refresherTokenId, &accessTokenId,
                                                              &accessTokenExpiration, &refreshTokenExpiration, &logoutDateTime, &logoutReason},
                                                             orderByStatement, limit, offset);

        while (i && i->isSuccessful() && i->step())
        {
            Json::Value row;
            row["f_accountName"] = f_accountName.toJSON();
            row["f_schemeId"] = f_schemeId.toJSON();
            row["f_appName"] = f_appName.toJSON();
            row["loginDateTime"] = loginDateTime.toJSON();
            row["loginIP"] = loginIP.toJSON();
            row["loginTLSCN"] = loginTLSCN.toJSON();
            row["loginUserAgent"] = loginUserAgent.toJSON();
            row["refresherTokenId"] = refresherTokenId.toJSON();
            row["accessTokenId"] = accessTokenId.toJSON();
            row["accessTokenExpiration"] = accessTokenExpiration.toJSON();
            row["refreshTokenExpiration"] = refreshTokenExpiration.toJSON();
            row["logoutDateTime"] = logoutDateTime.toJSON();
            row["logoutReason"] = logoutReason.toJSON();

            // Flag: session is still active?
            row["isActive"] = (logoutDateTime.isNull() && accessTokenExpiration.isInFuture() && refreshTokenExpiration.isInFuture());

            ret["data"].append(row);
        }

        if (i)
        {
            ret["recordsTotal"] = i->getTotalRecordsCount();
            ret["recordsFiltered"] = i->getFilteredRecordsCount();
        }
    }

    return ret;
}

Json::Value IdentityManager_DB::AuthController_DB::searchAccountPasswordActivity(const std::string &accountName, const json &dataTablesFilters)
{
    Json::Value ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    ret["draw"] = dataTablesFilters["draw"];
    uint64_t offset = JSON_ASUINT64(dataTablesFilters, "start", 0);
    uint64_t limit = JSON_ASUINT64(dataTablesFilters, "length", 0);
    std::string orderByStatement = Helpers::DataTables::getOrderByStatement(dataTablesFilters);
    std::string searchValue = JSON_ASSTRING(dataTablesFilters["search"], "value", "");

    std::string whereFilters = "`f_accountName` = :ACCOUNTNAME";

    std::string sqlQueryStr = R"(
        SELECT `f_accountName`, `f_slotId`, `logDateTime`, `logIP`, `logTLSCN`,
               `logUserAgent`, `logExtraData`, `logStatus`
        FROM logs.authSlotLog
    )";

    // Construcción de parámetros
    std::map<std::string, std::shared_ptr<Abstract::Var>> params;
    params[":ACCOUNTNAME"] = MAKE_VAR(STRING, accountName);

    if (!searchValue.empty())
    {
        searchValue = "%" + searchValue + "%";
        whereFilters += " AND (`logIP` LIKE :SEARCH OR `logTLSCN` LIKE :SEARCH OR `logUserAgent` LIKE :SEARCH OR `logExtraData` LIKE :SEARCH)";
        params[":SEARCH"] = MAKE_VAR(STRING, searchValue);
        params[":SEARCH_SLOT"] = MAKE_VAR(STRING, searchValue);
    }

    {
        Abstract::STRING f_accountName, logDateTime, logIP, logTLSCN, logUserAgent, logExtraData;
        Abstract::INT32 f_slotId, logStatus;

        auto i = _parent->m_sqlConnector->qSelectWithFilters(sqlQueryStr, whereFilters, params, {&f_accountName, &f_slotId, &logDateTime, &logIP, &logTLSCN, &logUserAgent, &logExtraData, &logStatus},
                                                             orderByStatement, limit, offset);

        while (i && i->isSuccessful() && i->step())
        {
            Json::Value row;
            row["f_accountName"] = f_accountName.toJSON();
            row["f_slotId"] = f_slotId.toJSON();
            row["logDateTime"] = logDateTime.toJSON();
            row["logIP"] = logIP.toJSON();
            row["logTLSCN"] = logTLSCN.toJSON();
            row["logUserAgent"] = logUserAgent.toJSON();
            row["logExtraData"] = logExtraData.toJSON();
            row["logStatus"] = logStatus.toJSON();

            ret["data"].append(row);
        }

        if (i)
        {
            ret["recordsTotal"] = i->getTotalRecordsCount();
            ret["recordsFiltered"] = i->getFilteredRecordsCount();
        }
    }
    return ret;
}

std::pair<uint32_t, uint32_t> IdentityManager_DB::AuthController_DB::getAccountActiveCredentialsCount(const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    // Total available slots in the system
    Abstract::UINT32 totalCount;
    uint32_t totalSlots = 0;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT COUNT(*) FROM iam.authenticationSlots;", {}, {&totalCount}))
    {
        totalSlots = totalCount.getValue();
    }

    // Configured slots for this account
    Abstract::UINT32 accountCount;
    uint32_t accountSlots = 0;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT COUNT(*) FROM iam.accountCredentials WHERE `f_accountName`=:accountName;", {{":accountName", MAKE_VAR(STRING, accountName)}}, {&accountCount}))
    {
        accountSlots = accountCount.getValue();
    }

    return {totalSlots, accountSlots};
}

std::set<uint32_t> IdentityManager_DB::AuthController_DB::listUsedAuthenticationSlotsOnAccount(const std::string &accountName)
{
    std::set<uint32_t> r;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::UINT32 slotId;
    auto i = _parent->m_sqlConnector->qSelect("SELECT `f_AuthSlotId` FROM iam.accountCredentials WHERE `f_accountName`=:f_accountName;", {{":f_accountName", MAKE_VAR(STRING, accountName)}}, {&slotId});

    while (i && i->isSuccessful() && i->step())
    {
        r.insert(slotId.getValue());
    }

    return r;
}

std::map<uint32_t, std::pair<bool, Credential>> IdentityManager_DB::AuthController_DB::listAllAuthCredentialSlotsPublicDataForAccount(const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    std::map<uint32_t, std::pair<bool, Credential>> r;

    // Get all authentication slots and configured slots.
    std::map<uint32_t, AuthenticationSlotDetails> allAuthSlots = listAllAuthenticationSlots();
    auto configuredSlots = listUsedAuthenticationSlotsOnAccount(accountName);

    // For each authentication slot, create a public Credential entry
    for (const auto &[id, slotDetails] : allAuthSlots)
    {
        if (configuredSlots.find(id) != configuredSlots.end())
        {
            // Account has this slot configured - provide public info
            bool accountFound, authSlotFound;
            Credential cred = retrieveAccountCredential(accountName, id, &accountFound, &authSlotFound);
            if (!accountFound || !authSlotFound)
            {
                // UNEXPECTED ERROR!.
                return {};
            }
            r[id] = std::make_pair(true, cred.getPublicData(m_authenticationPolicy));
        }
        else
        {
            // Account does not have this slot configured
            // we deliver only the slot details instead.
            Credential cred;
            cred.slotDetails = slotDetails;
            r[id] = std::make_pair(false, cred);
        }
    }

    return r;
}

bool IdentityManager_DB::AuthController_DB::doesCredentialSlotExistOnAccount(const std::string &accountName, uint32_t slotId)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::UINT32 count;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT COUNT(*) FROM iam.accountCredentials WHERE `f_accountName`=:accountName AND `f_AuthSlotId`=:slotId;",
                                                  {{":accountName", MAKE_VAR(STRING, accountName)}, {":slotId", MAKE_VAR(UINT32, slotId)}}, {&count}))
    {
        return count.getValue() > 0;
    }

    return false;
}

bool IdentityManager_DB::AuthController_DB::removeAccountCredential(const std::string &accountName, uint32_t slotId)
{
    return _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountCredentials WHERE `f_accountName` = :accountName and `f_AuthSlotId` = :slotId",
                                               {{":accountName", MAKE_VAR(STRING, accountName)}, {":slotId", MAKE_VAR(UINT32, slotId)}});
}

bool IdentityManager_DB::AuthController_DB::setCredentialMustChange(const std::string &accountName, uint32_t slotId, bool mustChange)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    return _parent->m_sqlConnector->qExecuteEx("UPDATE iam.accountCredentials SET `mustChange` = :mustChange "
                                               "WHERE `f_accountName` = :accountName AND `f_AuthSlotId` = :slotId;",
                                               {{":accountName", MAKE_VAR(STRING, accountName)},
                                                {":slotId", MAKE_VAR(UINT32, slotId)},
                                                {":mustChange", MAKE_VAR(BOOL, mustChange)}});
}

bool IdentityManager_DB::AuthController_DB::setCredentialLockedStatus(const std::string &accountName, uint32_t slotId, bool isLocked)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    return _parent->m_sqlConnector->qExecuteEx("UPDATE iam.accountCredentials SET `isLocked` = :isLocked "
                                               "WHERE `f_accountName` = :accountName AND `f_AuthSlotId` = :slotId;",
                                               {{":accountName", MAKE_VAR(STRING, accountName)},
                                                {":slotId", MAKE_VAR(UINT32, slotId)},
                                                {":isLocked", MAKE_VAR(BOOL, isLocked)}});

}

bool IdentityManager_DB::AuthController_DB::updateDefaultAuthScheme(const uint32_t &schemeId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Delete any existing default scheme
    _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.defaultAuthScheme;", {});

    // Insert the new default scheme
    return _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.defaultAuthScheme (`f_defaultSchemeId`) VALUES (:schemeId);", {{":schemeId", MAKE_VAR(UINT32, schemeId)}});
}

std::optional<uint32_t> IdentityManager_DB::AuthController_DB::getDefaultAuthScheme()
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    Abstract::UINT32 schemeId;
    if (!_parent->m_sqlConnector->qSelectSingleRow("SELECT f_defaultSchemeId FROM iam.defaultAuthScheme WHERE id = 1;", {}, {&schemeId}))
        return std::nullopt;
    return schemeId.getValue();
}

std::optional<uint32_t> IdentityManager_DB::AuthController_DB::addNewAuthenticationSlot(const AuthenticationSlotDetails &details)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    auto i = _parent->m_sqlConnector->qExecute("INSERT INTO iam.authenticationSlots (`description`,`function`,`defaultExpirationSeconds`,`strengthJSONValidator`,`totp2FAStepsToleranceWindow`) "
                                               "VALUES(:description,:function,:defaultExpirationSeconds,:strengthJSONValidator,:totp2FAStepsToleranceWindow);",
                                               {{":description", MAKE_VAR(STRING, details.description)},
                                                {":function", MAKE_VAR(UINT32, details.passwordFunction)},
                                                {":defaultExpirationSeconds", MAKE_VAR(UINT32, details.defaultExpirationSeconds)},
                                                {":totp2FAStepsToleranceWindow", MAKE_VAR(UINT32, details.totp2FAStepsToleranceWindow)},
                                                {":strengthJSONValidator", MAKE_VAR(STRING, details.strengthJSONValidator)}});
    if (!i || !i->isSuccessful())
        return std::nullopt;

    return i->getLastInsertRowID();
}

bool IdentityManager_DB::AuthController_DB::removeAuthenticationSlot(const uint32_t &slotId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.authenticationSlots WHERE `slotId`=:slotId;", {{":slotId", MAKE_VAR(UINT32, slotId)}});
}

bool IdentityManager_DB::AuthController_DB::updateAuthenticationSlotDetails(const uint32_t &slotId, const AuthenticationSlotDetails &details)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Update...
    return _parent->m_sqlConnector->qExecuteEx("UPDATE iam.authenticationSlots SET "
                                               "`description` = :description, "
                                               "`defaultExpirationSeconds` = :defaultExpirationSeconds, "
                                               "`totp2FAStepsToleranceWindow` = :totp2FAStepsToleranceWindow, "
                                               "`strengthJSONValidator` = :strengthJSONValidator "
                                               "WHERE `slotId` = :slotId;",
                                               {{":slotId", MAKE_VAR(UINT32, slotId)},
                                                {":description", MAKE_VAR(STRING, details.description)},
                                                {":defaultExpirationSeconds", MAKE_VAR(UINT32, details.defaultExpirationSeconds)},
                                                {":totp2FAStepsToleranceWindow", MAKE_VAR(UINT32, details.totp2FAStepsToleranceWindow)},
                                                {":strengthJSONValidator", MAKE_VAR(STRING, details.strengthJSONValidator)}});
}

std::map<uint32_t, AuthenticationSlotDetails> IdentityManager_DB::AuthController_DB::listAllAuthenticationSlots()
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::map<uint32_t, AuthenticationSlotDetails> ret;

    // Temporal Variables to store the results
    Abstract::UINT32 uSlotId;
    Abstract::STRING sDescription;
    Abstract::UINT32 uFunction;
    Abstract::UINT32 uDefaultExpirationSeconds;
    Abstract::STRING sStrengthJSONValidator;
    Abstract::UINT32 uTotp2FAStepsToleranceWindow;

    auto i = _parent->m_sqlConnector->qSelect("SELECT `slotId`, `description`, `function`, `defaultExpirationSeconds`, `strengthJSONValidator`,`totp2FAStepsToleranceWindow` "
                                              "FROM iam.authenticationSlots;",
                                              {}, {&uSlotId, &sDescription, &uFunction, &uDefaultExpirationSeconds, &sStrengthJSONValidator, &uTotp2FAStepsToleranceWindow});

    // Iterate:
    while (i && i->isSuccessful() && i->step())
    {
        // Build AuthenticationSlotDetails and insert it to the maps
        ret.insert({uSlotId.getValue(), AuthenticationSlotDetails(sDescription.getValue(), (HashFunction) uFunction.getValue(), sStrengthJSONValidator.getValue(), uDefaultExpirationSeconds.getValue(),
                                                                  uTotp2FAStepsToleranceWindow.getValue())});
    }

    return ret;
}

std::optional<uint32_t> IdentityManager_DB::AuthController_DB::addAuthenticationScheme(const std::string &description)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    auto i = _parent->m_sqlConnector->qExecute("INSERT INTO iam.authenticationSchemes (`description`) VALUES(:description);", {{":description", MAKE_VAR(STRING, description)}});

    if (!i || !i->isSuccessful())
        return std::nullopt;

    return i->getLastInsertRowID();
}

bool IdentityManager_DB::AuthController_DB::updateAuthenticationScheme(const uint32_t &schemeId, const std::string &description)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Update...
    return _parent->m_sqlConnector->qExecuteEx("UPDATE iam.authenticationSchemes SET "
                                               "`description` = :description "
                                               "WHERE `schemeId` = :schemeId;",
                                               {{":schemeId", MAKE_VAR(UINT32, schemeId)}, {":description", MAKE_VAR(STRING, description)}});
}

bool IdentityManager_DB::AuthController_DB::removeAuthenticationScheme(const uint32_t &schemeId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.authenticationSchemes WHERE `schemeId`=:schemeId;", {{":schemeId", MAKE_VAR(UINT32, schemeId)}});
}

std::map<uint32_t, std::string> IdentityManager_DB::AuthController_DB::listAuthenticationSchemes()
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::map<uint32_t, std::string> ret;

    // Temporal Variables to store the results
    Abstract::UINT32 uSlotId;
    Abstract::STRING sDescription;

    auto i = _parent->m_sqlConnector->qSelect("SELECT `schemeId`, `description` FROM iam.authenticationSchemes;", {}, {&uSlotId, &sDescription});

    // Iterate:
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert({uSlotId.getValue(), sDescription.getValue()});
    }

    return ret;
}

std::vector<AuthenticationSchemeUsedSlot> IdentityManager_DB::AuthController_DB::listAuthenticationSlotsUsedByScheme(const uint32_t &schemeId)
{
    std::vector<AuthenticationSchemeUsedSlot> slotsList;
    auto allAuthSlots = listAllAuthenticationSlots();

    // Acquire a read lock for thread-safe read operation
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::UINT32 uSlotId;
    Abstract::UINT32 uOrderPriority;
    Abstract::BOOL uOptional;

    // Prepare the SQL SELECT statement to fetch slot details by schemeId
    std::string sql = "SELECT `f_slotId`, `orderPriority`, `optional` "
                      "FROM `iam`.`authenticationSchemeUsedSlots` "
                      "WHERE `f_schemeId` = :schemeId "
                      "ORDER BY `orderPriority` ASC;"; // Assuming you want to order by priority

    // Execute the query with direct parameter passing
    auto queryInstance = _parent->m_sqlConnector->qSelect(sql, {{":schemeId", MAKE_VAR(UINT32, schemeId)}}, {&uSlotId, &uOrderPriority, &uOptional});

    // Assuming queryInstance->query provides a way to iterate over results and bind columns to variables

    while (queryInstance && queryInstance->isSuccessful() && queryInstance->step())
    {
        uint32_t slotId = uSlotId.getValue(), orderPriority = uOrderPriority.getValue();
        bool optional = uOptional.getValue();

        // Add the fetched slot details to the list
        if (allAuthSlots.find(slotId) != allAuthSlots.end())
            slotsList.push_back(AuthenticationSchemeUsedSlot{slotId, orderPriority, optional, allAuthSlots[slotId]});
    }

    return slotsList;
}

bool IdentityManager_DB::AuthController_DB::updateAuthenticationSlotUsedByScheme(const uint32_t &schemeId, const std::list<AuthenticationSchemeUsedSlot> &slotsUsedByScheme)
{
    // Acquire a write lock for thread-safe database modification
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Remove existing slots for the scheme
    std::string deleteSql = "DELETE FROM `iam`.`authenticationSchemeUsedSlots` WHERE `f_schemeId` = :schemeId;";
    if (!_parent->m_sqlConnector->qExecuteEx(deleteSql, {{":schemeId", MAKE_VAR(UINT32, schemeId)}}))
    {
        return false; // If deletion fails, return false
    }

    // Repopulate the table with new slots
    for (const auto &slot : slotsUsedByScheme)
    {
        std::string insertSql = "INSERT INTO `iam`.`authenticationSchemeUsedSlots` (`f_schemeId`, `f_slotId`, `orderPriority`, `optional`) VALUES (:schemeId, "
                                ":slotId, :orderPriority, :optional);";
        if (!_parent->m_sqlConnector->qExecuteEx(insertSql, {{":schemeId", MAKE_VAR(UINT32, schemeId)},
                                                             {":slotId", MAKE_VAR(UINT32, slot.slotId)},
                                                             {":orderPriority", MAKE_VAR(UINT32, slot.orderPriority)},
                                                             {":optional", MAKE_VAR(BOOL, slot.optional)}}))
        {
            // If any insert fails, there's limited context here to handle rollback or partial success scenarios
            return false;
        }
    }

    return true; // Return true if deletion and all insert operations succeed
}

void IdentityManager_DB::AuthController_DB::resetBadAttemptsOnAccountCredential(const std::string &accountName, const uint32_t &slotId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    _parent->m_sqlConnector->qExecuteEx("UPDATE iam.accountCredentials SET `badAttempts`='0' WHERE `f_accountName`=:accountName and `f_AuthSlotId`=:slotId;",
                                        {{":accountName", MAKE_VAR(STRING, accountName)}, {":slotId", MAKE_VAR(UINT32, slotId)}});
}

void IdentityManager_DB::AuthController_DB::incrementBadAttemptsOnAccountCredential(const std::string &accountName, const uint32_t &slotId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    _parent->m_sqlConnector->qExecuteEx("UPDATE iam.accountCredentials SET `badAttempts`=`badAttempts`+1  WHERE `f_accountName`=:accountName and `f_AuthSlotId`=:slotId;",
                                        {{":accountName", MAKE_VAR(STRING, accountName)}, {":slotId", MAKE_VAR(UINT32, slotId)}});
}

std::set<ApplicationScope> IdentityManager_DB::AuthController_DB::getAccountDirectApplicationScopes(const std::string &accountName, bool lock)
{
    std::set<ApplicationScope> ret;
    if (lock)
        _parent->m_mutex.lockShared();

    Abstract::STRING appName, scopeId;
    auto i = _parent->m_sqlConnector->qSelect("SELECT `f_appName`,`f_scopeId` FROM iam.applicationScopeAccounts WHERE `f_accountName`=:accountName;", {{":accountName", MAKE_VAR(STRING, accountName)}},
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
    return _parent->m_sqlConnector->qExecuteEx("UPDATE logs.applicationAuthLog "
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
    return _parent->m_sqlConnector->qExecuteEx("UPDATE logs.applicationAuthLog "
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
    _parent->m_sqlConnector->qExecuteEx("INSERT OR REPLACE INTO logs.accountsLastAccessToApplication (`f_accountName`, `f_appName`, `lastLogin`) "
                                        "VALUES (:accountName, :appName, CURRENT_TIMESTAMP);",
                                        {{":accountName", MAKE_VAR(STRING, accountName)}, {":appName", MAKE_VAR(STRING, appName)}});
    // Insert into the login history log
    _parent->m_sqlConnector->qExecuteEx("INSERT INTO logs.applicationAuthLog(`f_accountName`, `f_schemeId`, `f_appName`, `loginDateTime`, `loginIP`, `loginTLSCN`, `loginUserAgent`, `loginExtraData`, "
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

void IdentityManager_DB::AuthController_DB::insertAccountAuthCredentialSlotLog(const std::string &accountName, uint32_t slotId, const ClientDetails &clientDetails, int logStatus)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    _parent->m_sqlConnector->qExecuteEx(
        R"(INSERT INTO logs.authSlotLog (`f_accountName`, `f_slotId`, `logIP`, `logTLSCN`, `logUserAgent`, `logExtraData`, `logStatus`)
           VALUES (:accountName, :slotId,  :logIP, :logTLSCN, :logUserAgent, :logExtraData, :logStatus);)",
        {{":accountName", MAKE_VAR(STRING, accountName)},
         {":slotId", MAKE_VAR(UINT32, slotId)},
         {":logIP", MAKE_VAR(STRING, clientDetails.ipAddress)},
         {":logTLSCN", MAKE_VAR(STRING, clientDetails.tlsCommonName)},
         {":logUserAgent", MAKE_VAR(STRING, clientDetails.userAgent)},
         {":logExtraData", MAKE_VAR(STRING, clientDetails.extraData)},
         {":logStatus", MAKE_VAR(INT32, logStatus)}});
}

void IdentityManager_DB::AuthController_DB::markExpiredAuthLogSessions()
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    time_t now = time(nullptr);

    // Mark entries where refreshToken has expired (covers both access and refresh)
    _parent->m_sqlConnector->qExecuteEx(
        R"(UPDATE logs.applicationAuthLog
           SET logoutReason = 2, logoutDateTime = CURRENT_TIMESTAMP
           WHERE refreshTokenExpiration < CURRENT_TIMESTAMP
           AND logoutReason IS NULL)",
        {{":now", MAKE_VAR(DATETIME, now)}});
}
