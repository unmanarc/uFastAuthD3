#include "identitymanager_db.h"

#include <Mantids30/Threads/lock_shared.h>
#include <limits>

#include <Mantids30/Memory/a_bool.h>
#include <Mantids30/Memory/a_datetime.h>
#include <Mantids30/Memory/a_int32.h>
#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_uint32.h>
#include <Mantids30/Memory/a_uint64.h>
#include <Mantids30/Memory/a_var.h>
#include <optional>

using namespace Mantids30::Memory;
using namespace Mantids30::Database;
using namespace Mantids30;

Credential IdentityManager_DB::AuthController_DB::retrieveCredential(const std::string &accountName, const uint32_t &slotId, bool *accountFound, bool *authSlotFound)
{
    Credential ret;
    *authSlotFound = false;
    *accountFound = false;

    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::UINT32 badAttempts;
    Abstract::BOOL forcedExpiration;
    Abstract::DATETIME expiration;
    Abstract::STRING salt, hash;

    *accountFound = _parent->accounts->doesAccountExist(accountName);

    if (!*accountFound)
        return ret;

    auto authSlots = listAuthenticationSlots();

    if (authSlots.find(slotId) != authSlots.end())
    {
        ret.slotDetails = authSlots[slotId];
    }
    else
    {
        // Bad...
        return ret;
    }

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect(R"(SELECT `forcedExpiration`,`expiration`,`badAttempts`,`salt`,`hash`
                                                                        FROM iam.accountCredentials
                                                                        WHERE `f_accountName`=:accountName AND `f_AuthSlotId`=:slotId LIMIT 1;
                                                                        )",
                                                                     {{":accountName", MAKE_VAR(STRING, accountName)}, {":slotId", MAKE_VAR(UINT32, slotId)}},
                                                                     {&forcedExpiration, &expiration, &badAttempts, &salt, &hash});

    if (i.getResultsOK() && i.query->step())
    {
        *authSlotFound = true;
        ret.forceExpiration = forcedExpiration.getValue();
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

    SQLConnector::QueryInstance i
        = _parent->m_sqlConnector->qSelect("SELECT `f_roleName` FROM iam.applicationRolesScopes WHERE `f_scopeId`=:scopeId AND `f_appName`=:appName AND `f_roleName`=:roleName;",
                                           {{":scopeId", MAKE_VAR(STRING, scope.id)}, {":appName", MAKE_VAR(STRING, scope.appName)}, {":roleName", MAKE_VAR(STRING, roleName)}},
                                           {});
    ret = (i.getResultsOK()) && i.query->step();

    if (lock)
        _parent->m_mutex.unlockShared();
    return ret;
}

std::set<ApplicationScope> IdentityManager_DB::AuthController_DB::getRoleApplicationScopes(const std::string &appName,const std::string &roleName, bool lock)
{
    std::set<ApplicationScope> ret;

    if (lock)
        _parent->m_mutex.lockShared();

    Abstract::STRING sScopeName,sDescription;
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT ars.`f_scopeId`,ascope.description FROM iam.applicationRolesScopes ars LEFT JOIN iam.applicationScopes ascope ON (ars.`f_scopeId` = ascope.scopeId AND ars.`f_appName` = ascope.f_appName) WHERE ars.`f_roleName`=:roleName AND ars.`f_appName`=:appName;",
                                                                     {
                                                                      {":roleName", MAKE_VAR(STRING, roleName)},
                                                                      {":appName", MAKE_VAR(STRING, appName)}
                                                                     }, {&sScopeName,&sDescription});
    while (i.getResultsOK() && i.query->step())
    {
        ret.insert({appName, sScopeName.getValue(),sDescription.getValue()});
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
    SQLConnector::QueryInstance i
        = _parent->m_sqlConnector->qSelect("SELECT `f_roleName` FROM iam.applicationRolesScopes WHERE `f_scopeId`=:scopeId AND `f_appName`=:appName;",
                                           {{":appName", MAKE_VAR(STRING, applicationScope.appName)}, {":scopeId", MAKE_VAR(STRING, applicationScope.id)}}, {&roleName});
    while (i.getResultsOK() && i.query->step())
    {
        ret.insert(roleName.getValue());
    }

    if (lock)
        _parent->m_mutex.unlockShared();
    return ret;
}


bool IdentityManager_DB::AuthController_DB::changeCredential(const std::string &accountName, Credential passwordData, uint32_t slotId)
{
    auto authSlots = listAuthenticationSlots();

    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (authSlots.find(slotId) == authSlots.end())
    {
        // Bad, slot id not found...
        return false;
    }

    if (!authSlots[slotId].isCompatible(passwordData.slotDetails))
    {
        // Bad slotId function...
        return false;
    }

    if (passwordData.expirationTimestamp == 1)
    {
        passwordData.expirationTimestamp = time(nullptr) + authSlots[slotId].defaultExpirationSeconds;
    }

    // Destroy (if exist).
    _parent->m_sqlConnector->execute("DELETE FROM iam.accountCredentials WHERE `f_accountName`=:accountName and `f_AuthSlotId`=:slotId",
                                     {{":accountName", MAKE_VAR(STRING, accountName)}, {":slotId", MAKE_VAR(UINT32, slotId)}});

    return _parent->m_sqlConnector->execute(R"( INSERT INTO iam.accountCredentials (`f_AuthSlotId`,`f_accountName`,`hash`,`expiration`,`salt`,`forcedExpiration`,`usedstrengthJSONValidator`)
                                                VALUES (:slotId,:account,:hash,:expiration,:salt,:forcedExpiration,:usedValidator);)",
                                             {{":slotId", MAKE_VAR(UINT32, slotId)},
                                             {":account", MAKE_VAR(STRING, accountName)},
                                             {":hash", MAKE_VAR(STRING, passwordData.hash)},
                                             {":expiration", MAKE_VAR(DATETIME, passwordData.expirationTimestamp)},
                                             {":salt", MAKE_VAR(STRING, Mantids30::Helpers::Encoders::toHex(passwordData.ssalt, 4))},
                                             {":forcedExpiration", MAKE_VAR(BOOL, passwordData.forceExpiration)},
                                             {":usedValidator", MAKE_VAR(STRING, authSlots[slotId].strengthJSONValidator)}});

    //                                              {":passwordFunction",MAKE_VAR(UINT32,passwordData.passwordFunction)},
    //                                               {":totp2FAStepsToleranceWindow",MAKE_VAR(UINT32,passwordData.totp2FAStepsToleranceWindow)}
}

std::string IdentityManager_DB::AuthController_DB::getAccountConfirmationToken(const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING token;
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT confirmationToken FROM iam.accountsActivationToken WHERE `f_accountName`=:accountName LIMIT 1;",
                                                                     {{":accountName", MAKE_VAR(STRING, accountName)}}, {&token});
    if (i.getResultsOK() && i.query->step())
    {
        return token.getValue();
    }
    return "";
}

void IdentityManager_DB::AuthController_DB::updateAccountLastAccess(const std::string &accountName, const uint32_t &slotId, const ClientDetails &clientDetails)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    bool notUpdatedOk = true;

    // Attempt to update first
    {
        auto updateResult = _parent->m_sqlConnector->qExecute("UPDATE logs.accountsLastAccess SET `lastLogin`=CURRENT_TIMESTAMP WHERE `f_accountName`=:accountName;",
                                                              {{":accountName", MAKE_VAR(STRING, accountName)}});
        notUpdatedOk = !updateResult.getResultsOK() || updateResult.query->getAffectedRecords() == 0;
    }

    // If no records were updated, then insert a new record
    if (notUpdatedOk)
    {
        _parent->m_sqlConnector->execute("INSERT INTO logs.accountsLastAccess(`f_accountName`, `lastLogin`) VALUES (:accountName, CURRENT_TIMESTAMP);",
                                         {{":accountName", MAKE_VAR(STRING, accountName)}});
    }

    // Insert into the login history log
    _parent->m_sqlConnector->execute("INSERT INTO logs.accountAuthLog(`f_accountName`, `f_AuthSlotId`, `loginDateTime`, `loginIP`, `loginTLSCN`, `loginUserAgent`, `loginExtraData`) "
                                     "VALUES (:accountName, :slotId, :date, :loginIP, :loginTLSCN, :loginUserAgent, :loginExtraData);",
                                     {{":accountName", MAKE_VAR(STRING, accountName)},
                                      {":slotId", MAKE_VAR(UINT32, slotId)},
                                      {":date", MAKE_VAR(DATETIME, time(nullptr))},
                                      {":loginIP", MAKE_VAR(STRING, clientDetails.ipAddress)},
                                      {":loginTLSCN", MAKE_VAR(STRING, clientDetails.tlsCommonName)},
                                      {":loginUserAgent", MAKE_VAR(STRING, clientDetails.userAgent)},
                                      {":loginExtraData", MAKE_VAR(STRING, clientDetails.extraData)}});
}

time_t IdentityManager_DB::AuthController_DB::getAccountLastAccess(const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    {
        Abstract::DATETIME lastLogin;
        SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `lastLogin` FROM logs.accountsLastAccess WHERE `f_accountName`=:accountName LIMIT 1;",
                                                                         {{":accountName", MAKE_VAR(STRING, accountName)}}, {&lastLogin});

        if (i.getResultsOK() && i.query->step())
        {
            return lastLogin.getValue(); // Asegúrate de convertir a `time_t` si es necesario
        }
    }

    // no account? time_t max value...
    return std::numeric_limits<time_t>::max();
}

std::set<uint32_t> IdentityManager_DB::AuthController_DB::listUsedAuthenticationSlotsOnAccount(const std::string &accountName)
{
    std::set<uint32_t> r;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::UINT32 slotId;
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `f_AuthSlotId` FROM iam.accountCredentials WHERE `f_accountName`=:f_accountName;",
                                                                     {{":f_accountName", MAKE_VAR(STRING, accountName)}}, {&slotId});

    while (i.getResultsOK() && i.query->step())
    {
        r.insert(slotId.getValue());
    }

    return r;
}

bool IdentityManager_DB::AuthController_DB::updateDefaultAuthScheme(const uint32_t &schemeId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Delete any existing default scheme
    _parent->m_sqlConnector->execute("DELETE FROM iam.defaultAuthScheme;", {});

    // Insert the new default scheme
    return _parent->m_sqlConnector->execute(
        "INSERT INTO iam.defaultAuthScheme (`f_defaultSchemeId`) VALUES (:schemeId);",
        {{":schemeId", MAKE_VAR(UINT32, schemeId)}}
        );
}

std::optional<uint32_t> IdentityManager_DB::AuthController_DB::getDefaultAuthScheme()
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::UINT32 schemeId;
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect(
        "SELECT f_defaultSchemeId FROM iam.defaultAuthScheme WHERE id = 1;",
        {},
        {&schemeId}
        );

    if (!i.getResultsOK() || !i.query->step())
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
    if (!i.getResultsOK())
        return std::nullopt;

    return i.query->getLastInsertRowID();
}

bool IdentityManager_DB::AuthController_DB::removeAuthenticationSlot(const uint32_t &slotId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("DELETE FROM iam.authenticationSlots WHERE `slotId`=:slotId;", {{":slotId", MAKE_VAR(UINT32, slotId)}});
}

bool IdentityManager_DB::AuthController_DB::updateAuthenticationSlotDetails(const uint32_t &slotId, const AuthenticationSlotDetails &details)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Update...
    return _parent->m_sqlConnector->execute("UPDATE iam.authenticationSlots SET "
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

std::map<uint32_t, AuthenticationSlotDetails> IdentityManager_DB::AuthController_DB::listAuthenticationSlots()
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

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `slotId`, `description`, `function`, `defaultExpirationSeconds`, `strengthJSONValidator`,`totp2FAStepsToleranceWindow` "
                                                                     "FROM iam.authenticationSlots;",
                                                                     {}, {&uSlotId, &sDescription, &uFunction, &uDefaultExpirationSeconds, &sStrengthJSONValidator, &uTotp2FAStepsToleranceWindow});

    // Iterate:
    while (i.getResultsOK() && i.query->step())
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

    if (!i.getResultsOK())
        return std::nullopt;

    return i.query->getLastInsertRowID();
}

bool IdentityManager_DB::AuthController_DB::updateAuthenticationScheme(const uint32_t &schemeId, const std::string &description)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Update...
    return _parent->m_sqlConnector->execute("UPDATE iam.authenticationSchemes SET "
                                            "`description` = :description "
                                            "WHERE `schemeId` = :schemeId;",
                                            {{":schemeId", MAKE_VAR(UINT32, schemeId)}, {":description", MAKE_VAR(STRING, description)}});
}

bool IdentityManager_DB::AuthController_DB::removeAuthenticationScheme(const uint32_t &schemeId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("DELETE FROM iam.authenticationSchemes WHERE `schemeId`=:schemeId;", {{":schemeId", MAKE_VAR(UINT32, schemeId)}});
}

std::map<uint32_t, std::string> IdentityManager_DB::AuthController_DB::listAuthenticationSchemes()
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::map<uint32_t, std::string> ret;

    // Temporal Variables to store the results
    Abstract::UINT32 uSlotId;
    Abstract::STRING sDescription;

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `schemeId`, `description` FROM iam.authenticationSchemes;", {}, {&uSlotId, &sDescription});

    // Iterate:
    while (i.getResultsOK() && i.query->step())
    {
        ret.insert({uSlotId.getValue(), sDescription.getValue()});
    }

    return ret;
}

std::vector<AuthenticationSchemeUsedSlot> IdentityManager_DB::AuthController_DB::listAuthenticationSlotsUsedByScheme(const uint32_t &schemeId)
{
    std::vector<AuthenticationSchemeUsedSlot> slotsList;
    auto allAuthSlots = listAuthenticationSlots();

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
    SQLConnector::QueryInstance queryInstance = _parent->m_sqlConnector->qSelect(sql, {{":schemeId", MAKE_VAR(UINT32, schemeId)}}, {&uSlotId, &uOrderPriority, &uOptional});

    // Assuming queryInstance->query provides a way to iterate over results and bind columns to variables

    while (queryInstance.getResultsOK() && queryInstance.query->step())
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
    if (!_parent->m_sqlConnector->execute(deleteSql, {{":schemeId", MAKE_VAR(UINT32, schemeId)}}))
    {
        return false; // If deletion fails, return false
    }

    // Repopulate the table with new slots
    for (const auto &slot : slotsUsedByScheme)
    {
        std::string insertSql = "INSERT INTO `iam`.`authenticationSchemeUsedSlots` (`f_schemeId`, `f_slotId`, `orderPriority`, `optional`) VALUES (:schemeId, "
                                ":slotId, :orderPriority, :optional);";
        if (!_parent->m_sqlConnector->execute(insertSql, {{":schemeId", MAKE_VAR(UINT32, schemeId)},
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

void IdentityManager_DB::AuthController_DB::resetBadAttemptsOnCredential(const std::string &accountName, const uint32_t &slotId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    _parent->m_sqlConnector->execute("UPDATE iam.accountCredentials SET `badAttempts`='0' WHERE `f_accountName`=:accountName and `f_AuthSlotId`=:slotId;",
                                     {{":accountName", MAKE_VAR(STRING, accountName)}, {":slotId", MAKE_VAR(UINT32, slotId)}});
}

void IdentityManager_DB::AuthController_DB::incrementBadAttemptsOnCredential(const std::string &accountName, const uint32_t &slotId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    _parent->m_sqlConnector->execute("UPDATE iam.accountCredentials SET `badAttempts`=`badAttempts`+1  WHERE `f_accountName`=:accountName and `f_AuthSlotId`=:slotId;",
                                     {{":accountName", MAKE_VAR(STRING, accountName)}, {":slotId", MAKE_VAR(UINT32, slotId)}});
}

std::set<ApplicationScope> IdentityManager_DB::AuthController_DB::getAccountDirectApplicationScopes(const std::string &accountName, bool lock)
{
    std::set<ApplicationScope> ret;
    if (lock)
        _parent->m_mutex.lockShared();

    Abstract::STRING appName, scopeId;
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `f_appName`,`f_scopeId` FROM iam.applicationScopeAccounts WHERE `f_accountName`=:accountName;",
                                                                     {{":accountName", MAKE_VAR(STRING, accountName)}}, {&appName, &scopeId});
    while (i.getResultsOK() && i.query->step())
    {
        ret.insert({appName.getValue(), scopeId.getValue()});
    }

    if (lock)
        _parent->m_mutex.unlockShared();
    return ret;
}
