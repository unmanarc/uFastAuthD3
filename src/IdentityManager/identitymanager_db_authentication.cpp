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

using namespace Mantids30::Memory;
using namespace Mantids30::Database;
using namespace Mantids30;


std::string IdentityManager_DB::AuthController_DB::getAccountConfirmationToken(const std::string &accountUUID)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::STRING token;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT confirmationToken FROM iam.accountsActivationToken WHERE `f_accountUUID`=:accountUUID LIMIT 1;",
                                                  {{":accountUUID", MAKE_VAR(STRING, accountUUID)}}, {&token}))
    {
        return token.getValue();
    }
    return "";
}
IdentityManager::LastAccountAccessResult IdentityManager_DB::AuthController_DB::getAccountLastAccess(const std::string &accountUUID)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    IdentityManager::LastAccountAccessResult result;
    Abstract::DATETIME lastLogin;
    Abstract::STRING appName;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `lastLogin`, `f_appName` FROM logs.applicationAccess_accountLastLogin "
                                                  "WHERE `f_accountUUID` = :accountUUID;",
                                                  {{":accountUUID", MAKE_VAR(STRING, accountUUID)}}, {&lastLogin, &appName}))
    {
        result.lastAccess = {lastLogin.getValue(), appName.getValue()};
    }

    Abstract::DATETIME validUntil;

    // Consulta 2: Obtener extensión de inactividad si existe
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `validUntil` FROM iam.inactivityExtensions "
                                                  "WHERE `accountUUID` = :accountUUID;",
                                                  {{":accountUUID", MAKE_VAR(STRING, accountUUID)}}, {&validUntil}))
    {
        result.inactivityExtensionUntil = validUntil.getValue();
    }

    return result;
}

// ------------------------------------------------------------------------
// Application Auth Log - Logout and Token tracking
// ------------------------------------------------------------------------
bool IdentityManager_DB::AuthController_DB::updateApplicationAuthLogAccessTokenId(const std::string &accountUUID, const std::string &appName, const std::string &refresherTokenId,
                                                                                  const std::string &accessTokenId, const time_t &accessTokenExpiration)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);

    // Update the log entry identified by the refresher token id
    return _parent->m_sqlConnector->qExecuteEx("UPDATE logs.applicationAccess_accountSessions "
                                               "SET `accessTokenId` = :accessTokenId, "
                                               "`accessTokenExpiration` = :accessTokenExpiration "
                                               "WHERE `f_accountUUID` = :accountUUID "
                                               "  AND `f_appName` = :appName "
                                               "  AND `refresherTokenId` = :refresherTokenId "
                                               "ORDER BY `loginDateTime` DESC "
                                               "LIMIT 1;",
                                               {{":accessTokenId", MAKE_VAR(STRING, accessTokenId)},
                                                {":accessTokenExpiration", MAKE_VAR(DATETIME, accessTokenExpiration)},
                                                {":accountUUID", MAKE_VAR(STRING, accountUUID)},
                                                {":appName", MAKE_VAR(STRING, appName)},
                                                {":refresherTokenId", MAKE_VAR(STRING, refresherTokenId)}});
}

bool IdentityManager_DB::AuthController_DB::logoutApplicationAuthLog(const std::string &accountUUID, const std::string &appName, const std::string &refresherTokenId, LogoutReason reason)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("UPDATE logs.applicationAccess_accountSessions "
                                               "SET `logoutDateTime` = CURRENT_TIMESTAMP, "
                                               "    `logoutReason` = :reason "
                                               "WHERE `f_accountUUID` = :accountUUID "
                                               "  AND `f_appName` = :appName "
                                               "  AND `refresherTokenId` = :refresherTokenId "
                                               "  AND `logoutDateTime` IS NULL "
                                               "ORDER BY `loginDateTime` DESC "
                                               "LIMIT 1;",
                                               {{":accountUUID", MAKE_VAR(STRING, accountUUID)},
                                                {":appName", MAKE_VAR(STRING, appName)},
                                                {":refresherTokenId", MAKE_VAR(STRING, refresherTokenId)},
                                                {":reason", MAKE_VAR(INT32, static_cast<int>(reason))}});
}

void IdentityManager_DB::AuthController_DB::insertApplicationAccountAccessAuthLog(const std::string &accountUUID, const std::string &appName, const uint32_t &schemeId,
                                                                                  const ClientDetails &clientDetails, const std::string &refresherTokenId, const std::string &accessTokenId,
                                                                                  const time_t &accessTokenExpiration, const time_t &refreshTokenExpiration)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);

    // Use INSERT OR REPLACE to handle upsert logic for accountsLastAccessToApplication
    _parent->m_sqlConnector->qExecuteEx("INSERT OR REPLACE INTO logs.applicationAccess_accountLastLogin (`f_accountUUID`, `f_appName`, `lastLogin`) "
                                        "VALUES (:accountUUID, :appName, CURRENT_TIMESTAMP);",
                                        {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":appName", MAKE_VAR(STRING, appName)}});
    // Insert into the login history log
    _parent->m_sqlConnector
        ->qExecuteEx("INSERT INTO logs.applicationAccess_accountSessions(`f_accountUUID`, `f_schemeId`, `f_appName`, `loginDateTime`, `loginIP`, `loginTLSCN`, `loginUserAgent`, `loginExtraData`, "
                     "`refresherTokenId`, `accessTokenId`, `accessTokenExpiration`, `refreshTokenExpiration`) "
                     "VALUES (:accountUUID, :schemeId, :appName, :loginDateTime, :loginIP, :loginTLSCN, :loginUserAgent, :loginExtraData, :refresherTokenId, :accessTokenId, "
                     ":accessTokenExpiration, :refreshTokenExpiration);",
                     {{":accountUUID", MAKE_VAR(STRING, accountUUID)},
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
