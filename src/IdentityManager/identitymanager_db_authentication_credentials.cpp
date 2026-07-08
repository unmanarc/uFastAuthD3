#include "identitymanager_db.h"

#include <Mantids30/Helpers/datatables.h>


#include <Mantids30/Memory/a_bool.h>
#include <Mantids30/Memory/a_datetime.h>
#include <Mantids30/Memory/a_int32.h>
#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_uint32.h>
#include <Mantids30/Memory/a_uint64.h>
#include <Mantids30/Memory/a_var.h>
#include <memory>
#include <string>
#include <utility>

using namespace Mantids30::Memory;
using namespace Mantids30::Database;
using namespace Mantids30;

bool IdentityManager::AuthController::recoverAccountMasterCredential(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, std::string *sInitPW)
{
    *sInitPW = "";
    std::map<uint32_t, AuthenticationSlotDetails> authSlots;
    std::string newPass;
    Credential credentialData;

    {
        std::shared_lock<std::shared_mutex> lock(m_parent->m_mutex);

        authSlots = m_parent->authController->listAllAuthenticationSlots();
        // not any slot assigned to this scheme
        if (authSlots.empty())
        {
            return false;
        }

        // not a password...
        if (!authSlots.begin()->second.isTextPasswordFunction())
        {
            return false;
        }
        newPass = Mantids30::Helpers::Random::createRandomString(16);
        credentialData = m_parent->authController->createNewCredential(authSlots.begin()->first, newPass, true);
    }

    bool r = m_parent->authController->changeAccountCredential(clientDetails, performedBy, accountUUID, credentialData, authSlots.begin()->first);

    if (r)
    {
        *sInitPW = newPass;
    }

    return r;
}

Credential IdentityManager_DB::AuthController_DB::retrieveAccountCredential(const std::string &accountUUID, const uint32_t &slotId, bool *accountFound, bool *authSlotFound)
{
    Credential ret;
    *authSlotFound = false;
    *accountFound = false;

    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::UINT32 badAttempts;
    Abstract::BOOL mustChange, isLocked;
    Abstract::DATETIME expiration, lastChange;
    Abstract::STRING salt, hash;

    *accountFound = _parent->accounts->doesAccountExist(accountUUID);

    if (!*accountFound)
    {
        return ret;
    }

    std::map<uint32_t, AuthenticationSlotDetails> authSlots = listAllAuthenticationSlots();

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
                                                                        WHERE `f_accountUUID`=:accountUUID AND `f_AuthSlotId`=:slotId LIMIT 1;
                                                                        )",
                                                  {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":slotId", MAKE_VAR(UINT32, slotId)}},
                                                  {&mustChange, &expiration, &badAttempts, &salt, &hash, &lastChange, &isLocked}))
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

Json::Value IdentityManager_DB::AuthController_DB::searchAccountCredentialsActivity(const std::string &accountUUID, const Json::Value &dataTablesFilters)
{
    Json::Value ret;
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    ret["draw"] = dataTablesFilters["draw"];
    uint64_t offset = Helpers::JSON::ASUINT64(dataTablesFilters, "start", 0);
    uint64_t limit = Helpers::JSON::ASUINT64(dataTablesFilters, "length", 0);
    std::string orderByStatement = Helpers::DataTables::getOrderByStatement(dataTablesFilters);
    std::string searchValue = Helpers::JSON::ASSTRING(dataTablesFilters["search"], "value", "");
    std::string whereFilters = "`f_accountUUID` = :ACCOUNTNAME";
    std::string sqlQueryStr = R"(
        SELECT `f_accountUUID`, `f_slotId`, `logDateTime`, `logIP`, `logTLSCN`,
               `logUserAgent`, `logExtraData`, `logStatus`
        FROM logs.authEvents_accountCredentialValidation
    )";

    // Construcción de parámetros
    std::map<std::string, std::shared_ptr<Abstract::Var>> params;
    params[":ACCOUNTNAME"] = MAKE_VAR(STRING, accountUUID);

    if (!searchValue.empty())
    {
        searchValue = "%" + searchValue + "%";
        whereFilters += " AND (`logIP` LIKE :SEARCH OR `logTLSCN` LIKE :SEARCH OR `logUserAgent` LIKE :SEARCH OR `logExtraData` LIKE :SEARCH)";
        params[":SEARCH"] = MAKE_VAR(STRING, searchValue);
        params[":SEARCH_SLOT"] = MAKE_VAR(STRING, searchValue);
    }

    {
        Abstract::STRING f_accountUUID, logDateTime, logIP, logTLSCN, logUserAgent, logExtraData;
        Abstract::INT32 f_slotId, logStatus;

        std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelectWithFilters(sqlQueryStr, whereFilters, params,
                                                                               {&f_accountUUID, &f_slotId, &logDateTime, &logIP, &logTLSCN, &logUserAgent, &logExtraData, &logStatus}, orderByStatement,
                                                                               limit, offset);

        while (i && i->isSuccessful() && i->step())
        {
            Json::Value row;
            row["f_accountUUID"] = f_accountUUID.getValue();
            row["f_slotId"] = f_slotId.getValue();
            row["logDateTime"] = logDateTime.getValue();
            row["logIP"] = logIP.getValue();
            row["logTLSCN"] = logTLSCN.getValue();
            row["logUserAgent"] = logUserAgent.getValue();
            row["logExtraData"] = logExtraData.getValue();
            row["logStatus"] = logStatus.getValue();

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

std::pair<uint32_t, uint32_t> IdentityManager_DB::AuthController_DB::getAccountActiveCredentialsCount(const std::string &accountUUID)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

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
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT COUNT(*) FROM iam.accountCredentials WHERE `f_accountUUID`=:accountUUID;", {{":accountUUID", MAKE_VAR(STRING, accountUUID)}}, {&accountCount}))
    {
        accountSlots = accountCount.getValue();
    }

    return {totalSlots, accountSlots};
}

std::set<uint32_t> IdentityManager_DB::AuthController_DB::listUsedAuthenticationSlotsOnAccount(const std::string &accountUUID)
{
    std::set<uint32_t> r;
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::UINT32 slotId;
    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `f_AuthSlotId` FROM iam.accountCredentials WHERE `f_accountUUID`=:f_accountUUID;",
                                                                {{":f_accountUUID", MAKE_VAR(STRING, accountUUID)}}, {&slotId});

    while (i && i->isSuccessful() && i->step())
    {
        r.insert(slotId.getValue());
    }

    return r;
}

std::map<uint32_t, std::pair<bool, Credential>> IdentityManager_DB::AuthController_DB::listAllAuthCredentialSlotsPublicDataForAccount(const std::string &accountUUID)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);
    std::map<uint32_t, std::pair<bool, Credential>> r;

    // Get all authentication slots and configured slots.
    std::map<uint32_t, AuthenticationSlotDetails> allAuthSlots = listAllAuthenticationSlots();
    std::set<uint32_t> configuredSlots = listUsedAuthenticationSlotsOnAccount(accountUUID);

    // For each authentication slot, create a public Credential entry
    for (const auto &i : allAuthSlots)
    {
        uint32_t id = i.first;
        AuthenticationSlotDetails slotDetails = i.second;

        if (configuredSlots.find(id) != configuredSlots.end())
        {
            // Account has this slot configured - provide public info
            bool accountFound, authSlotFound;
            Credential cred = retrieveAccountCredential(accountUUID, id, &accountFound, &authSlotFound);
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

bool IdentityManager_DB::AuthController_DB::doesCredentialSlotExistOnAccount(const std::string &accountUUID, uint32_t slotId)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::UINT32 count;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT COUNT(*) FROM iam.accountCredentials WHERE `f_accountUUID`=:accountUUID AND `f_AuthSlotId`=:slotId;",
                                                  {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":slotId", MAKE_VAR(UINT32, slotId)}}, {&count}))
    {
        return count.getValue() > 0;
    }

    return false;
}

bool IdentityManager_DB::AuthController_DB::changeAccountCredential(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, Credential passwordData,
                                                                    uint32_t slotId)
{
    std::map<uint32_t, AuthenticationSlotDetails> authSlots = listAllAuthenticationSlots();
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);

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
        {
            passwordData.expirationTimestamp = 0;
        }
        else
        {
            passwordData.expirationTimestamp = time(nullptr) + authSlots[slotId].defaultExpirationSeconds;
        }
    }

    // Única operación SQL
    bool success = _parent->m_sqlConnector->qExecuteEx(R"(
            INSERT OR REPLACE INTO iam.accountCredentials (f_AuthSlotId, f_accountUUID, hash, expiration, salt, mustChange)
            VALUES (:slotId, :account, :hash, :expiration, :salt, :mustChange);
        )",
                                                       {{":slotId", MAKE_VAR(UINT32, slotId)},
                                                        {":account", MAKE_VAR(STRING, accountUUID)},
                                                        {":hash", MAKE_VAR(STRING, passwordData.hash)},
                                                        {":expiration", MAKE_VAR(DATETIME, passwordData.expirationTimestamp)},
                                                        {":salt", MAKE_VAR(STRING, Mantids30::Helpers::Encoders::toHex(passwordData.ssalt, 4))},
                                                        {":mustChange", MAKE_VAR(BOOL, passwordData.mustChange)}

                                                       });

    if (success)
    {
        _parent->logSecurityEventOnAccountCredentials(accountUUID, slotId, SecurityEventAction::UPDATE, "Credential changed for authentication slot", performedBy, clientDetails);
    }

    return success;
}

bool IdentityManager_DB::AuthController_DB::activateAccountCredential(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, uint32_t slotId,
                                                                      const std::string &hash, const std::string &ssalt)
{
    std::map<uint32_t, AuthenticationSlotDetails> authSlots = listAllAuthenticationSlots();
    // Validate slot exists
    if (authSlots.find(slotId) == authSlots.end())
    {
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);

    // Check if credential already exists (already activated)
    Abstract::UINT32 count;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT COUNT(*) FROM iam.accountCredentials WHERE `f_accountUUID`=:accountUUID AND `f_AuthSlotId`=:slotId;",
                                                  {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":slotId", MAKE_VAR(UINT32, slotId)}}, {&count}))
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

    bool success = _parent->m_sqlConnector->qExecuteEx(R"(INSERT INTO iam.accountCredentials
           (`f_AuthSlotId`, `f_accountUUID`, `hash`, `expiration`, `salt`, `mustChange`)
           VALUES (:slotId, :account, :hash, :expiration, :salt, :mustChange);)",
                                                       {{":slotId", MAKE_VAR(UINT32, slotId)},
                                                        {":account", MAKE_VAR(STRING, accountUUID)},
                                                        {":hash", MAKE_VAR(STRING, hash)},
                                                        {":expiration", MAKE_VAR(DATETIME, expiration)},
                                                        {":salt", MAKE_VAR(STRING, ssalt)},
                                                        {":mustChange", MAKE_VAR(BOOL, false)}});

    if (success)
    {
        _parent->logSecurityEventOnAccountCredentials(accountUUID, slotId, SecurityEventAction::CREATE, "New credential activated for authentication slot", performedBy, clientDetails);
    }

    return success;
}

bool IdentityManager_DB::AuthController_DB::removeAccountCredential(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, uint32_t slotId)
{
    bool success = _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountCredentials WHERE `f_accountUUID` = :accountUUID and `f_AuthSlotId` = :slotId",
                                                       {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":slotId", MAKE_VAR(UINT32, slotId)}});

    if (success)
    {
        _parent->logSecurityEventOnAccountCredentials(accountUUID, slotId, SecurityEventAction::DELETE, "Credential removed from authentication slot", performedBy, clientDetails);
    }

    return success;
}

bool IdentityManager_DB::AuthController_DB::setAccountCredentialMustChange(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, uint32_t slotId, bool mustChange)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);

    bool success = _parent->m_sqlConnector->qExecuteEx("UPDATE iam.accountCredentials SET `mustChange` = :mustChange "
                                                       "WHERE `f_accountUUID` = :accountUUID AND `f_AuthSlotId` = :slotId;",
                                                       {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":slotId", MAKE_VAR(UINT32, slotId)}, {":mustChange", MAKE_VAR(BOOL, mustChange)}});

    if (success)
    {
        std::string desc = mustChange ? "Credential marked as must-change on next use for slot" : "Credential must-change flag cleared for slot";
        _parent->logSecurityEventOnAccountCredentials(accountUUID, slotId, mustChange ? SecurityEventAction::FORCE_CHANGE : SecurityEventAction::CANCEL_FORCE_CHANGE, desc, performedBy, clientDetails);
    }

    return success;
}

bool IdentityManager_DB::AuthController_DB::setAccountCredentialLockedStatus(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, uint32_t slotId, bool isLocked)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);

    bool success;
    if (!isLocked) {
        // When unlocking, also reset badAttempts to 0
        success = _parent->m_sqlConnector->qExecuteEx("UPDATE iam.accountCredentials SET `isLocked` = :isLocked, `badAttempts` = 0 "
                                                       "WHERE `f_accountUUID` = :accountUUID AND `f_AuthSlotId` = :slotId;",
                                                       {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":slotId", MAKE_VAR(UINT32, slotId)}, {":isLocked", MAKE_VAR(BOOL, isLocked)}});
    } else {
        success = _parent->m_sqlConnector->qExecuteEx("UPDATE iam.accountCredentials SET `isLocked` = :isLocked "
                                                       "WHERE `f_accountUUID` = :accountUUID AND `f_AuthSlotId` = :slotId;",
                                                       {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":slotId", MAKE_VAR(UINT32, slotId)}, {":isLocked", MAKE_VAR(BOOL, isLocked)}});
    }

    if (success)
    {
        std::string desc = isLocked ? "Credential locked (authentication disabled) on slot" : "Credential unlocked (authentication re-enabled) on slot";
        _parent->logSecurityEventOnAccountCredentials(accountUUID, slotId, isLocked ? SecurityEventAction::LOCK : SecurityEventAction::UNLOCK, desc, performedBy, clientDetails);
    }

    return success;
}

void IdentityManager_DB::AuthController_DB::resetBadAttemptsOnAccountCredential(const std::string &accountUUID, const uint32_t &slotId)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    _parent->m_sqlConnector->qExecuteEx("UPDATE iam.accountCredentials SET `badAttempts`='0' WHERE `f_accountUUID`=:accountUUID and `f_AuthSlotId`=:slotId;",
                                        {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":slotId", MAKE_VAR(UINT32, slotId)}});
}

void IdentityManager_DB::AuthController_DB::incrementBadAttemptsOnAccountCredential(const std::string &accountUUID, const uint32_t &slotId)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    _parent->m_sqlConnector->qExecuteEx("UPDATE iam.accountCredentials SET `badAttempts`=`badAttempts`+1  WHERE `f_accountUUID`=:accountUUID and `f_AuthSlotId`=:slotId;",
                                        {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":slotId", MAKE_VAR(UINT32, slotId)}});
}

void IdentityManager_DB::AuthController_DB::insertAccountAuthCredentialSlotLog(const std::string &accountUUID, uint32_t slotId, const ClientDetails &clientDetails, int logStatus)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);

    _parent->m_sqlConnector->qExecuteEx(
        R"(INSERT INTO logs.authEvents_accountCredentialValidation (`f_accountUUID`, `f_slotId`, `logIP`, `logTLSCN`, `logUserAgent`, `logExtraData`, `logStatus`)
           VALUES (:accountUUID, :slotId,  :logIP, :logTLSCN, :logUserAgent, :logExtraData, :logStatus);)",
        {{":accountUUID", MAKE_VAR(STRING, accountUUID)},
         {":slotId", MAKE_VAR(UINT32, slotId)},
         {":logIP", MAKE_VAR(STRING, clientDetails.ipAddress)},
         {":logTLSCN", MAKE_VAR(STRING, clientDetails.tlsCommonName)},
         {":logUserAgent", MAKE_VAR(STRING, clientDetails.userAgent)},
         {":logExtraData", MAKE_VAR(STRING, clientDetails.extraData)},
         {":logStatus", MAKE_VAR(INT32, logStatus)}});
}
