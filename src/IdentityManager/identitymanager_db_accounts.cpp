#include "IdentityManager/identitymanager.h"
#include "identitymanager_db.h"
#include "globals.h"
#include <Mantids30/Helpers/json.h>

#include <Mantids30/DB/transaction.h>
#include <Mantids30/Helpers/datatables.h>
#include <Mantids30/Helpers/random.h>
#include <Mantids30/Threads/lock_shared.h>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/regex.hpp>
#include <regex>
#include <json/value.h>
#include <optional>

#include <Mantids30/Memory/a_bool.h>
#include <Mantids30/Memory/a_datetime.h>
#include <Mantids30/Memory/a_int32.h>
#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_uint32.h>
#include <Mantids30/Memory/a_uint64.h>
#include <Mantids30/Memory/a_var.h>

using namespace Mantids30;
using namespace Mantids30::Memory;
using namespace Mantids30::Database;

bool IdentityManager_DB::Accounts_DB::extendInactivity(const std::string &accountUUID, const time_t &validUntil)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    Database::Transaction tg(*_parent->m_sqlConnector);

    // Step 1: Delete the existing record if it exists
    // Note: In SQLite, if accountUUID is not unique, this deletes ALL matching rows.
    // Ensure 'accountUUID' is unique or adjust logic if multiple rows per account are possible.
    bool success = _parent->m_sqlConnector->qExecuteEx(R"(DELETE FROM iam.inactivityExtensions WHERE `accountUUID` = :accountUUID;)", {{":accountUUID", MAKE_VAR(STRING, accountUUID)}});

    if (!success)
    {
        // Rollback on failure and return false.
        return tg.finalize(false);
    }

    // Step 2: Insert the new record
    success = _parent->m_sqlConnector->qExecuteEx(
        R"(INSERT INTO iam.inactivityExtensions (`accountUUID`, `validUntil`)
              VALUES (:accountUUID, :validUntil);)",
        {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":validUntil", MAKE_VAR(DATETIME, validUntil)}});

    if (!success)
    {
        // Rollback on failure and return false.
        return tg.finalize(false);
    }

    // Commit the transaction
    if (!_parent->m_sqlConnector->commitTransaction())
    {
        // Rollback on failure and return false.
        return tg.finalize(false);
    }

    // commit the transaction.
    return tg.finalize();
}

CreateAccountResult IdentityManager_DB::Accounts_DB::createAccount(time_t expirationDate, const AccountFlags &accountFlags, const ClientDetails &clientDetails, const std::string &performedBy,
                                                                   const std::map<std::string, ApplicationDef> &appDefs, const std::map<std::string, std::string> &detailFieldsValues)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    Database::Transaction tg(*_parent->m_sqlConnector);

    std::string accountUUID = Helpers::Random::createUUIDv4();

    bool r = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.accounts (`accountUUID`,`isAdmin`,`isEnabled`,`isBlocked`,`expiration`,`isAccountConfirmed`,`creator`) "
                                                 "VALUES(:accountUUID,:admin ,:enabled, :blocked ,:expiration ,:confirmed ,:creator);",
                                                 {{":accountUUID", MAKE_VAR(STRING, accountUUID)},
                                                  {":admin", MAKE_VAR(BOOL, accountFlags.admin)},
                                                  {":enabled", MAKE_VAR(BOOL, accountFlags.enabled)},
                                                  {":blocked", MAKE_VAR(BOOL, accountFlags.blocked)},
                                                  {":expiration", MAKE_VAR(DATETIME, expirationDate)},
                                                  {":confirmed", MAKE_VAR(BOOL, accountFlags.confirmed)},
                                                  {":creator", performedBy.empty() ? MAKE_NULL_VAR /* null */ : MAKE_VAR(STRING, performedBy)}});

    if (r)
    {
        // Now create the activation token...
        r = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.accountsActivationToken (`f_accountUUID`,`confirmationToken`) "
                                                "VALUES(:accountUUID,:confirmationToken);",
                                                {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":confirmationToken", MAKE_VAR(STRING, _parent->authController->genRandomConfirmationToken())}});
    }

    // Insert application associations, roles, scopes, and admin status
    // Use the private _ methods from the DB classes to avoid double-locking
    // (createAccount already holds the lock)
    if (r && !appDefs.empty())
    {
        // Cast base pointers to DB-derived types to access private methods
        Applications_DB *appsDB = static_cast<Applications_DB *>(_parent->applications);
        ApplicationRoles_DB *rolesDB = static_cast<ApplicationRoles_DB *>(_parent->applicationRoles);
        ApplicationScopes_DB *scopesDB = static_cast<ApplicationScopes_DB *>(_parent->applicationScopes);

        for (const auto &appDef : appDefs)
        {
            // Add account to application using the private helper (no locking)
            r = appsDB->_addAccountToApplication(clientDetails, performedBy, appDef.first, accountUUID);
            if (!r)
            {
                break;
            }

            // Set as application admin if requested using the private helper (no locking)
            if (appDef.second.isAppAdmin)
            {
                r = appsDB->_setAccountAsApplicationAdmin(clientDetails, performedBy, appDef.first, accountUUID, true);
                if (!r)
                {
                    break;
                }
            }

            // Insert roles using the private helper (no locking)
            for (const auto &role : appDef.second.roles)
            {
                r = rolesDB->_addAccountToRole(clientDetails, performedBy, appDef.first, role, accountUUID);
                if (!r)
                {
                    break;
                }
            }

            // Insert scopes using the private helper (no locking)
            for (const auto &scopeId : appDef.second.scopes)
            {
                ApplicationScope applicationScope{appDef.first, scopeId};
                r = scopesDB->_addApplicationScopeToAccount(clientDetails, performedBy, applicationScope, accountUUID);
                if (!r)
                {
                    break;
                }
            }
        }
    }

    // Prepare the CreateAccountResult
    CreateAccountResult result;

    if (r)
    {
        _parent->logSecurityEventOnAccounts(accountUUID, SecurityEventAction::CREATE, "New account created", performedBy, clientDetails);
        result.success = true;
        result.accountUUID = accountUUID;

        // Use _updateAccountDetailFieldValues to insert detail field values
        result.detailResult = _updateAccountDetailFieldValues(clientDetails, performedBy, accountUUID, detailFieldsValues, true);

        // If _updateAccountDetailFieldValues failed, mark account creation as failed
        if (result.detailResult.status != UpdateAccountDetailFieldValuesResult::Status::SUCCESS)
        {
            r = false;
            result.success = false;
            result.accountUUID = "";
        }
    }

    if (r)
    {
        return tg.finalize(true) ? result : CreateAccountResult{false, "", {}};
    }
    else
    {
        tg.finalize(false);
        result.success = false;
        result.accountUUID = "";
        return result;
    }
}

bool IdentityManager_DB::Accounts_DB::removeAccount(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (isThereAnotherAdmin(accountUUID))
    {
        bool result = _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accounts WHERE `accountUUID`=:accountUUID;", {{":accountUUID", MAKE_VAR(STRING, accountUUID)}});
        if (result)
        {
            _parent->logSecurityEventOnAccounts(accountUUID, SecurityEventAction::DELETE, "Account removed", performedBy, clientDetails);
        }
        return result;
    }
    return false;
}

bool IdentityManager_DB::Accounts_DB::doesAccountExist(const std::string &accountUUID)
{
    bool ret = false;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    ret = _parent->m_sqlConnector->qSelectSingleRow("SELECT `isEnabled` FROM iam.accounts WHERE `accountUUID`=:accountUUID LIMIT 1;", {{":accountUUID", MAKE_VAR(STRING, accountUUID)}}, {});
    return ret;
}

bool IdentityManager_DB::Accounts_DB::disableAccount(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, bool disabled)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (disabled && !isThereAnotherAdmin(accountUUID))
    {
        return false;
    }

    bool result = _parent->m_sqlConnector->qExecuteEx("UPDATE iam.accounts SET `isEnabled`=:enabled WHERE `accountUUID`=:accountUUID;",
                                                      {{":enabled", MAKE_VAR(BOOL, !disabled)}, {":accountUUID", MAKE_VAR(STRING, accountUUID)}});
    if (result)
    {
        _parent->logSecurityEventOnAccounts(accountUUID,
                                            disabled ? SecurityEventAction::DISABLE : SecurityEventAction::ENABLE,
                                            disabled ? "Account disabled" : "Account enabled",
                                            performedBy,
                                            clientDetails);
    }
    return result;
}

std::string IdentityManager_DB::Accounts_DB::getAccountDisplayName(const std::string &accountUUID)
{
    std::string userDisplayFormat = Globals::pConfig.get<std::string>("UserInfo.DisplayFormat", "{{USERNAME}}");

    // Get account detail field values for template substitution
    std::map<std::string, AccountDetailFieldValue> detailFieldValues = getAccountDetailFieldValues(accountUUID, AccountDetailsToShow::ALL);

    // Build a map of field name -> value for regex replacement
    std::map<std::string, std::string> fieldValuesMap;
    for (const auto &[fieldName, fieldValue] : detailFieldValues)
    {
        if (fieldValue.value.has_value())
        {
            fieldValuesMap[fieldName] = fieldValue.value.value();
        }
        else
        {
            fieldValuesMap[fieldName] = "";
        }
    }

    // Format the display name by replacing {{tagName}} with random placeholders,
    // then resolve placeholders to actual values using boost::replace_all.
    // This prevents field values containing {{...}} from being processed as tags.
    static const std::regex tagRegex(R"(\{\{(\w+)\}\})");
    std::regex_iterator<std::string::const_iterator> iter(userDisplayFormat.begin(), userDisplayFormat.end(), tagRegex);
    std::regex_iterator<std::string::const_iterator> end;

    std::map<std::string, std::string> placeholderToValue;
    std::string result;
    std::string::size_type lastPos = 0;
    for (; iter != end; ++iter)
    {
        const auto &match = *iter;
        std::size_t matchPos = static_cast<std::size_t>(match[0].first - userDisplayFormat.begin());
        result.append(userDisplayFormat.substr(lastPos, matchPos - lastPos));
        std::string tagName = match[1].str();
        auto it = fieldValuesMap.find(tagName);
        if (it != fieldValuesMap.end())
        {
            std::string placeholder = Helpers::Random::createRandomString(16);
            placeholderToValue[placeholder] = it->second;
            result.append(placeholder);
        }
        else
        {
            result.append(match[0].str()); // Leave unchanged if not found
        }
        lastPos = static_cast<std::size_t>(match[0].second - userDisplayFormat.begin());
    }
    result.append(userDisplayFormat.substr(lastPos));

    // Resolve all placeholders with actual values
    for (const auto &[placeholder, value] : placeholderToValue)
    {
        boost::replace_all(result, placeholder, value);
    }

    return result;
}

bool IdentityManager_DB::Accounts_DB::confirmAccount(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, const std::string &confirmationToken)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    Abstract::STRING token;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `confirmationToken` FROM iam.accountsActivationToken WHERE `f_accountUUID`=:accountUUID LIMIT 1;",
                                                  {{":accountUUID", MAKE_VAR(STRING, accountUUID)}},
                                                  {&token}))
    {
        if (!token.getValue().empty() && token.getValue() == confirmationToken)
        {
            bool result = _parent->m_sqlConnector->qExecuteEx("UPDATE iam.accounts SET `isAccountConfirmed`='1' WHERE `accountUUID`=:accountUUID;", {{":accountUUID", MAKE_VAR(STRING, accountUUID)}});
            if (result)
            {
                _parent->logSecurityEventOnAccounts(accountUUID, SecurityEventAction::CONFIRM, "Account confirmed", performedBy, clientDetails);
            }
            return result;
        }
    }
    return false;
}

bool IdentityManager_DB::Accounts_DB::changeAccountExpiration(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, time_t expiration)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    bool result = _parent->m_sqlConnector->qExecuteEx("UPDATE iam.accounts SET `expiration`=:expiration WHERE `accountUUID`=:accountUUID;",
                                                      {{":expiration", MAKE_VAR(DATETIME, expiration)}, {":accountUUID", MAKE_VAR(STRING, accountUUID)}});
    if (result)
    {
        _parent->logSecurityEventOnAccounts(accountUUID, SecurityEventAction::UPDATE, "Account expiration changed", performedBy, clientDetails);
    }
    return result;
}

AccountFlags IdentityManager_DB::Accounts_DB::getAccountFlags(const std::string &accountUUID)
{
    AccountFlags r;

    Abstract::BOOL enabled, confirmed, admin, blocked;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `isEnabled`,`isAccountConfirmed`,`isAdmin`,`isBlocked` FROM iam.accounts WHERE `accountUUID`=:accountUUID LIMIT 1;",
                                                  {{":accountUUID", MAKE_VAR(STRING, accountUUID)}},
                                                  {&enabled, &confirmed, &admin, &blocked}))
    {
        r.enabled = enabled.getValue();
        r.confirmed = confirmed.getValue();
        r.admin = admin.getValue();
        r.blocked = blocked.getValue();
    }

    return r;
}

bool IdentityManager_DB::Accounts_DB::updateAccountApplicationRoles(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &accountUUID,
                                                                    const std::set<std::string> &roleSet)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (!_parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.applicationRolesAccounts WHERE "
                                             "`f_accountUUID`=:accountUUID AND `f_appName`=:appName;",
                                             {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":appName", MAKE_VAR(STRING, appName)}}))
    {
        return false;
    }

    for (const std::string &role : roleSet)
    {
        if (!_parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.applicationRolesAccounts "
                                                 "(`f_roleName`,`f_accountUUID`,`f_appName`) "
                                                 "VALUES(:roleName,:accountUUID,:appName);",
                                                 {{":roleName", MAKE_VAR(STRING, role)}, {":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":appName", MAKE_VAR(STRING, appName)}}))
        {
            return false;
        }
    }

    _parent->logSecurityEventOnAccounts(accountUUID, SecurityEventAction::UPDATE, "Application roles updated to account", performedBy, clientDetails);

    return true;
}

bool IdentityManager_DB::Accounts_DB::changeAccountFlags(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, const AccountFlags &accountFlags)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if ((!accountFlags.confirmed || !accountFlags.enabled || !accountFlags.admin) && !isThereAnotherAdmin(accountUUID))
    {
        return false;
    }

    bool result = _parent->m_sqlConnector
                      ->qExecuteEx("UPDATE iam.accounts SET `isEnabled`=:enabled,`isAccountConfirmed`=:confirmed,`isAdmin`=:admin,`isBlocked`=:blocked WHERE `accountUUID`=:accountUUID;",
                                   {{":enabled", MAKE_VAR(BOOL, accountFlags.enabled)},
                                    {":confirmed", MAKE_VAR(BOOL, accountFlags.confirmed)},
                                    {":admin", MAKE_VAR(BOOL, accountFlags.admin)},
                                    {":blocked", MAKE_VAR(BOOL, accountFlags.blocked)},
                                    {":accountUUID", MAKE_VAR(STRING, accountUUID)}});
    if (result)
    {
        _parent->logSecurityEventOnAccounts(accountUUID, SecurityEventAction::UPDATE, "Account flags changed", performedBy, clientDetails);
    }
    return result;
}

time_t IdentityManager_DB::Accounts_DB::getAccountExpirationTime(const std::string &accountUUID)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::DATETIME expiration;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `expiration` FROM iam.accounts WHERE `accountUUID`=:accountUUID LIMIT 1;", {{":accountUUID", MAKE_VAR(STRING, accountUUID)}}, {&expiration}))
    {
        return expiration.getValue();
    }
    // If can't get this data, the account is expired:
    return 1;
}

time_t IdentityManager_DB::Accounts_DB::getAccountCreationTime(const std::string &accountUUID)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::DATETIME creation;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `creation` FROM iam.accounts WHERE `accountUUID`=:accountUUID LIMIT 1;", {{":accountUUID", MAKE_VAR(STRING, accountUUID)}}, {&creation}))
    {
        return creation.getValue(); // Asegúrate de convertir a `time_t` si es necesario
    }

    return std::numeric_limits<time_t>::max();
}

Json::Value IdentityManager_DB::Accounts_DB::searchAccounts(const Json::Value &dataTablesFilters)
{
    Json::Value ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    // DataTables:
    ret["draw"] = dataTablesFilters["draw"];

    uint64_t offset = Helpers::JSON::ASUINT64(dataTablesFilters, "start", 0);
    uint64_t limit = Helpers::JSON::ASUINT64(dataTablesFilters, "length", 0);

    // Manejo de ordenamiento (order)
    std::string orderByStatement = Helpers::DataTables::getOrderByStatement(dataTablesFilters);

    // Extract the search value from dataTablesFilters
    std::string searchValue = Helpers::JSON::ASSTRING(dataTablesFilters["search"], "value", "");
    std::string whereFilters;

    // Build the SQL query with WHERE clause for DataTables search

    std::string sqlQueryStr = R"(
    SELECT
        iam.accounts.accountUUID as accountUUID,
        iam.accounts.creation as creation,
        iam.accounts.expiration as expiration,
        last_login_agg.lastLogin as lastLogin,
        iam.accountCredentials.lastChange as lastChange,
        iam.accounts.isAdmin as isAdmin,
        iam.accounts.isEnabled as isEnabled,
        iam.accounts.isBlocked as isBlocked,
        iam.accounts.isAccountConfirmed as isAccountConfirmed,
        iam.accounts.creator as creator,
        EXISTS(
            SELECT 1 FROM iam.accountCredentials ac
            WHERE ac.f_accountUUID = iam.accounts.accountUUID AND ac.isLocked = 1
        ) as hasBlockedCredential
    FROM iam.accounts
    LEFT JOIN (
        SELECT f_accountUUID, MAX(lastLogin) as lastLogin
        FROM logs.applicationAccess_accountLastLogin
        GROUP BY f_accountUUID
    ) last_login_agg
        ON last_login_agg.f_accountUUID = iam.accounts.accountUUID
    LEFT JOIN iam.accountCredentials
        ON iam.accountCredentials.f_accountUUID = iam.accounts.accountUUID
        AND iam.accountCredentials.f_AuthSlotId = 1
    WHERE accounts.accountUUID <> '00000000-0000-4000-8000-000000000000'
    )";

    // Add WHERE clause for search term if provided
    if (!searchValue.empty())
    {
        searchValue = "%" + searchValue + "%";
        whereFilters += "accountUUID LIKE :SEARCHWORDS";
    }

    {
        Abstract::STRING accountUUID;
        Abstract::DATETIME creation, expiration, lastLogin, lastChange;
        Abstract::BOOL isAdmin, isEnabled, isBlocked, isAccountConfirmed;
        Abstract::STRING creator;
        Abstract::BOOL hasBlockedCredential;

        std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelectWithFilters(
            sqlQueryStr,
            whereFilters,
            {{":SEARCHWORDS", MAKE_VAR(STRING, searchValue)}},
            {&accountUUID, &creation, &expiration, &lastLogin, &lastChange, &isAdmin, &isEnabled, &isBlocked, &isAccountConfirmed, &creator, &hasBlockedCredential},
            orderByStatement, // Order by
            limit,            // LIMIT
            offset            // OFFSET
        );

        while (i && i->isSuccessful() && i->step())
        {
            Json::Value row;

            // accountUUID
            row["accountUUID"] = accountUUID.toJSON();
            // creation
            row["creation"] = creation.toJSON();
            // expiration
            row["expiration"] = expiration.toJSON();
            // lastAccess
            row["lastAccess"] = lastLogin.toJSON();
            // lastChange
            row["lastPasswordChange"] = lastChange.toJSON();

            row["applications"] = Json::arrayValue;

            row["DT_RowData"]["isAdmin"] = isAdmin.getValue();
            row["DT_RowData"]["isEnabled"] = isEnabled.getValue();
            row["DT_RowData"]["isBlocked"] = isBlocked.getValue();
            row["DT_RowData"]["isAccountConfirmed"] = isAccountConfirmed.getValue();
            row["DT_RowData"]["creator"] = creator.getValue();
            row["DT_RowData"]["hasBlockedCredential"] = hasBlockedCredential.getValue();

            ret["data"].append(row);
        }

        if (i)
        {
            ret["recordsTotal"] = i->getTotalRecordsCount();
            ret["recordsFiltered"] = i->getFilteredRecordsCount();
        }
    }

    // Now fill applications for each account (after the query scope ended to avoid DB blocking)
    for (Json::Value &row : ret["data"])
    {
        std::string accountUUID = row["accountUUID"].asString();
        Json::Value appsArray = Json::arrayValue;
        for (const std::string &appName : _parent->applications->listAccountApplications(accountUUID))
        {
            Json::Value appObj = Json::objectValue;
            appObj["name"] = appName;
            appObj["isAppAdmin"] = _parent->applications->isApplicationAdmin(appName, accountUUID);
            // Get last login per app from logs.applicationAccess_accountLastLogin
            {
                Abstract::DATETIME appLastLogin;
                if (_parent->m_sqlConnector->qSelectSingleRow("SELECT lastLogin FROM logs.applicationAccess_accountLastLogin WHERE f_accountUUID=:accountUUID AND f_appName=:appName;",
                                                              {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":appName", MAKE_VAR(STRING, appName)}},
                                                              {&appLastLogin}))
                {
                    appObj["lastLogin"] = appLastLogin.toJSON();
                }
                else
                {
                    appObj["lastLogin"] = Json::nullValue;
                }
            }
            appsArray.append(appObj);
        }
        row["displayName"] = getAccountDisplayName(accountUUID);
        row["applications"] = appsArray;
        row["DT_RowData"]["isInactive"] = _parent->authController->isAccountInactive(_parent->authController->getAccountLastAccess(accountUUID), row["DT_RowData"]["isAdmin"].asBool());
    }

    return ret;
}

std::set<std::string> IdentityManager_DB::Accounts_DB::listAccounts()
{
    std::set<std::string> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING accountUUID;
    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `accountUUID` FROM iam.accounts;", {}, {&accountUUID});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert(accountUUID.getValue());
    }

    return ret;
}

std::set<std::string> IdentityManager_DB::Accounts_DB::listAdminAccounts()
{
    std::set<std::string> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING accountUUID;
    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `accountUUID` FROM iam.accounts WHERE `isAdmin`=:admin;", {{":admin", MAKE_VAR(BOOL, true)}}, {&accountUUID});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert(accountUUID.getValue());
    }

    return ret;
}

std::set<ApplicationRole> IdentityManager_DB::Accounts_DB::getAccountApplicationRoles(const std::string &appName, const std::string &accountUUID, bool lock)
{
    std::set<ApplicationRole> ret;
    if (lock)
    {
        _parent->m_mutex.lockShared();
    }

    {
        Abstract::STRING role;
        Abstract::STRING roleDescription;
        std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT ar.f_roleName, r.roleDescription FROM iam.applicationRolesAccounts ar LEFT JOIN iam.applicationRoles r ON "
                                                                    "ar.f_roleName = r.roleName AND ar.f_appName = r.f_appName WHERE ar.f_accountUUID=:accountUUID AND ar.f_appName = :appName;",
                                                                    {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":appName", MAKE_VAR(STRING, appName)}},
                                                                    {&role, &roleDescription});
        while (i && i->isSuccessful() && i->step())
        {
            ApplicationRole appRole;
            appRole.id = role.getValue();
            appRole.appName = appName;
            appRole.description = roleDescription.getValue();
            ret.insert(appRole);
        }
    }

    if (lock)
    {
        _parent->m_mutex.unlockShared();
    }

    return ret;
}

bool IdentityManager_DB::Accounts_DB::hasValidAdminAccount()
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    return _parent->m_sqlConnector->qSelectSingleRow("SELECT `isAdmin` FROM iam.accounts WHERE `isAdmin`=:admin LIMIT 1;", {{":admin", MAKE_VAR(BOOL, true)}}, {});
}

bool IdentityManager_DB::Accounts_DB::isThereAnotherAdmin(const std::string &accountUUID)
{
    // Check if there is any admin acount beside this "to be deleted" account...
    return _parent->m_sqlConnector
        ->qSelectSingleRow("SELECT `isEnabled` FROM iam.accounts WHERE `accountUUID`!=:accountUUID and "
                           "`isAdmin`=:admin and `isEnabled`=:enabled and `isAccountConfirmed`=:confirmed LIMIT 1;",
                           {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":admin", MAKE_VAR(BOOL, true)}, {":enabled", MAKE_VAR(BOOL, true)}, {":confirmed", MAKE_VAR(BOOL, true)}},
                           {});
}

int32_t IdentityManager_DB::Accounts_DB::getAccountBlockTokenNoRenew(const std::string &accountUUID, std::string &token)
{
    AuthenticationPolicy authenticationPolicy = _parent->authController->getGlobalAuthenticationPolicy();
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING blockToken;
    Abstract::DATETIME lastAccess;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `blockToken`,`lastAccess` FROM iam.accountsBlockToken WHERE `f_accountUUID`=:accountUUID;",
                                                  {{":accountUUID", MAKE_VAR(STRING, accountUUID)}},
                                                  {&blockToken, &lastAccess}))
    {
        if (lastAccess.getValue() + authenticationPolicy.blockTokenTimeout > time(nullptr))
        {
            token = blockToken.getValue();
            return 0;
        }
        return -1;
    }
    return -2;
}

void IdentityManager_DB::Accounts_DB::removeBlockToken(const std::string &accountUUID)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountsBlockToken WHERE `f_accountUUID`=:accountUUID;", {{":accountUUID", MAKE_VAR(STRING, accountUUID)}});
}

void IdentityManager_DB::Accounts_DB::updateOrCreateBlockToken(const std::string &accountUUID)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    if (!_parent->m_sqlConnector->qExecuteEx("UPDATE iam.accountsBlockToken SET `lastAccess`=CURRENT_TIMESTAMP WHERE `f_accountUUID`=:accountUUID;", {{":accountUUID", MAKE_VAR(STRING, accountUUID)}}))
    {
        _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.accountsBlockToken (`f_accountUUID`,`blockToken`) VALUES(:account,:blockToken);",
                                            {{":account", MAKE_VAR(STRING, accountUUID)}, {":blockToken", MAKE_VAR(STRING, _parent->authController->genRandomConfirmationToken())}});
    }
}

std::string IdentityManager_DB::Accounts_DB::getAccountBlockToken(const std::string &accountUUID)
{
    std::string token;
    int32_t i = getAccountBlockTokenNoRenew(accountUUID, token);
    if (i == 0)
    {
        // Update the registry last access here...
        updateOrCreateBlockToken(accountUUID);
        return token;
    }
    else if (i == -1)
    {
        // Expired, remove the previous one create a new one...
        removeBlockToken(accountUUID);
        updateOrCreateBlockToken(accountUUID);
    }
    else if (i == -2)
    {
        // No registry... Create a new one...
        updateOrCreateBlockToken(accountUUID);
    }
    i = getAccountBlockTokenNoRenew(accountUUID, token);
    if (i == 0)
    {
        return token;
    }

    return "";
}

bool IdentityManager_DB::Accounts_DB::blockAccountUsingToken(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, const std::string &blockToken)
{
    std::string dbBlockToken;
    if (getAccountBlockTokenNoRenew(accountUUID, dbBlockToken) == 0)
    {
        if (dbBlockToken == blockToken)
        {
            // everything in place to block this account:
            bool result = disableAccount(clientDetails, performedBy, accountUUID);
            if (result)
            {
                _parent->logSecurityEventOnAccounts(accountUUID, SecurityEventAction::LOCK, "Account blocked via token", performedBy, clientDetails);
            }
            return result;
        }
    }
    return false;
}

std::optional<std::string> IdentityManager_DB::Accounts_DB::getAccountUUIDByAccountName(const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    // Finds the accountUUID for a given accountName by looking up the first
    // login-identifier field (isLoginIdentifier=TRUE) in accountDetailFields
    // and matching its value in accountDetailValues.
    Abstract::STRING accountUUID;

    bool r = _parent->m_sqlConnector->qSelectSingleRow(
        R"(
            SELECT vadv.f_accountUUID
            FROM iam.accountDetailValues vadv
            INNER JOIN iam.accountDetailFields vadf ON vadf.fieldName = vadv.f_fieldName
            WHERE vadf.isLoginIdentifier = 1
              AND vadv.value = :accountName
            LIMIT 1
        )",
        {{":accountName", MAKE_VAR(STRING, accountName)}},
        {&accountUUID});

    if (r)
    {
        std::string uuid = accountUUID.getValue();
        if (!uuid.empty())
        {
            return uuid;
        }
    }

    return std::nullopt;
}

std::set<std::string> IdentityManager_DB::Accounts_DB::getAccountNamesByAccountUUID(const std::string &accountUUID)
{
    std::set<std::string> result;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    // Query all login-identifier field values for the given accountUUID
    Abstract::STRING value;
    std::shared_ptr<Query> q = _parent->m_sqlConnector->qSelect(
        R"(
            SELECT vadv.value
            FROM iam.accountDetailValues vadv
            INNER JOIN iam.accountDetailFields vadf ON vadf.fieldName = vadv.f_fieldName
            WHERE vadf.isLoginIdentifier = 1
              AND vadv.f_accountUUID = :accountUUID
        )",
        {{":accountUUID", MAKE_VAR(STRING, accountUUID)}},
        {&value});

    while (q && q->isSuccessful() && q->step())
    {
        result.insert(value.getValue());
    }

    return result;
}
