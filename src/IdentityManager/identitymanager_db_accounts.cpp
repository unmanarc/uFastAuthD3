#include "IdentityManager/identitymanager.h"
#include <Mantids30/Helpers/json.h>
#include "identitymanager_db.h"

#include <Mantids30/DB/transaction.h>
#include <Mantids30/Helpers/datatables.h>
#include <Mantids30/Helpers/random.h>
#include <Mantids30/Threads/lock_shared.h>
#include <boost/regex.hpp>
#include <json/value.h>
#include <optional>
#include <regex>

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

std::optional<std::string> IdentityManager_DB::Accounts_DB::createAccount(time_t expirationDate, const AccountFlags &accountFlags, const ClientDetails &clientDetails,
                                                                          const std::string &sCreatorAccountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    std::string accountUUID = Helpers::Random::createUUIDv4();

    bool r = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.accounts (`accountUUID`,`isAdmin`,`isEnabled`,`isBlocked`,`expiration`,`isAccountConfirmed`,`creator`) "
                                                 "VALUES(:accountUUID,:admin ,:enabled, :blocked ,:expiration ,:confirmed ,:creator);",
                                                 {{":accountUUID", MAKE_VAR(STRING, accountUUID)},
                                                  {":admin", MAKE_VAR(BOOL, accountFlags.admin)},
                                                  {":enabled", MAKE_VAR(BOOL, accountFlags.enabled)},
                                                  {":blocked", MAKE_VAR(BOOL, accountFlags.blocked)},
                                                  {":expiration", MAKE_VAR(DATETIME, expirationDate)},
                                                  {":confirmed", MAKE_VAR(BOOL, accountFlags.confirmed)},
                                                  {":creator", sCreatorAccountName.empty() ? MAKE_NULL_VAR /* null */ : MAKE_VAR(STRING, sCreatorAccountName)}});

    if (r)
    {
        // Now create the activation token...
        r = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.accountsActivationToken (`f_accountUUID`,`confirmationToken`) "
                                                "VALUES(:accountUUID,:confirmationToken);",
                                                {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":confirmationToken", MAKE_VAR(STRING, _parent->authController->genRandomConfirmationToken())}});
        if (r)
        {
            // Now create the credential... but!!... the credential should be a valid subset from an authentication mode...
        }
    }

    if (r)
    {
        _parent->logSecurityEventOnAccounts(accountUUID, SecurityEventAction::CREATE, "New account created", sCreatorAccountName.empty() ? accountUUID : sCreatorAccountName, clientDetails);
    }

    if (r)
    {
        return accountUUID;
    }
    else
    {
        return std::nullopt;
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
        _parent->logSecurityEventOnAccounts(accountUUID, disabled ? SecurityEventAction::DISABLE : SecurityEventAction::ENABLE, disabled ? "Account disabled" : "Account enabled", performedBy,
                                            clientDetails);
    }
    return result;
}

bool IdentityManager_DB::Accounts_DB::confirmAccount(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, const std::string &confirmationToken)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    Abstract::STRING token;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `confirmationToken` FROM iam.accountsActivationToken WHERE `f_accountUUID`=:accountUUID LIMIT 1;",
                                                  {{":accountUUID", MAKE_VAR(STRING, accountUUID)}}, {&token}))
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
                                                  {{":accountUUID", MAKE_VAR(STRING, accountUUID)}}, {&enabled, &confirmed, &admin, &blocked}))
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

std::optional<AccountDetails> IdentityManager_DB::Accounts_DB::getAccountDetails(const std::string &accountUUID, const AccountDetailsToShow &detailsToShow)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    // Definir las variables para capturar los valores de la base de datos
    Abstract::STRING creator;
    Abstract::BOOL isAdmin, isEnabled, isAccountConfirmed;
    Abstract::DATETIME creation, expiration;

    std::map<std::string, AccountDetailField> allFields = listAccountDetailFields();
    AccountDetails details;

    {
        if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `isAdmin`,`creation`, `creator`, `expiration`, `isEnabled`, `isAccountConfirmed` "
                                                      "FROM iam.accounts WHERE `accountUUID`=:accountUUID LIMIT 1;",
                                                      {{":accountUUID", MAKE_VAR(STRING, accountUUID)}}, {&isAdmin, &creation, &creator, &expiration, &isEnabled, &isAccountConfirmed}))
        {
            details.accountUUID = accountUUID;
            details.creator = creator.getValue();
            details.accountFlags.admin = isAdmin.getValue();
            details.accountFlags.enabled = isEnabled.getValue();
            details.accountFlags.confirmed = isAccountConfirmed.getValue();
            details.expirationDate = expiration.getValue();
            details.creationDate = creation.getValue();
            details.expired = std::time(nullptr) > details.expirationDate;
        }
        else
        {
            return std::nullopt;
        }
    }

    details.fields = getAccountDetailFieldValues(accountUUID, detailsToShow);

    return details;
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

Json::Value IdentityManager_DB::Accounts_DB::searchFields(const Json::Value &dataTablesFilters)
{
    Json::Value ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    // DataTables:
    ret["draw"] = dataTablesFilters["draw"];

    uint64_t offset = Helpers::JSON::ASUINT64(dataTablesFilters, "start", 0);
    uint64_t limit = Helpers::JSON::ASUINT64(dataTablesFilters, "length", 0);

    // Manejo de ordenamiento (order);
    std::string orderByStatement = Helpers::DataTables::getOrderByStatement(dataTablesFilters);

    // Extract the search value from dataTablesFilters
    std::string searchValue = Helpers::JSON::ASSTRING(dataTablesFilters["search"], "value", "");
    std::string whereFilters;

    // Build the SQL query with WHERE clause for DataTables search
    std::string sqlQueryStr = R"(
    SELECT
        fieldName,
        fieldDescription,
        fieldType,
        isOptionalField,
        isUnique,
        isLoginIdentifier
    FROM accountDetailFields
    )";

    // Add WHERE clause for search term if provided
    if (!searchValue.empty())
    {
        searchValue = "%" + searchValue + "%";
        whereFilters += "fieldName LIKE :SEARCHWORDS OR fieldDescription LIKE :SEARCHWORDS";
    }

    {
        Abstract::STRING fieldName, fieldDescription, fieldType;
        Abstract::BOOL isOptionalField, isUnique, isLoginIdentifier;
        std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelectWithFilters(sqlQueryStr, whereFilters, {{":SEARCHWORDS", MAKE_VAR(STRING, searchValue)}},
                                                                               {&fieldName, &fieldDescription, &fieldType, &isOptionalField, &isUnique, &isLoginIdentifier},
                                                                               orderByStatement, // Order by
                                                                               limit,            // LIMIT
                                                                               offset            // OFFSET
        );

        while (i && i->isSuccessful() && i->step())
        {
            Json::Value row;

            // fieldName
            row["fieldName"] = fieldName.toJSON();
            // fieldDescription
            row["fieldDescription"] = fieldDescription.toJSON();
            // fieldType
            row["fieldType"] = fieldType.toJSON();
            // isOptionalField
            row["isOptionalField"] = isOptionalField.getValue();
            // isUnique
            row["isUnique"] = isUnique.getValue();
            // isLoginIdentifier
            row["isLoginIdentifier"] = isLoginIdentifier.getValue();

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

        std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelectWithFilters(sqlQueryStr, whereFilters, {{":SEARCHWORDS", MAKE_VAR(STRING, searchValue)}},
                                                                               {&accountUUID, &creation, &expiration, &lastLogin, &lastChange, &isAdmin, &isEnabled, &isBlocked, &isAccountConfirmed,
                                                                                &creator, &hasBlockedCredential},
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
                                                              {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":appName", MAKE_VAR(STRING, appName)}}, {&appLastLogin}))
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
                                                                    {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":appName", MAKE_VAR(STRING, appName)}}, {&role, &roleDescription});
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
                           {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":admin", MAKE_VAR(BOOL, true)}, {":enabled", MAKE_VAR(BOOL, true)}, {":confirmed", MAKE_VAR(BOOL, true)}}, {});
}

int32_t IdentityManager_DB::Accounts_DB::getAccountBlockTokenNoRenew(const std::string &accountUUID, std::string &token)
{
    AuthenticationPolicy authenticationPolicy = _parent->authController->getGlobalAuthenticationPolicy();
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING blockToken;
    Abstract::DATETIME lastAccess;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `blockToken`,`lastAccess` FROM iam.accountsBlockToken WHERE `f_accountUUID`=:accountUUID;", {{":accountUUID", MAKE_VAR(STRING, accountUUID)}},
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

bool IdentityManager_DB::Accounts_DB::createAccountDetailField(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &fieldName, const AccountDetailField &details)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Invalid condition.
    if (details.isLoginIdentifier && !details.isUnique)
    {
        return false;
    }

    if (_parent->m_sqlConnector
            ->qExecuteEx("INSERT INTO iam.accountDetailFields (`fieldName`, `fieldDescription`, `fieldType`, `isOptionalField`, `isUnique`,`isLoginIdentifier`, `jsonExtendedAttribs`)"
                         " VALUES (:fieldName, :fieldDescription, :fieldType, :isOptionalField, :isUnique, :isLoginIdentifier, :jsonExtendedAttribs);",
                         {{":fieldName", MAKE_VAR(STRING, fieldName)},
                          {":fieldDescription", MAKE_VAR(STRING, details.description)},
                          {":fieldType", MAKE_VAR(STRING, details.fieldType)},
                          {":isOptionalField", MAKE_VAR(BOOL, details.isOptionalField)},
                          {":isUnique", MAKE_VAR(BOOL, details.isUnique)},
                          {":isLoginIdentifier", MAKE_VAR(BOOL, details.isLoginIdentifier)},
                          {":jsonExtendedAttribs", MAKE_VAR(STRING, details.extendedAttributes.toStyledString())}}))
    {
        _parent->logSecurityEventOnAccountDetailFields(fieldName, SecurityEventAction::CREATE, "Account detail field created", performedBy, clientDetails);
        return true;
    }

    return false;
}

bool IdentityManager_DB::Accounts_DB::updateAccountDetailField(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &fieldName, const AccountDetailField &details)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Invalid condition.
    if (details.isLoginIdentifier && !details.isUnique)
    {
        return false;
    }

    if (!_parent->m_sqlConnector->qExecuteEx("UPDATE iam.accountDetailFields SET `fieldDescription`=:fieldDescription, `fieldType`=:fieldType, `isOptionalField`=:isOptionalField, "
                                             "`isUnique`=:isUnique, `isLoginIdentifier`=:isLoginIdentifier, `jsonExtendedAttribs`=:jsonExtendedAttribs WHERE `fieldName`=:fieldName;",
                                             {{":fieldName", MAKE_VAR(STRING, fieldName)},
                                              {":fieldDescription", MAKE_VAR(STRING, details.description)},
                                              {":fieldType", MAKE_VAR(STRING, details.fieldType)},
                                              {":isOptionalField", MAKE_VAR(BOOL, details.isOptionalField)},
                                              {":isUnique", MAKE_VAR(BOOL, details.isUnique)},
                                              {":isLoginIdentifier", MAKE_VAR(BOOL, details.isLoginIdentifier)},
                                              {":jsonExtendedAttribs", MAKE_VAR(STRING, details.extendedAttributes.toStyledString())}}))
    {
        return false;
    }

    _parent->logSecurityEventOnAccountDetailFields(fieldName, SecurityEventAction::UPDATE, "Account detail field updated", performedBy, clientDetails);

    return true;
}

bool IdentityManager_DB::Accounts_DB::removeAccountDetailField(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &fieldName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (!_parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountDetailFields WHERE `fieldName` = :fieldName;", {{":fieldName", MAKE_VAR(STRING, fieldName)}}))
    {
        return false;
    }

    _parent->logSecurityEventOnAccountDetailFields(fieldName, SecurityEventAction::DELETE, "Account detail field removed", performedBy, clientDetails);

    return true;
}

std::map<std::string, AccountDetailField> IdentityManager_DB::Accounts_DB::listAccountDetailFields()
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::map<std::string, AccountDetailField> fieldMap;

    // Variables para capturar valores de la base de datos
    Abstract::STRING fieldName, fieldDescription, fieldType;
    Abstract::BOOL isOptionalField, isUnique, isLoginIdentifier;
    Abstract::STRING jsonExtendedAttribsText;

    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect(
        "SELECT `fieldName`, `fieldDescription`, `fieldType`, `isOptionalField`, `isUnique`, `isLoginIdentifier`, `jsonExtendedAttribs` FROM `iam`.`accountDetailFields`;", {},
        {&fieldName, &fieldDescription, &fieldType, &isOptionalField, &isUnique, &isLoginIdentifier, &jsonExtendedAttribsText});

    if (i && i->isSuccessful())
    {
        while (i->step())
        {
            Json::Value r;
            Json::Reader().parse(jsonExtendedAttribsText.getValue(), r);

            AccountDetailField field;
            field.description = fieldDescription.getValue();
            field.fieldType = fieldType.getValue();
            field.isOptionalField = isOptionalField.getValue();
            field.isUnique = isUnique.getValue();
            field.isLoginIdentifier = isLoginIdentifier.getValue();
            field.extendedAttributes = r;

            fieldMap[fieldName.getValue()] = field;
        }
    }

    return fieldMap;
}
std::optional<AccountDetailField> IdentityManager_DB::Accounts_DB::getAccountDetailField(const std::string &fieldName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    AccountDetailField field;

    // Variables para capturar valores de la base de datos
    Abstract::STRING fieldDescription, fieldType;
    Abstract::BOOL isOptionalField, isUnique, isLoginIdentifier;
    Abstract::STRING jsonExtendedAttribsText;

    if (_parent->m_sqlConnector->qSelectSingleRow(
            "SELECT `fieldDescription`,`fieldType`,`isOptionalField`, `isUnique`, `isLoginIdentifier`,`jsonExtendedAttribs` FROM `iam`.`accountDetailFields` WHERE `fieldName` = :fieldName;",
            {{":fieldName", MAKE_VAR(STRING, fieldName)}}, {&fieldDescription, &fieldType, &isOptionalField, &isUnique, &isLoginIdentifier, &jsonExtendedAttribsText}))
    {
        Json::Value r;
        Json::Reader().parse(jsonExtendedAttribsText.getValue(), r);

        field.description = fieldDescription.getValue();
        field.fieldType = fieldType.getValue();
        field.isOptionalField = isOptionalField.getValue();
        field.isUnique = isUnique.getValue();
        field.isLoginIdentifier = isLoginIdentifier.getValue();
        field.extendedAttributes = r;

        return field;
    }

    // Return empty optional if not found
    return std::nullopt;
}

bool IdentityManager_DB::Accounts_DB::changeAccountDetails(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID,
                                                           const std::map<std::string, std::string> &fieldsValues, bool resetAllValues)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    Transaction tg(*_parent->m_sqlConnector);

    if (resetAllValues)
    {
        // Delete all values for the specified account
        if (!_parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountDetailValues WHERE `f_accountUUID` = :accountUUID;", {{":accountUUID", MAKE_VAR(STRING, accountUUID)}}))
        {
            return tg.finalize(false);
        }
    }
    else
    {
        // Delete only specified fields for the account
        for (const auto &field : fieldsValues)
        {
            if (!_parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountDetailValues WHERE `f_accountUUID` = :accountUUID AND `f_fieldName` = :fieldName;",
                                                     {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":fieldName", MAKE_VAR(STRING, field.first)}}))
            {
                return tg.finalize(false);
            }
        }
    }

    // Insert new values
    for (const auto &field : fieldsValues)
    {
        // Validate field value against regex from iam.accountDetailFields
        Abstract::STRING regex;
        if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `fieldRegexpValidator` FROM iam.accountDetailFields WHERE `fieldName` = :fieldName;", {{":fieldName", MAKE_VAR(STRING, field.first)}},
                                                      {&regex}))
        {
            std::regex reg(regex.getValue());
            if (!std::regex_match(field.second, reg))
            {
                // The value does not match the regex
                return tg.finalize(false);
            }
        }

        // Inserting the validated value
        if (!_parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.accountDetailValues (`f_accountUUID`, `f_fieldName`, `value`) VALUES(:accountUUID, :fieldName, :value);",
                                                 {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":fieldName", MAKE_VAR(STRING, field.first)}, {":value", MAKE_VAR(STRING, field.second)}}))
        {
            return tg.finalize(false);
        }
    }

    // Commit the transaction
    _parent->logSecurityEventOnAccounts(accountUUID, SecurityEventAction::UPDATE, resetAllValues ? "All account details reset" : "Account details updated", performedBy, clientDetails);

    return tg.finalize();
}

bool IdentityManager_DB::Accounts_DB::removeAccountDetail(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, const std::string &fieldName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    bool result = _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountDetailValues WHERE `f_accountUUID` = :accountUUID AND `f_fieldName` = :fieldName;",
                                                      {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":fieldName", MAKE_VAR(STRING, fieldName)}});
    if (result)
    {
        _parent->logSecurityEventOnAccounts(accountUUID, SecurityEventAction::DELETE, "Account detail removed", performedBy, clientDetails);
    }
    return result;
}

bool IdentityManager_DB::Accounts_DB::updateAccountDetailFieldValues(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID,
                                                                     const std::list<AccountDetailFieldValue> &inputFieldValues, bool isAdmin)
{
    std::map<std::string, AccountDetailField> dbFieldsScheme = listAccountDetailFields();

    // TODO: log the field update operation.
    for (const AccountDetailFieldValue &inputFieldValue : inputFieldValues)
    {
        // Validate Regexp.
        if (dbFieldsScheme.find(inputFieldValue.name) != dbFieldsScheme.end())
        {
            if (!dbFieldsScheme[inputFieldValue.name].canUserEdit() && !isAdmin)
            {
                // User can not edit this field.
                return false;
            }

            if (inputFieldValue.value.has_value())
            {
                std::string regexpValidator = dbFieldsScheme[inputFieldValue.name].getRegexpValidatorText();
                if (!regexpValidator.empty())
                {
                    std::string value = inputFieldValue.value.value();
                    try
                    {
                        boost::regex regExp(regexpValidator);
                        if (!boost::regex_search(value, regExp))
                        {
                            // Rexep does not match.
                            return false;
                        }
                    }
                    catch (const boost::regex_error &)
                    {
                        // if not defined, continue.
                    }
                }
            }
        }
        else
        {
            // Invalid field.
            return false;
        }
    }

    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    _parent->m_sqlConnector->beginTransaction();

    // Delete all the fields that are going to be replaced.
    if (isAdmin)
    {
        _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountDetailValues WHERE `f_accountUUID` = :accountUUID;", {{":accountUUID", MAKE_VAR(STRING, accountUUID)}});
    }
    else
    {
        // Collect all editable field names for this account
        std::set<std::string> editableFields;
        for (const auto &field : dbFieldsScheme)
        {
            if ((field.second.canUserEdit() && !isAdmin) || isAdmin)
            {
                editableFields.insert(field.first);
            }
        }

        // Delete every editable field from that user account.
        for (const std::string &fieldName : editableFields)
        {
            std::string sql = "DELETE FROM iam.accountDetailValues WHERE `f_accountUUID` = :account AND `f_fieldName` = :field;";
            std::map<std::string, std::shared_ptr<Mantids30::Memory::Abstract::Var>> params;
            params[":account"] = MAKE_VAR(STRING, accountUUID);
            params[":field"] = MAKE_VAR(STRING, fieldName);
            if (!_parent->m_sqlConnector->qExecuteEx(sql, params))
            {
                // Maybe the field does not exist yet...
            }
        }
    }

    // Insert all the fields to the database.
    for (const AccountDetailFieldValue &fieldValue : inputFieldValues)
    {
        if (fieldValue.value.has_value() && dbFieldsScheme.find(fieldValue.name) != dbFieldsScheme.end())
        {
            if (!_parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.accountDetailValues (`f_accountUUID`, `f_fieldName`, `value`) VALUES(:accountUUID, :fieldName, :value);",
                                                     {{":accountUUID", MAKE_VAR(STRING, accountUUID)},
                                                      {":fieldName", MAKE_VAR(STRING, fieldValue.name)},
                                                      {":value", MAKE_VAR(STRING, fieldValue.value.value())}}))
            {
                _parent->m_sqlConnector->rollbackTransaction();
                return false;
            }
        }
    }

    _parent->logSecurityEventOnAccounts(accountUUID, SecurityEventAction::UPDATE, "Account detail field values updated", performedBy, clientDetails);

    _parent->m_sqlConnector->commitTransaction();
    return true;
}

std::map<std::string, AccountDetailFieldValue> IdentityManager_DB::Accounts_DB::getAccountDetailFieldValues(const std::string &accountUUID, const AccountDetailsToShow &detailsToShow)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::map<std::string, AccountDetailFieldValue> detailValues;

    Abstract::STRING fieldName, fieldDescription, fieldType, jsonExtendedAttribsText, value;

    std::string query = R"(
                            SELECT vadf.fieldName, vadf.fieldDescription, vadf.fieldType, vadf.jsonExtendedAttribs, vadv.value
                            FROM iam.accountDetailFields vadf
                            LEFT JOIN iam.accountDetailValues vadv ON vadf.fieldName = vadv.f_fieldName
                            AND vadv.f_accountUUID = :accountUUID
                        )";

    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect(query, {{":accountUUID", MAKE_VAR(STRING, accountUUID)}}, {&fieldName, &fieldDescription, &fieldType, &jsonExtendedAttribsText, &value});

    if (i && i->isSuccessful())
    {
        while (i->step())
        {
            Json::Value extendedAttributes;
            Json::Reader().parse(jsonExtendedAttribsText.getValue(), extendedAttributes);

            bool visible = false;

            switch (detailsToShow)
            {
            case AccountDetailsToShow::SEARCH:
                visible = Helpers::JSON::ASBOOL(extendedAttributes["visibility"], "includeInSearch", false);
                break;
            case AccountDetailsToShow::COLUMNVIEW:
                visible = Helpers::JSON::ASBOOL(extendedAttributes["visibility"], "includeInColumnView", false);
                break;
            case AccountDetailsToShow::TOKEN:
                visible = Helpers::JSON::ASBOOL(extendedAttributes["visibility"], "includeInToken", false);
                break;
            case AccountDetailsToShow::APISYNC:
                visible = Helpers::JSON::ASBOOL(extendedAttributes["visibility"], "includeInAPISync", false);
                break;
            case AccountDetailsToShow::ALL:
            default:
                // no additional filter for ALL
                visible = true;
                break;
            }

            visible &= Helpers::JSON::ASBOOL(extendedAttributes["security"], "canUserView", false);

            if (visible)
            {
                AccountDetailFieldValue field;
                field.name = fieldName.getValue();
                field.description = fieldDescription.getValue();
                field.fieldType = fieldType.getValue();
                field.fieldRegexpValidator = Helpers::JSON::ASSTRING(extendedAttributes["behavior"], "regexpValidator", ""); // TODO: remover esta linea
                field.extendedAttribs = extendedAttributes;

                if (value.isNull())
                {
                    field.value = std::nullopt;
                }
                else
                {
                    field.value = value.getValue();
                }

                detailValues[fieldName.getValue()] = field;
            }
        }
    }

    return detailValues;
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
        {{":accountName", MAKE_VAR(STRING, accountName)}}, {&accountUUID});

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
