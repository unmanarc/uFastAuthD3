#include "IdentityManager/identitymanager.h"
#include "Mantids30/Helpers/json.h"
#include "identitymanager_db.h"

#include <Mantids30/Threads/lock_shared.h>
#include <boost/regex.hpp>
#include <json/value.h>
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

bool IdentityManager_DB::Accounts_DB::addAccount(const std::string &accountName, time_t expirationDate, const AccountFlags &accountFlags, const std::string &sCreatorAccountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    bool r = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.accounts (`accountName`,`isAdmin`,`isEnabled`,`isBlocked`,`expiration`,`isAccountConfirmed`,`creator`) "
                                                 "VALUES(:accountName,:admin ,:enabled, :blocked ,:expiration ,:confirmed ,:creator);",
                                                 {{":accountName", MAKE_VAR(STRING, accountName)},
                                                  {":admin", MAKE_VAR(BOOL, accountFlags.admin)},
                                                  {":enabled", MAKE_VAR(BOOL, accountFlags.enabled)},
                                                  {":blocked", MAKE_VAR(BOOL, accountFlags.blocked)},
                                                  {":expiration", MAKE_VAR(DATETIME, expirationDate)},
                                                  {":confirmed", MAKE_VAR(BOOL, accountFlags.confirmed)},
                                                  {":creator", sCreatorAccountName.empty() ? MAKE_NULL_VAR /* null */ : MAKE_VAR(STRING, sCreatorAccountName)}});

    if (r)
    {
        // Now create the activation token...
        r = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.accountsActivationToken (`f_accountName`,`confirmationToken`) "
                                                "VALUES(:account,:confirmationToken);",
                                                {{":account", MAKE_VAR(STRING, accountName)}, {":confirmationToken", MAKE_VAR(STRING, _parent->authController->genRandomConfirmationToken())}});
        if (r)
        {
            // Now create the credential... but!!... the credential should be a valid subset from an authentication mode...
        }
    }

    return r;
}

bool IdentityManager_DB::Accounts_DB::removeAccount(const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (isThereAnotherAdmin(accountName))
    {
        return _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accounts WHERE `accountName`=:accountName;", {{":accountName", MAKE_VAR(STRING, accountName)}});
    }
    return false;
}

bool IdentityManager_DB::Accounts_DB::doesAccountExist(const std::string &accountName)
{
    bool ret = false;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    ret = _parent->m_sqlConnector->qSelectSingleRow("SELECT `isEnabled` FROM iam.accounts WHERE `accountName`=:accountName LIMIT 1;", {{":accountName", MAKE_VAR(STRING, accountName)}}, {});
    return ret;
}

bool IdentityManager_DB::Accounts_DB::disableAccount(const std::string &accountName, bool disabled)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (disabled == true && !isThereAnotherAdmin(accountName))
    {
        return false;
    }

    return _parent->m_sqlConnector->qExecuteEx("UPDATE iam.accounts SET `isEnabled`=:enabled WHERE `accountName`=:accountName;",
                                               {{":enabled", MAKE_VAR(BOOL, !disabled)}, {":accountName", MAKE_VAR(STRING, accountName)}});
}

bool IdentityManager_DB::Accounts_DB::confirmAccount(const std::string &accountName, const std::string &confirmationToken)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    Abstract::STRING token;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `confirmationToken` FROM iam.accountsActivationToken WHERE `f_accountName`=:accountName LIMIT 1;",
                                                  {{":accountName", MAKE_VAR(STRING, accountName)}}, {&token}))
    {
        if (!token.getValue().empty() && token.getValue() == confirmationToken)
        {
            return _parent->m_sqlConnector->qExecuteEx("UPDATE iam.accounts SET `isAccountConfirmed`='1' WHERE `accountName`=:accountName;", {{":accountName", MAKE_VAR(STRING, accountName)}});
        }
    }
    return false;
}

bool IdentityManager_DB::Accounts_DB::changeAccountExpiration(const std::string &accountName, time_t expiration)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    return _parent->m_sqlConnector->qExecuteEx("UPDATE iam.accounts SET `expiration`=:expiration WHERE `accountName`=:accountName;",
                                               {{":expiration", MAKE_VAR(DATETIME, expiration)}, {":accountName", MAKE_VAR(STRING, accountName)}});
}

AccountFlags IdentityManager_DB::Accounts_DB::getAccountFlags(const std::string &accountName)
{
    AccountFlags r;

    Abstract::BOOL enabled, confirmed, admin, blocked;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `isEnabled`,`isAccountConfirmed`,`isAdmin`,`isBlocked` FROM iam.accounts WHERE `accountName`=:accountName LIMIT 1;",
                                                  {{":accountName", MAKE_VAR(STRING, accountName)}}, {&enabled, &confirmed, &admin, &blocked}))
    {
        r.enabled = enabled.getValue();
        r.confirmed = confirmed.getValue();
        r.admin = admin.getValue();
        r.blocked = blocked.getValue();
    }

    return r;
}

bool IdentityManager_DB::Accounts_DB::updateAccountRoles(const std::string &appName, const std::string &accountName, const std::set<std::string> &roleSet)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (!_parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.applicationRolesAccounts WHERE `f_accountName`=:accountName AND `f_appName`=:appName;",
                                             {{":accountName", MAKE_VAR(STRING, accountName)}, {":appName", MAKE_VAR(STRING, appName)}}))
        return false;

    for (const auto &role : roleSet)
    {
        if (!_parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.applicationRolesAccounts (`f_roleName`,`f_accountName`,`f_appName`) VALUES(:roleName,:accountName,:appName);",
                                                 {{":roleName", MAKE_VAR(STRING, role)}, {":accountName", MAKE_VAR(STRING, accountName)}, {":appName", MAKE_VAR(STRING, appName)}}))
            return false;
    }
    return true;
}

bool IdentityManager_DB::Accounts_DB::changeAccountFlags(const std::string &accountName, const AccountFlags &accountFlags)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if ((accountFlags.confirmed == false || accountFlags.enabled == false || accountFlags.admin == false) && !isThereAnotherAdmin(accountName))
    {
        return false;
    }

    return _parent->m_sqlConnector->qExecuteEx("UPDATE iam.accounts SET `isEnabled`=:enabled,`isAccountConfirmed`=:confirmed,`isAdmin`=:admin,`isBlocked`=:blocked WHERE `accountName`=:accountName;",
                                               {{":enabled", MAKE_VAR(BOOL, accountFlags.enabled)},
                                                {":confirmed", MAKE_VAR(BOOL, accountFlags.confirmed)},
                                                {":admin", MAKE_VAR(BOOL, accountFlags.admin)},
                                                {":blocked", MAKE_VAR(BOOL, accountFlags.blocked)},
                                                {":accountName", MAKE_VAR(STRING, accountName)}});
}

std::optional<AccountDetails> IdentityManager_DB::Accounts_DB::getAccountDetails(const std::string &accountName, const AccountDetailsToShow &detailsToShow)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    // Definir las variables para capturar los valores de la base de datos
    Abstract::STRING creator;
    Abstract::BOOL isAdmin, isEnabled, isAccountConfirmed;
    Abstract::DATETIME creation, expiration;

    auto allFields = listAccountDetailFields();
    AccountDetails details;

    {
        if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `isAdmin`,`creation`, `creator`, `expiration`, `isEnabled`, `isAccountConfirmed` "
                                                      "FROM iam.accounts WHERE `accountName`=:accountName LIMIT 1;",
                                                      {{":accountName", MAKE_VAR(STRING, accountName)}}, {&isAdmin, &creation, &creator, &expiration, &isEnabled, &isAccountConfirmed}))
        {
            details.accountName = accountName;
            details.creator = creator.getValue();
            details.accountFlags.admin = isAdmin.getValue();
            details.accountFlags.enabled = isEnabled.getValue();
            details.accountFlags.confirmed = isAccountConfirmed.getValue();
            details.expirationDate = expiration.getValue();
            details.creationDate = creation.getValue();
            details.expired = std::time(nullptr) > details.expirationDate;
        }
        else
            return std::nullopt;
    }

    details.fields = getAccountDetailFieldValues(accountName, detailsToShow);

    return details;
}

time_t IdentityManager_DB::Accounts_DB::getAccountExpirationTime(const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::DATETIME expiration;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `expiration` FROM iam.accounts WHERE `accountName`=:accountName LIMIT 1;", {{":accountName", MAKE_VAR(STRING, accountName)}}, {&expiration}))
    {
        return expiration.getValue();
    }
    // If can't get this data, the account is expired:
    return 1;
}

time_t IdentityManager_DB::Accounts_DB::getAccountCreationTime(const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::DATETIME creation;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `creation` FROM iam.accounts WHERE `accountName`=:accountName LIMIT 1;", {{":accountName", MAKE_VAR(STRING, accountName)}}, {&creation}))
    {
        return creation.getValue(); // Asegúrate de convertir a `time_t` si es necesario
    }

    return std::numeric_limits<time_t>::max();
}

Json::Value IdentityManager_DB::Accounts_DB::searchFields(const json &dataTablesFilters)
{
    Json::Value ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    // DataTables:
    ret["draw"] = dataTablesFilters["draw"];

    uint64_t offset = JSON_ASUINT64(dataTablesFilters, "start", 0);
    uint64_t limit = JSON_ASUINT64(dataTablesFilters, "length", 0);

    std::string orderByStatement;

    // Manejo de ordenamiento (order)
    const Json::Value &orderArray = dataTablesFilters["order"];
    if (JSON_ISARRAY_D(orderArray) && orderArray.size() > 0)
    {
        const Json::Value &orderArrayElement = orderArray[0];
        std::string columnName = getColumnNameFromColumnPos(dataTablesFilters, JSON_ASUINT(orderArrayElement, "column", 0));
        std::string dir = JSON_ASSTRING(orderArrayElement, "dir", "desc");

        auto isValidField = [](const std::string &c) -> bool
        {
            static const std::vector<std::string> validFields = {"fieldName", "fieldDescription", "fieldType", "isOptionalField", "isUnique"};
            return std::find(validFields.begin(), validFields.end(), c) != validFields.end();
        };

        if (isValidField(columnName))
        {
            orderByStatement = "`" + columnName + "` ";
            orderByStatement += (dir == "desc") ? "DESC" : "ASC";
        }
    }

    // Extract the search value from dataTablesFilters
    std::string searchValue = JSON_ASSTRING(dataTablesFilters["search"], "value", "");
    std::string whereFilters;

    // Build the SQL query with WHERE clause for DataTables search
    std::string sqlQueryStr = R"(
    SELECT
        fieldName,
        fieldDescription,
        fieldType,
        isOptionalField,
        isUnique
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
        Abstract::BOOL isOptionalField, isUnique;
        auto i = _parent->m_sqlConnector->qSelectWithFilters(sqlQueryStr, whereFilters, {{":SEARCHWORDS", MAKE_VAR(STRING, searchValue)}},
                                                             {&fieldName, &fieldDescription, &fieldType, &isOptionalField, &isUnique},
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

Json::Value IdentityManager_DB::Accounts_DB::searchAccounts(const json &dataTablesFilters)
{
    Json::Value ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    // DataTables:
    ret["draw"] = dataTablesFilters["draw"];

    uint64_t offset = JSON_ASUINT64(dataTablesFilters, "start", 0);
    uint64_t limit = JSON_ASUINT64(dataTablesFilters, "length", 0);

    std::string orderByStatement;

    // Manejo de ordenamiento (order)
    const Json::Value &orderArray = dataTablesFilters["order"];
    if (JSON_ISARRAY_D(orderArray) && orderArray.size() > 0)
    {
        const Json::Value &orderArrayElement = orderArray[0];
        std::string columnName = getColumnNameFromColumnPos(dataTablesFilters, JSON_ASUINT(orderArrayElement, "column", 0));
        std::string dir = JSON_ASSTRING(orderArrayElement, "dir", "desc");

        auto isValidField = [](const std::string &c) -> bool
        {
            static const std::vector<std::string> validFields = {"accountName", "creation",  "expiration", "lastLogin",          "lastChange",
                                                                 "isAdmin",     "isEnabled", "isBlocked",  "isAccountConfirmed", "creator"};
            return std::find(validFields.begin(), validFields.end(), c) != validFields.end();
        };

        if (isValidField(columnName))
        {
            orderByStatement = "`" + columnName + "` ";
            orderByStatement += (dir == "desc") ? "DESC" : "ASC";
        }
    }

    // Extract the search value from dataTablesFilters
    std::string searchValue = JSON_ASSTRING(dataTablesFilters["search"], "value", "");
    std::string whereFilters;

    // Build the SQL query with WHERE clause for DataTables search
    std::string sqlQueryStr = R"(
        SELECT
            iam.accounts.accountName as accountName,
            iam.accounts.creation as creation,
            iam.accounts.expiration as expiration,
            logs.accountsLastAccess.lastLogin as lastLogin,
            iam.accountCredentials.lastChange as lastChange,
            iam.accounts.isAdmin as isAdmin,
            iam.accounts.isEnabled as isEnabled,
            iam.accounts.isBlocked as isBlocked,
            iam.accounts.isAccountConfirmed as isAccountConfirmed,
            iam.accounts.creator as creator
        FROM iam.accounts
        LEFT JOIN logs.accountsLastAccess
            ON logs.accountsLastAccess.f_accountName = iam.accounts.accountName
        LEFT JOIN iam.accountCredentials
            ON iam.accountCredentials.f_accountName = iam.accounts.accountName
            AND iam.accountCredentials.f_AuthSlotId = 1
        )";

    // Add WHERE clause for search term if provided
    if (!searchValue.empty())
    {
        searchValue = "%" + searchValue + "%";
        whereFilters += "accountName LIKE :SEARCHWORDS";
    }

    {
        Abstract::STRING accountName;
        Abstract::DATETIME creation, expiration, lastLogin, lastChange;
        Abstract::BOOL isAdmin, isEnabled, isBlocked, isAccountConfirmed;
        Abstract::STRING creator;

        auto i = _parent->m_sqlConnector->qSelectWithFilters(sqlQueryStr, whereFilters, {{":SEARCHWORDS", MAKE_VAR(STRING, searchValue)}},
                                                             {&accountName, &creation, &expiration, &lastLogin, &lastChange, &isAdmin, &isEnabled, &isBlocked, &isAccountConfirmed, &creator},
                                                             orderByStatement, // Order by
                                                             limit,            // LIMIT
                                                             offset            // OFFSET
        );

        while (i && i->isSuccessful() && i->step())
        {
            Json::Value row;

            // accountName
            row["accountName"] = accountName.toJSON();
            // creation
            row["creation"] = creation.toJSON();
            // expiration
            row["expiration"] = expiration.toJSON();
            // lastAccess
            row["lastAccess"] = lastLogin.toJSON();
            // lastChange
            row["lastPasswordChange"] = lastChange.toJSON();

            row["roles"] = "";

            row["applications"] = "";

            row["DT_RowData"]["isAdmin"] = isAdmin.getValue();
            row["DT_RowData"]["isEnabled"] = isEnabled.getValue();
            row["DT_RowData"]["isBlocked"] = isBlocked.getValue();
            row["DT_RowData"]["isAccountConfirmed"] = isAccountConfirmed.getValue();
            row["DT_RowData"]["creator"] = creator.getValue();

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

std::set<std::string> IdentityManager_DB::Accounts_DB::listAccounts()
{
    std::set<std::string> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING accountName;
    auto i = _parent->m_sqlConnector->qSelect("SELECT `accountName` FROM iam.accounts;", {}, {&accountName});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert(accountName.getValue());
    }

    return ret;
}

std::set<ApplicationRole> IdentityManager_DB::Accounts_DB::getAccountRoles(const std::string &appName, const std::string &accountName, bool lock)
{
    std::set<ApplicationRole> ret;
    if (lock)
        _parent->m_mutex.lockShared();

    {
        Abstract::STRING role;
        Abstract::STRING roleDescription;
        auto i = _parent->m_sqlConnector->qSelect("SELECT ar.f_roleName, r.roleDescription FROM iam.applicationRolesAccounts ar LEFT JOIN iam.applicationRoles r ON "
                                                  "ar.f_roleName = r.roleName AND ar.f_appName = r.f_appName WHERE ar.f_accountName=:accountName AND ar.f_appName = :appName;",
                                                  {{":accountName", MAKE_VAR(STRING, accountName)}, {":appName", MAKE_VAR(STRING, appName)}}, {&role, &roleDescription});
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
        _parent->m_mutex.unlockShared();

    return ret;
}

bool IdentityManager_DB::Accounts_DB::hasAdminAccount()
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    return _parent->m_sqlConnector->qSelectSingleRow("SELECT `isAdmin` FROM iam.accounts WHERE `isAdmin`=:admin LIMIT 1;", {{":admin", MAKE_VAR(BOOL, true)}}, {});
}

bool IdentityManager_DB::Accounts_DB::isThereAnotherAdmin(const std::string &accountName)
{
    // Check if there is any admin acount beside this "to be deleted" account...
    return _parent->m_sqlConnector
        ->qSelectSingleRow("SELECT `isEnabled` FROM iam.accounts WHERE `accountName`!=:accountName and "
                           "`isAdmin`=:admin and `isEnabled`=:enabled and `isAccountConfirmed`=:confirmed LIMIT 1;",
                           {{":accountName", MAKE_VAR(STRING, accountName)}, {":admin", MAKE_VAR(BOOL, true)}, {":enabled", MAKE_VAR(BOOL, true)}, {":confirmed", MAKE_VAR(BOOL, true)}}, {});
}

int32_t IdentityManager_DB::Accounts_DB::getAccountBlockTokenNoRenew(const std::string &accountName, std::string &token)
{
    auto authenticationPolicy = _parent->authController->getAuthenticationPolicy();
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING blockToken;
    Abstract::DATETIME lastAccess;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `blockToken`,`lastAccess` FROM iam.accountsBlockToken WHERE `f_accountName`=:accountName;", {{":accountName", MAKE_VAR(STRING, accountName)}},
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

void IdentityManager_DB::Accounts_DB::removeBlockToken(const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountsBlockToken WHERE `f_accountName`=:accountName;", {{":accountName", MAKE_VAR(STRING, accountName)}});
}

void IdentityManager_DB::Accounts_DB::updateOrCreateBlockToken(const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    if (!_parent->m_sqlConnector->qExecuteEx("UPDATE iam.accountsBlockToken SET `lastAccess`=CURRENT_TIMESTAMP WHERE `f_accountName`=:accountName;", {{":accountName", MAKE_VAR(STRING, accountName)}}))
    {
        _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.accountsBlockToken (`f_accountName`,`blockToken`) VALUES(:account,:blockToken);",
                                            {{":account", MAKE_VAR(STRING, accountName)}, {":blockToken", MAKE_VAR(STRING, _parent->authController->genRandomConfirmationToken())}});
    }
}

std::string IdentityManager_DB::Accounts_DB::getAccountBlockToken(const std::string &accountName)
{
    std::string token;
    int32_t i = getAccountBlockTokenNoRenew(accountName, token);
    if (i == 0)
    {
        // Update the registry last access here...
        updateOrCreateBlockToken(accountName);
        return token;
    }
    else if (i == -1)
    {
        // Expired, remove the previous one create a new one...
        removeBlockToken(accountName);
        updateOrCreateBlockToken(accountName);
    }
    else if (i == -2)
    {
        // No registry... Create a new one...
        updateOrCreateBlockToken(accountName);
    }
    i = getAccountBlockTokenNoRenew(accountName, token);
    if (i == 0)
    {
        return token;
    }

    return "";
}

bool IdentityManager_DB::Accounts_DB::blockAccountUsingToken(const std::string &accountName, const std::string &blockToken)
{
    std::string dbBlockToken;
    if (getAccountBlockTokenNoRenew(accountName, dbBlockToken) == 0)
    {
        if (dbBlockToken == blockToken)
        {
            // everything in place to block this account:
            return disableAccount(accountName);
        }
    }
    return false;
}

bool IdentityManager_DB::Accounts_DB::addAccountDetailField(const std::string &fieldName, const AccountDetailField &details)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (!_parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.accountDetailFields (`fieldName`, `fieldDescription`, `fieldType`, `isOptionalField`, `isUnique`, `jsonExtendedAttribs`)"
                                             " VALUES (:fieldName, :fieldDescription, :fieldType, :isOptionalField, :isUnique, :jsonExtendedAttribs);",
                                             {{":fieldName", MAKE_VAR(STRING, fieldName)},
                                              {":fieldDescription", MAKE_VAR(STRING, details.description)},
                                              {":fieldType", MAKE_VAR(STRING, details.fieldType)},
                                              {":isOptionalField", MAKE_VAR(BOOL, details.isOptionalField)},
                                              {":isUnique", MAKE_VAR(BOOL, details.isUnique)},
                                              {":jsonExtendedAttribs", MAKE_VAR(STRING, details.extendedAttributes.toStyledString())}}))
    {
        return false;
    }

    return true;
}

bool IdentityManager_DB::Accounts_DB::updateAccountDetailField(const std::string &fieldName, const AccountDetailField &details)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (!_parent->m_sqlConnector->qExecuteEx("UPDATE iam.accountDetailFields SET `fieldDescription`=:fieldDescription, `fieldType`=:fieldType, `isOptionalField`=:isOptionalField, "
                                             "`isUnique`=:isUnique, `jsonExtendedAttribs`=:jsonExtendedAttribs WHERE `fieldName`=:fieldName;",
                                             {{":fieldName", MAKE_VAR(STRING, fieldName)},
                                              {":fieldDescription", MAKE_VAR(STRING, details.description)},
                                              {":fieldType", MAKE_VAR(STRING, details.fieldType)},
                                              {":isOptionalField", MAKE_VAR(BOOL, details.isOptionalField)},
                                              {":isUnique", MAKE_VAR(BOOL, details.isUnique)},
                                              {":jsonExtendedAttribs", MAKE_VAR(STRING, details.extendedAttributes.toStyledString())}}))
    {
        return false;
    }

    return true;
}

bool IdentityManager_DB::Accounts_DB::removeAccountDetailField(const std::string &fieldName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (!_parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountDetailFields WHERE `fieldName` = :fieldName;", {{":fieldName", MAKE_VAR(STRING, fieldName)}}))
    {
        return false;
    }

    return true;
}

std::map<std::string, AccountDetailField> IdentityManager_DB::Accounts_DB::listAccountDetailFields()
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::map<std::string, AccountDetailField> fieldMap;

    // Variables para capturar valores de la base de datos
    Abstract::STRING fieldName, fieldDescription, fieldType;
    Abstract::BOOL isOptionalField, isUnique;
    Abstract::STRING jsonExtendedAttribsText;

    auto i = _parent->m_sqlConnector->qSelect("SELECT `fieldName`, `fieldDescription`, `fieldType`, `isOptionalField`, `isUnique`, `jsonExtendedAttribs` FROM `iam`.`accountDetailFields`;", {},
                                              {&fieldName, &fieldDescription, &fieldType, &isOptionalField, &isUnique, &jsonExtendedAttribsText});

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
    Abstract::BOOL isOptionalField, isUnique;
    Abstract::STRING jsonExtendedAttribsText;

    if (_parent->m_sqlConnector
            ->qSelectSingleRow("SELECT `fieldDescription`,`fieldType`,`isOptionalField`, `isUnique`,`jsonExtendedAttribs` FROM `iam`.`accountDetailFields` WHERE `fieldName` = :fieldName;",
                               {{":fieldName", MAKE_VAR(STRING, fieldName)}}, {&fieldDescription, &fieldType, &isOptionalField, &isUnique, &jsonExtendedAttribsText}))
    {
        Json::Value r;
        Json::Reader().parse(jsonExtendedAttribsText.getValue(), r);

        field.description = fieldDescription.getValue();
        field.fieldType = fieldType.getValue();
        field.isOptionalField = isOptionalField.getValue();
        field.isUnique = isUnique.getValue();
        field.extendedAttributes = r;

        return field;
    }

    // Return empty optional if not found
    return std::nullopt;
}

bool IdentityManager_DB::Accounts_DB::changeAccountDetails(const std::string &accountName, const std::map<std::string, std::string> &fieldsValues, bool resetAllValues)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (resetAllValues)
    {
        // Delete all values for the specified account
        _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountDetailValues WHERE `f_accountName` = :accountName;", {{":accountName", MAKE_VAR(STRING, accountName)}});
    }
    else
    {
        // Delete only specified fields for the account
        for (const auto &field : fieldsValues)
        {
            _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountDetailValues WHERE `f_accountName` = :accountName AND `f_fieldName` = :fieldName;",
                                                {{":accountName", MAKE_VAR(STRING, accountName)}, {":fieldName", MAKE_VAR(STRING, field.first)}});
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
                return false;
            }
        }

        // Inserting the validated value
        if (!_parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.accountDetailValues (`f_accountName`, `f_fieldName`, `value`) VALUES(:accountName, :fieldName, :value);",
                                                 {{":accountName", MAKE_VAR(STRING, accountName)}, {":fieldName", MAKE_VAR(STRING, field.first)}, {":value", MAKE_VAR(STRING, field.second)}}))
        {
            return false;
        }
    }

    return true;
}

bool IdentityManager_DB::Accounts_DB::removeAccountDetail(const std::string &accountName, const std::string &fieldName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountDetailValues WHERE `f_accountName` = :accountName AND `f_fieldName` = :fieldName;",
                                               {{":accountName", MAKE_VAR(STRING, accountName)}, {":fieldName", MAKE_VAR(STRING, fieldName)}});
}

bool IdentityManager_DB::Accounts_DB::updateAccountDetailFieldValues(const std::string &accountName, const std::list<AccountDetailFieldValue> &fieldValues)
{
    std::map<std::string, AccountDetailField> fields = listAccountDetailFields();

    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Primero borramos todos los datos de campos para ese usuario
    _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountDetailValues WHERE `f_accountName` = :accountName;", {{":accountName", MAKE_VAR(STRING, accountName)}});

    for (const auto &fieldValue : fieldValues)
    {
        if (fields.find(fieldValue.name) != fields.end() && fieldValue.value.has_value())
        {
            std::string regexpValidator = fields[fieldValue.name].getRegexpValidatorText();
            std::string value = fieldValue.value.value();
            try
            {
                boost::regex regExp(regexpValidator);
                if (!boost::regex_match(value, regExp))
                {
                    return false;
                }
            }
            catch (const boost::regex_error &)
            {
                // if not possible, continue with the rest.
            }
        }
    }

    // Luego insertamos los nuevos datos
    for (const auto &fieldValue : fieldValues)
    {
        if (fieldValue.value.has_value())
        {
            if (!_parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.accountDetailValues (`f_accountName`, `f_fieldName`, `value`) VALUES(:accountName, :fieldName, :value);",
                                                     {{":accountName", MAKE_VAR(STRING, accountName)},
                                                      {":fieldName", MAKE_VAR(STRING, fieldValue.name)},
                                                      {":value", MAKE_VAR(STRING, fieldValue.value.value())}}))
            {
                return false;
            }
        }
    }

    return true;
}

std::map<std::string, AccountDetailFieldValue> IdentityManager_DB::Accounts_DB::getAccountDetailFieldValues(const std::string &accountName, const AccountDetailsToShow &detailsToShow)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::map<std::string, AccountDetailFieldValue> detailValues;

    Abstract::STRING fieldName, fieldDescription, fieldType, jsonExtendedAttribsText, value;

    std::string query = R"(
                            SELECT vadf.fieldName, vadf.fieldDescription, vadf.fieldType, vadf.jsonExtendedAttribs, vadv.value
                            FROM iam.accountDetailFields vadf
                            LEFT JOIN iam.accountDetailValues vadv ON vadf.fieldName = vadv.f_fieldName
                            AND vadv.f_accountName = :accountName
                        )";

    auto i = _parent->m_sqlConnector->qSelect(query, {{":accountName", MAKE_VAR(STRING, accountName)}}, {&fieldName, &fieldDescription, &fieldType, &jsonExtendedAttribsText, &value});

    if (i && i->isSuccessful())
    {
        while (i->step())
        {
            Json::Value extendedAttributes;
            Json::Reader().parse(jsonExtendedAttribsText.getValue(), extendedAttributes);

            bool visible = false;

            switch (detailsToShow)
            {
            case ACCOUNT_DETAILS_SEARCH:
                visible = JSON_ASBOOL(extendedAttributes["visibility"], "includeInSearch", false);
                break;
            case ACCOUNT_DETAILS_COLUMNVIEW:
                visible = JSON_ASBOOL(extendedAttributes["visibility"], "includeInColumnView", false);
                break;
            case ACCOUNT_DETAILS_TOKEN:
                visible = JSON_ASBOOL(extendedAttributes["visibility"], "includeInToken", false);
                break;
            case ACCOUNT_DETAILS_APISYNC:
                visible = JSON_ASBOOL(extendedAttributes["visibility"], "includeInAPISync", false);
                break;
            case ACCOUNT_DETAILS_ALL:
            default:
                // no additional filter for ALL
                visible = true;
                break;
            }

            if (visible)
            {
                AccountDetailFieldValue field;
                field.name = fieldName.getValue();
                field.description = fieldDescription.getValue();
                field.fieldType = fieldType.getValue();
                field.fieldRegexpValidator = JSON_ASSTRING(extendedAttributes["behavior"], "regexpValidator", "");

                if (value.isNull())
                    field.value = std::nullopt;
                else
                    field.value = value.getValue();

                detailValues[fieldName.getValue()] = field;
            }
        }
    }

    return detailValues;
}
