#include "Mantids30/Helpers/json.h"
#include "identitymanager_db.h"
#include <Mantids30/Helpers/encoders.h>



#include <Mantids30/Helpers/datatables.h>
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
using namespace Mantids30::Helpers;
using namespace Mantids30;

bool IdentityManager_DB::Applications_DB::createApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &applicationDescription,
                                                            const std::string &appURL, const std::string &apiKey, const std::string &creatorAccountUUID, const ApplicationAttributes &appAttributes,
                                                            bool initializeDefaultValues)
{
    bool tokenInsertSuccess;
    {
        std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);

        // Insert into iam.applications.
        bool appInsertSuccess = _parent->m_sqlConnector
                                    ->qExecuteEx("INSERT INTO iam.applications (`appName`, `f_appCreatorAccountUUID`, `appDescription`, `apiKey`, `appAttributesJSON`) VALUES (:appName, "
                                                 ":appCreatorAccountUUID, :description, :apiKey, :appAttributesJSON);",
                                                 {{":appName", MAKE_VAR(STRING, appName)},
                                                  {":appCreatorAccountUUID", MAKE_VAR(STRING, creatorAccountUUID)},
                                                  {":description", MAKE_VAR(STRING, applicationDescription)},
                                                  {":apiKey", MAKE_VAR(STRING, Encoders::encodeToBase64Obf(apiKey))},
                                                  {":appAttributesJSON", MAKE_VAR(STRING, appAttributes.toJSON().toStyledString())}});

        // If the insertion is successful, insert another row default values into iam.applicationsAuthSettings.
        if (appInsertSuccess)
        {
            std::string randomSecret = Mantids30::Helpers::Random::createRandomString(64);
            tokenInsertSuccess = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.applicationsAuthSettings (`f_appName`, `accessTokenSigningKey`, `accessTokenValidationKey`) "
                                                                     "VALUES (:appName, :signingKey, :validationKey);",
                                                                     {{":appName", MAKE_VAR(STRING, appName)},
                                                                      {":signingKey", MAKE_VAR(STRING, Helpers::Encoders::encodeToBase64Obf(randomSecret, 0x8A376C54D999F187))},
                                                                      {":validationKey", MAKE_VAR(STRING, Helpers::Encoders::encodeToBase64Obf(randomSecret, 0x8A376C54D999F187))}});
        }
        else
        {
            return false;
        }
    }

    if (tokenInsertSuccess && initializeDefaultValues)
    {
        if (!setApplicationWebLoginCallbackURI(clientDetails, performedBy, appName, appURL + "/auth/api/v1/callback"))
        {
            return false;
        }
        if (!addWebLoginOriginURLToApplication(clientDetails, performedBy, appName, appURL))
        {
            return false;
        }
        if (!addWebLoginAllowedRedirectURIToApplication(clientDetails, performedBy, appName, appURL + "/"))
        {
            return false;
        }
        if (!updateWebLoginDefaultRedirectURIForApplication(clientDetails, performedBy, appName, appURL + "/"))
        {
            return false;
        }
    }

    if (tokenInsertSuccess)
    {
        _parent->logSecurityEventOnApplications(appName, SecurityEventAction::CREATE, "Created application", performedBy, clientDetails);
    }

    return tokenInsertSuccess;
}

bool IdentityManager_DB::Applications_DB::removeApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    bool result = _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.applications WHERE `appName`=:appName;", {{":appName", MAKE_VAR(STRING, appName)}});
    if (result)
    {
        _parent->logSecurityEventOnApplications(appName, SecurityEventAction::DELETE, "Removed application", performedBy, clientDetails);
    }
    return result;
}

bool IdentityManager_DB::Applications_DB::doesApplicationExist(const std::string &appName)
{
    bool ret = false;
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);
    ret = _parent->m_sqlConnector->qSelectSingleRow("SELECT `appDescription` FROM iam.applications WHERE `appName`=:appName LIMIT 1;", {{":appName", MAKE_VAR(STRING, appName)}}, {});
    return ret;
}

bool IdentityManager_DB::Applications_DB::updateApplicationAttributes(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName,
                                                                      const ApplicationAttributes &appAttributes)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    bool result = _parent->m_sqlConnector->qExecuteEx("UPDATE iam.applications SET "
                                                      "`appAttributesJSON`=:appAttributesJSON WHERE `appName`=:appName;",
                                                      {{":appName", MAKE_VAR(STRING, appName)}, {":appAttributesJSON", MAKE_VAR(STRING, appAttributes.toJSON().toStyledString())}});
    if (result)
    {
        _parent->logSecurityEventOnApplications(appName, SecurityEventAction::UPDATE, "Updated attributes: " + appAttributes.toString(), performedBy, clientDetails);
    }
    return result;
}

std::optional<IdentityManager::Applications::ApplicationAttributes> IdentityManager_DB::Applications_DB::getApplicationAttributes(const std::string &appName)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);
    Abstract::STRING appAttributesJSON;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `appAttributesJSON` "
                                                  "FROM iam.applications WHERE `appName`=:appName LIMIT 1;",
                                                  {{":appName", MAKE_VAR(STRING, appName)}},
                                                  {&appAttributesJSON}))
    {
        IdentityManager::Applications::ApplicationAttributes attrs;
        Json::Value root;
        Helpers::JSON::JSONReader2 reader;
        reader.parse(appAttributesJSON.getValue(), root);
        attrs.fromJSON(root);
        return attrs;
    }
    return std::nullopt;
}

std::string IdentityManager_DB::Applications_DB::getApplicationDescription(const std::string &appName)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::STRING description;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `appDescription` FROM iam.applications WHERE `appName`=:appName LIMIT 1;", {{":appName", MAKE_VAR(STRING, appName)}}, {&description}))
    {
        return description.getValue();
    }
    return "";
}

std::string IdentityManager_DB::Applications_DB::getApplicationAPIKey(const std::string &appName)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::STRING apiKey;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `apiKey` FROM iam.applications WHERE `appName`=:appName LIMIT 1;", {{":appName", MAKE_VAR(STRING, appName)}}, {&apiKey}))
    {
        auto ret = Encoders::decodeFromBase64Obf(apiKey.getValue());
        return ret;
    }
    return "";
}

bool IdentityManager_DB::Applications_DB::updateApplicationAPIKey(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &apiKey)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    bool result = _parent->m_sqlConnector->qExecuteEx("UPDATE iam.applications SET `apiKey`=:apiKey WHERE `appName`=:appName;",
                                                      {{":appName", MAKE_VAR(STRING, appName)}, {":apiKey", MAKE_VAR(STRING, Encoders::encodeToBase64Obf(apiKey))}});
    if (result)
    {
        _parent->logSecurityEventOnApplications(appName, SecurityEventAction::UPDATE, "Updated API key", performedBy, clientDetails);
    }
    return result;
}

bool IdentityManager_DB::Applications_DB::updateApplicationDescription(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName,
                                                                       const std::string &applicationDescription)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    bool result = _parent->m_sqlConnector->qExecuteEx("UPDATE iam.applications SET `appDescription`=:description WHERE `appName`=:appName;",
                                                      {{":appName", MAKE_VAR(STRING, appName)}, {":description", MAKE_VAR(STRING, applicationDescription)}});
    if (result)
    {
        _parent->logSecurityEventOnApplications(appName, SecurityEventAction::UPDATE, "Updated description", performedBy, clientDetails);
    }
    return result;
}

std::string IdentityManager_DB::Applications_DB::getApplicationNameByAPIKey(const std::string &apiKey)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);
    Abstract::STRING appName;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `appName` FROM iam.applications WHERE `apiKey` = :encodedApiKey LIMIT 1;",
                                                  {
                                                      {":encodedApiKey", MAKE_VAR(STRING, Encoders::encodeToBase64Obf(apiKey))},
                                                  },
                                                  {&appName}))
    {
        return appName.getValue();
    }
    return "";
}

std::set<std::string> IdentityManager_DB::Applications_DB::listApplications()
{
    std::set<std::string> ret;
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::STRING sAppName;
    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `appName` FROM iam.applications;", {}, {&sAppName});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert(sAppName.getValue());
    }
    return ret;
}

bool IdentityManager_DB::Applications_DB::isApplicationAdmin(const std::string &appName, const std::string &accountUUID)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::BOOL isAppAdmin;
    if (!_parent->m_sqlConnector->qSelectSingleRow("SELECT `isAppAdmin` FROM iam.applicationAccounts WHERE "
                                                   "`f_accountUUID`=:accountUUID AND `f_appName`=:appName;",
                                                   {{":appName", MAKE_VAR(STRING, appName)}, {":accountUUID", MAKE_VAR(STRING, accountUUID)}},
                                                   {&isAppAdmin}))
    {
        return false;
    }

    return !isAppAdmin.isNull() && isAppAdmin.getValue();
}

bool IdentityManager_DB::Applications_DB::validateApplicationAccount(const std::string &appName, const std::string &accountUUID)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    return _parent->m_sqlConnector->qSelectSingleRow("SELECT `f_appName` FROM iam.applicationAccounts WHERE `f_accountUUID`=:accountUUID AND `f_appName`=:appName;",
                                                     {{":appName", MAKE_VAR(STRING, appName)}, {":accountUUID", MAKE_VAR(STRING, accountUUID)}},
                                                     {});
}
std::set<std::string> IdentityManager_DB::Applications_DB::listApplicationAdmins(const std::string &appName)
{
    std::set<std::string> ret;
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::STRING accountUUID;
    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `f_accountUUID` FROM iam.applicationAccounts WHERE `f_appName`=:appName AND `isAppAdmin`='1';",
                                                                {{":appName", MAKE_VAR(STRING, appName)}},
                                                                {&accountUUID});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert(accountUUID.getValue());
    }

    return ret;
}

std::set<std::string> IdentityManager_DB::Applications_DB::listApplicationAccounts(const std::string &appName)
{
    std::set<std::string> ret;
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::STRING accountUUID;
    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `f_accountUUID` FROM iam.applicationAccounts WHERE `f_appName`=:appName;",
                                                                {{":appName", MAKE_VAR(STRING, appName)}},
                                                                {&accountUUID});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert(accountUUID.getValue());
    }

    return ret;
}

std::set<std::string> IdentityManager_DB::Applications_DB::listAccountApplications(const std::string &accountUUID)
{
    std::set<std::string> ret;
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::STRING applicationName;
    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `f_appName` FROM iam.applicationAccounts WHERE `f_accountUUID`=:accountUUID;",
                                                                {{":accountUUID", MAKE_VAR(STRING, accountUUID)}},
                                                                {&applicationName});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert(applicationName.getValue());
    }

    return ret;
}

bool IdentityManager_DB::Applications_DB::_addAccountToApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &accountUUID)
{
    bool result = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.applicationAccounts (`f_accountUUID`,`f_appName`) VALUES(:accountUUID,:appName);",
                                                      {{":appName", MAKE_VAR(STRING, appName)}, {":accountUUID", MAKE_VAR(STRING, accountUUID)}});
    if (result)
    {
        _parent->logSecurityEventOnApplications(appName, SecurityEventAction::ASSIGN_ACCOUNT, "Assigned account '" + accountUUID + "'", performedBy, clientDetails);
    }
    return result;
}

bool IdentityManager_DB::Applications_DB::addAccountToApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &accountUUID)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    return _addAccountToApplication(clientDetails, performedBy, appName, accountUUID);
}

bool IdentityManager_DB::Applications_DB::removeAccountFromApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &accountUUID)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);

    bool ret = _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.applicationAccounts WHERE `f_appName`=:appName AND `f_accountUUID`=:accountUUID;",
                                                   {{":appName", MAKE_VAR(STRING, appName)}, {":accountUUID", MAKE_VAR(STRING, accountUUID)}});
    if (ret)
    {
        _parent->logSecurityEventOnApplications(appName, SecurityEventAction::REVOKE_ACCOUNT, "Revoked account '" + accountUUID + "'", performedBy, clientDetails);
    }
    return ret;
}

bool IdentityManager_DB::Applications_DB::_setAccountAsApplicationAdmin(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &accountUUID,
                                                                        bool isAppAdmin)
{
    bool result = _parent->m_sqlConnector->qExecuteEx("UPDATE iam.applicationAccounts SET `isAppAdmin`=:isAppAdmin WHERE `f_accountUUID`=:accountUUID AND `f_appName`=:appName;",
                                                      {{":appName", MAKE_VAR(STRING, appName)}, {":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":isAppAdmin", MAKE_VAR(BOOL, isAppAdmin)}});
    if (result)
    {
        _parent->logSecurityEventOnApplications(appName, SecurityEventAction::UPDATE, "Set account '" + accountUUID + "' as admin=" + std::to_string(isAppAdmin), performedBy, clientDetails);
    }
    return result;
}

bool IdentityManager_DB::Applications_DB::setAccountAsApplicationAdmin(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &accountUUID,
                                                                       bool isAppAdmin)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    return _setAccountAsApplicationAdmin(clientDetails, performedBy, appName, accountUUID, isAppAdmin);
}

Json::Value IdentityManager_DB::Applications_DB::searchApplications(const Json::Value &dataTablesFilters)
{
    Json::Value ret;
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

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
        SELECT `appName`, `f_appCreatorAccountUUID`, `appDescription`,
            (SELECT COUNT(*) FROM iam.applicationAccounts WHERE `f_appName` = iam.applications.`appName`) AS `registeredAccounts`
        FROM iam.applications
        )";

    // Add WHERE clause for search term if provided
    if (!searchValue.empty())
    {
        searchValue = "%" + searchValue + "%";
        whereFilters += "appName LIKE :SEARCHWORDS OR appDescription LIKE :SEARCHWORDS OR f_appCreatorAccountUUID LIKE :SEARCHWORDS";
    }

    {
        Abstract::STRING appName, appCreatorAccountUUID, appDescription;
        Abstract::INT32 registeredAccounts;
        std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelectWithFilters(sqlQueryStr,
                                                                               whereFilters,
                                                                               {{":SEARCHWORDS", MAKE_VAR(STRING, searchValue)}},
                                                                               {&appName, &appCreatorAccountUUID, &appDescription, &registeredAccounts},
                                                                               orderByStatement, // Order by
                                                                               limit,            // LIMIT
                                                                               offset            // OFFSET
        );

        while (i && i->isSuccessful() && i->step())
        {
            Json::Value row;

            // appName
            row["appName"] = appName.toString();
            // appCreatorAccountUUID
            row["DT_RowData"]["appCreatorAccountUUID"] = appCreatorAccountUUID.toString();
            // appDescription
            row["appDescription"] = appDescription.toString();
            // registeredAccounts
            row["registeredAccounts"] = registeredAccounts.getValue();

            ret["data"].append(row);
        }

        if (i)
        {
            ret["recordsTotal"] = i->getTotalRecordsCount();
            ret["recordsFiltered"] = i->getFilteredRecordsCount();
        }
    }

    // Now fill creator displayName for each application (after the query scope ended to avoid DB blocking)
    for (Json::Value &row : ret["data"])
    {
        std::string creatorAccountUUID = row["DT_RowData"]["appCreatorAccountUUID"].asString();
        if (!creatorAccountUUID.empty() && creatorAccountUUID != "00000000-0000-4000-8000-000000000000")
        {
            row["DT_RowData"]["appCreatorDisplayName"] = _parent->accounts->getAccountDisplayName(creatorAccountUUID);
        }
        else
        {
            row["DT_RowData"]["appCreatorDisplayName"] = "SYSTEM";
        }
    }

    return ret;
}

std::vector<AccountApplicationInfo> IdentityManager_DB::Applications_DB::listAccountApplicationsFullInfo(const std::string &accountUUID)
{
    std::vector<AccountApplicationInfo> ret;
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    // Query 1: Obtener apps basicas con JOIN
    {
        Abstract::STRING appName, appDescription;
        Abstract::BOOL isAppAdmin;
        Abstract::DATETIME enrollmentDate;

        std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT a.`f_appName`, ap.`appDescription`, a.`isAppAdmin`, a.`enrollmentDate` "
                                                                    "FROM iam.applicationAccounts a "
                                                                    "JOIN iam.applications ap ON a.`f_appName` = ap.`appName` "
                                                                    "WHERE a.`f_accountUUID` = :accountUUID;",
                                                                    {{":accountUUID", MAKE_VAR(STRING, accountUUID)}},
                                                                    {&appName, &appDescription, &isAppAdmin, &enrollmentDate});

        while (i && i->isSuccessful() && i->step())
        {
            AccountApplicationInfo info;
            info.appName = appName.getValue();
            info.appDescription = appDescription.getValue();
            info.isAppAdmin = isAppAdmin.getValue();
            info.enrollmentDate = enrollmentDate.getValue();

            ret.push_back(info);
        }
    }

    for (AccountApplicationInfo &info : ret)
    {
        // Query 2: Obtener roles del account en esta app
        {
            Abstract::STRING roleName;
            std::shared_ptr<Query> j = _parent->m_sqlConnector->qSelect("SELECT `f_roleName` FROM iam.applicationRolesAccounts "
                                                                        "WHERE `f_accountUUID` = :accountUUID AND `f_appName` = :appName;",
                                                                        {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":appName", MAKE_VAR(STRING, info.appName)}},
                                                                        {&roleName});

            while (j && j->isSuccessful() && j->step())
            {
                std::string currentRole = roleName.getValue();
                info.roles.insert(currentRole);
            }
        }

        for (const std::string &currentRole : info.roles)
        {
            // Query 3: Obtener scopes de este rol
            Abstract::STRING scopeId;
            std::shared_ptr<Query> k = _parent->m_sqlConnector->qSelect("SELECT `f_scopeId` FROM iam.applicationRolesScopes "
                                                                        "WHERE `f_appName` = :appName AND `f_roleName` = :roleName;",
                                                                        {{":appName", MAKE_VAR(STRING, info.appName)}, {":roleName", MAKE_VAR(STRING, currentRole)}},
                                                                        {&scopeId});

            while (k && k->isSuccessful() && k->step())
            {
                std::string scope = scopeId.getValue();
                info.allScopes.insert(scope);
            }
        }

        {
            // Query 4: Obtener scopes directos del account en esta app
            // desde iam.applicationScopeAccounts unido con iam.applicationScopes
            Abstract::STRING scopeId;
            std::shared_ptr<Query> l = _parent->m_sqlConnector->qSelect("SELECT `f_scopeId` FROM iam.applicationScopeAccounts  WHERE `f_accountUUID` = :accountUUID AND `f_appName` = :appName;",
                                                                        {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":appName", MAKE_VAR(STRING, info.appName)}},
                                                                        {&scopeId});

            while (l && l->isSuccessful() && l->step())
            {
                std::string scope = scopeId.getValue();
                info.directScopes.insert(scope);
                info.allScopes.insert(scope); // También en allScopes (unión)
            }
        }
    }

    return ret;
}

bool IdentityManager_DB::Applications_DB::addWebLoginAllowedRedirectURIToApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName,
                                                                                     const std::string &loginRedirectURI)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    bool result = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.applicationsWebLoginAllowedRedirectURIs (`f_appName`, `loginRedirectURI`) VALUES (:appName, :loginRedirectURI);",
                                                      {{":appName", MAKE_VAR(STRING, appName)}, {":loginRedirectURI", MAKE_VAR(STRING, loginRedirectURI)}});
    if (result)
    {
        _parent->logSecurityEventOnApplications(appName, SecurityEventAction::CREATE, "Added redirect URI '" + loginRedirectURI + "'", performedBy, clientDetails);
    }
    return result;
}

bool IdentityManager_DB::Applications_DB::removeWebLoginAllowedRedirectURIToApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName,
                                                                                        const std::string &loginRedirectURI)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    bool result = _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.applicationsWebLoginAllowedRedirectURIs WHERE `f_appName`=:appName AND `loginRedirectURI`=:loginRedirectURI;",
                                                      {{":appName", MAKE_VAR(STRING, appName)}, {":loginRedirectURI", MAKE_VAR(STRING, loginRedirectURI)}});
    if (result)
    {
        _parent->logSecurityEventOnApplications(appName, SecurityEventAction::DELETE, "Removed redirect URI '" + loginRedirectURI + "'", performedBy, clientDetails);
    }
    return result;
}

std::set<std::string> IdentityManager_DB::Applications_DB::listWebLoginAllowedRedirectURIsFromApplication(const std::string &appName)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::STRING loginRedirectURI;
    std::set<std::string> redirectURIs;

    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `loginRedirectURI` FROM iam.applicationsWebLoginAllowedRedirectURIs WHERE `f_appName`=:appName;",
                                                                {{":appName", MAKE_VAR(STRING, appName)}},
                                                                {&loginRedirectURI});
    while (i && i->isSuccessful() && i->step())
    {
        redirectURIs.insert(loginRedirectURI.getValue());
    }
    return redirectURIs;
}

bool IdentityManager_DB::Applications_DB::updateWebLoginDefaultRedirectURIForApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName,
                                                                                         const std::string &loginRedirectURI)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    bool result = _parent->m_sqlConnector->qExecuteEx("INSERT OR REPLACE INTO iam.applicationsWebLoginDefaultRedirectURI (`f_appName`, `f_loginRedirectURI`) VALUES (:appName, :loginRedirectURI);",
                                                      {{":appName", MAKE_VAR(STRING, appName)}, {":loginRedirectURI", MAKE_VAR(STRING, loginRedirectURI)}});
    if (result)
    {
        _parent->logSecurityEventOnApplications(appName, SecurityEventAction::UPDATE, "Set default redirect URI '" + loginRedirectURI + "'", performedBy, clientDetails);
    }
    return result;
}

std::string IdentityManager_DB::Applications_DB::getWebLoginDefaultRedirectURIForApplication(const std::string &appName)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::STRING loginRedirectURI;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `f_loginRedirectURI` FROM iam.applicationsWebLoginDefaultRedirectURI WHERE `f_appName`=:appName;",
                                                  {{":appName", MAKE_VAR(STRING, appName)}},
                                                  {&loginRedirectURI}))
    {
        return loginRedirectURI.getValue();
    }
    return "";
}

bool IdentityManager_DB::Applications_DB::setApplicationWebLoginCallbackURI(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName,
                                                                            const std::string &callbackURI)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);

    bool ret = false;

    // Delete existing callback URI for the application if it exists
    _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.applicationsLoginCallbackURI WHERE `f_appName`=:appName;", {{":appName", MAKE_VAR(STRING, appName)}});

    // Insert new callback URI
    ret = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.applicationsLoginCallbackURI (`f_appName`, `callbackURI`) VALUES (:appName, :callbackURI);",
                                              {{":appName", MAKE_VAR(STRING, appName)}, {":callbackURI", MAKE_VAR(STRING, callbackURI)}});

    if (ret)
    {
        _parent->logSecurityEventOnApplications(appName, SecurityEventAction::UPDATE, "Set callback URI '" + callbackURI + "'", performedBy, clientDetails);
    }

    return ret;
}
std::string IdentityManager_DB::Applications_DB::getApplicationCallbackURI(const std::string &appName)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::STRING callbackURI;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `callbackURI` FROM iam.applicationsLoginCallbackURI WHERE `f_appName`=:appName LIMIT 1;",
                                                  {{":appName", MAKE_VAR(STRING, appName)}},
                                                  {&callbackURI}))
    {
        return callbackURI.getValue();
    }

    // Return an empty string if no callback URI is found
    return "";
}

bool IdentityManager_DB::Applications_DB::addWebLoginOriginURLToApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &originUrl)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    bool result = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.applicationsWebLoginOrigins (`f_appName`, `originUrl`) VALUES (:appName, :originUrl);",
                                                      {{":appName", MAKE_VAR(STRING, appName)}, {":originUrl", MAKE_VAR(STRING, originUrl)}});
    if (result)
    {
        _parent->logSecurityEventOnApplications(appName, SecurityEventAction::CREATE, "Added origin URL '" + originUrl + "'", performedBy, clientDetails);
    }
    return result;
}

bool IdentityManager_DB::Applications_DB::removeWebLoginOriginURLToApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName,
                                                                               const std::string &originUrl)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    bool result = _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.applicationsWebLoginOrigins WHERE `f_appName`=:appName AND `originUrl`=:originUrl;",
                                                      {{":appName", MAKE_VAR(STRING, appName)}, {":originUrl", MAKE_VAR(STRING, originUrl)}});
    if (result)
    {
        _parent->logSecurityEventOnApplications(appName, SecurityEventAction::DELETE, "Removed origin URL '" + originUrl + "'", performedBy, clientDetails);
    }
    return result;
}

std::set<std::string> IdentityManager_DB::Applications_DB::listWebLoginOriginUrlsFromApplication(const std::string &appName)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::STRING originUrl;
    std::set<std::string> originUrls;

    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `originUrl` FROM iam.applicationsWebLoginOrigins WHERE `f_appName`=:appName;",
                                                                {{":appName", MAKE_VAR(STRING, appName)}},
                                                                {&originUrl});
    while (i && i->isSuccessful() && i->step())
    {
        originUrls.insert(originUrl.getValue());
    }
    return originUrls;
}

bool IdentityManager_DB::Applications_DB::updateAuthSettingsForApplication(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationAuthSettings &tokenInfo)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    bool result = _parent->m_sqlConnector->qExecuteEx("UPDATE iam.applicationsAuthSettings SET "
                                                      "tokenType=:tokenType, includeApplicationScopes=:includeApplicationScopes, "
                                                      "includeBasicAccountInfo=:includeBasicAccountInfo, allowRefreshTokenRenovation=:allowRefreshTokenRenovation, "
                                                      "tokensConfigJSON=:tokensConfigJSON, "
                                                      "sessionConfigJSON=:sessionConfigJSON, "
                                                      "maintainRevocationAndLogoutInfo=:maintainRevocationAndLogoutInfo WHERE f_appName=:appName;",
                                                      {{":appName", MAKE_VAR(STRING, tokenInfo.appName)},
                                                       {":tokenType", MAKE_VAR(STRING, tokenInfo.signAlgorithm)},
                                                       {":includeApplicationScopes", MAKE_VAR(BOOL, tokenInfo.includeApplicationScopes)},
                                                       {":includeBasicAccountInfo", MAKE_VAR(BOOL, tokenInfo.includeBasicAccountInfo)},
                                                       {":allowRefreshTokenRenovation", MAKE_VAR(BOOL, tokenInfo.allowRefreshTokenRenovation)},
                                                       {":allowRefreshTokenRenovation", MAKE_VAR(BOOL, tokenInfo.allowRefreshTokenRenovation)},
                                                       {":tokensConfigJSON", MAKE_VAR(STRING, tokenInfo.tokensConfiguration.toStyledString())},
                                                       {":sessionConfigJSON", MAKE_VAR(STRING, tokenInfo.sessionConfiguration.toStyledString())},
                                                       {":maintainRevocationAndLogoutInfo", MAKE_VAR(BOOL, tokenInfo.maintainRevocationAndLogoutInfo)}});
    if (result)
    {
        _parent->logSecurityEventOnApplications(tokenInfo.appName, SecurityEventAction::UPDATE, "Updated JWT token config", performedBy, clientDetails);
    }
    return result;
}

ApplicationAuthSettings IdentityManager_DB::Applications_DB::getAuthSettingsFromApplication(const std::string &appName)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    ApplicationAuthSettings tokenInfo;
    tokenInfo.appName = appName;

    // Define las variables para capturar los valores de la base de datos.
    Abstract::STRING tokenType, tokensConfigJSON, sessionConfigJSON;
    Abstract::BOOL includeApplicationScopes, includeBasicAccountInfo, maintainRevocationAndLogoutInfo, allowRefreshTokenRenovation;

    if (_parent->m_sqlConnector->qSelectSingleRow(
            "SELECT allowRefreshTokenRenovation, tokenType, "
            "includeApplicationScopes, includeBasicAccountInfo, maintainRevocationAndLogoutInfo, tokensConfigJSON, sessionConfigJSON "
            "FROM iam.applicationsAuthSettings "
            "WHERE f_appName=:appName;",
            {{":appName", MAKE_VAR(STRING, appName)}},
            {&allowRefreshTokenRenovation, &tokenType, &includeApplicationScopes, &includeBasicAccountInfo, &maintainRevocationAndLogoutInfo, &tokensConfigJSON, &sessionConfigJSON}))
    {
        tokenInfo.signAlgorithm = tokenType.getValue();
        tokenInfo.includeApplicationScopes = includeApplicationScopes.getValue();
        tokenInfo.includeBasicAccountInfo = includeBasicAccountInfo.getValue();
        tokenInfo.maintainRevocationAndLogoutInfo = maintainRevocationAndLogoutInfo.getValue();
        tokenInfo.allowRefreshTokenRenovation = allowRefreshTokenRenovation.getValue();
        tokenInfo.tokensConfiguration = Helpers::JSON::parse(tokensConfigJSON.getValue().c_str());
        tokenInfo.sessionConfiguration = Helpers::JSON::parse(sessionConfigJSON.getValue().c_str());
    }
    return tokenInfo;
}

bool IdentityManager_DB::Applications_DB::setWebLoginJWTSigningKeyForApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName,
                                                                                 const std::string &signingKey)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("UPDATE iam.applicationsAuthSettings SET accessTokenSigningKey=:signingKey WHERE f_appName=:appName;",
                                               {{":appName", MAKE_VAR(STRING, appName)}, {":signingKey", MAKE_VAR(STRING, Helpers::Encoders::encodeToBase64Obf(signingKey, 0x8A376C54D999F187))}});
}

std::string IdentityManager_DB::Applications_DB::getWebLoginJWTSigningKeyForApplication(const std::string &appName)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);
    Abstract::STRING signingKey;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT accessTokenSigningKey FROM iam.applicationsAuthSettings WHERE f_appName=:appName;",
                                                  {{":appName", MAKE_VAR(STRING, appName)}},
                                                  {&signingKey}))
    {
        // SBO... -.- (protect your .db file)
        return Helpers::Encoders::decodeFromBase64Obf(signingKey.getValue(), 0x8A376C54D999F187);
    }
    return "";
}

bool IdentityManager_DB::Applications_DB::setWebLoginJWTValidationKeyForApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName,
                                                                                    const std::string &validationKey)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("UPDATE iam.applicationsAuthSettings SET accessTokenValidationKey=:validationKey WHERE f_appName=:appName;",
                                               {{":appName", MAKE_VAR(STRING, appName)}, {":validationKey", MAKE_VAR(STRING, Helpers::Encoders::encodeToBase64Obf(validationKey, 0x8A376C54D999F187))}});
}

std::string IdentityManager_DB::Applications_DB::getWebLoginJWTValidationKeyForApplication(const std::string &appName)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);
    Abstract::STRING validationKey;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT accessTokenValidationKey FROM iam.applicationsAuthSettings WHERE f_appName=:appName;",
                                                  {{":appName", MAKE_VAR(STRING, appName)}},
                                                  {&validationKey}))
    {
        return Helpers::Encoders::decodeFromBase64Obf(validationKey.getValue(), 0x8A376C54D999F187);
    }
    return "";
}