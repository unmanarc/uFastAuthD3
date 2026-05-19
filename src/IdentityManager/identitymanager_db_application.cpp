#include "identitymanager_db.h"
#include <Mantids30/Helpers/encoders.h>

#include <Mantids30/Threads/lock_shared.h>

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
bool IdentityManager_DB::Applications_DB::addApplication(const std::string &appName, const std::string &applicationDescription, const std::string &appURL, const std::string &apiKey,
                                                         const std::string &creatorAccountName, const ApplicationAttributes &appAttributes, bool initializeDefaultValues)
{
    std::optional<uint32_t> defaultSchemeId = _parent->authController->getDefaultAuthScheme();

    if (initializeDefaultValues && !defaultSchemeId.has_value())
    {
        return false;
    }

    bool tokenInsertSuccess;
    {
        Threads::Sync::Lock_RW lock(_parent->m_mutex);

        // Insert into iam.applications.
        bool appInsertSuccess = _parent->m_sqlConnector->qExecuteEx(
            "INSERT INTO iam.applications (`appName`, `f_appCreator`, `appDescription`, `apiKey`, "
            "`canAdminModifyApplicationSecurityContext`, `canUserAutoRegister`, `appSyncEnabled`, `appSyncCanRetrieveAppAccountsList`) VALUES (:appName, "
            ":appCreator, :description, :apiKey, :canAdminModifyApplicationSecurityContext, :canUserAutoRegister, :appSyncEnabled, :appSyncCanRetrieveAppAccountsList);",
            {{":appName", MAKE_VAR(STRING, appName)},
             {":appCreator", MAKE_VAR(STRING, creatorAccountName)},
             {":description", MAKE_VAR(STRING, applicationDescription)},
             {":apiKey", MAKE_VAR(STRING, Encoders::encodeToBase64Obf(apiKey))},
             {":canAdminModifyApplicationSecurityContext", MAKE_VAR(BOOL, appAttributes.canAdminModifyApplicationSecurityContext)},
             {":canUserAutoRegister", MAKE_VAR(BOOL, appAttributes.canUserAutoRegister)},
             {":appSyncEnabled", MAKE_VAR(BOOL, appAttributes.appSyncEnabled)},
             {":appSyncCanRetrieveAppAccountsList", MAKE_VAR(BOOL, appAttributes.appSyncCanRetrieveAppAccountsList)}});

        // If the insertion is successful, insert another row default values into iam.applicationsJWTTokenConfig.
        if (appInsertSuccess)
        {
            std::string randomSecret = Mantids30::Helpers::Random::createRandomString(64);
            tokenInsertSuccess = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.applicationsJWTTokenConfig (`f_appName`, `accessTokenSigningKey`, `accessTokenValidationKey`) "
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
        if (!setApplicationWebLoginCallbackURI(appName, appURL + "/auth/api/v1/callback"))
            return false;
        if (!addWebLoginOriginURLToApplication(appName, appURL))
            return false;
        if (!addWebLoginAllowedRedirectURIToApplication(appName, appURL + "/"))
            return false;
        if (!updateWebLoginDefaultRedirectURIForApplication(appName, appURL + "/"))
            return false;
        if (!_parent->applicationActivities->setApplicationActivities(appName, {{"LOGIN", {.description = "Main Login", .parentActivity = ""}}}))
            return false;
        if (!_parent->applicationActivities->addAuthenticationSchemeToApplicationActivity(appName, "LOGIN", *defaultSchemeId))
            return false;
        if (!_parent->applicationActivities->setApplicationActivityDefaultScheme(appName, "LOGIN", *defaultSchemeId))
            return false;
    }

    return tokenInsertSuccess;
}

bool IdentityManager_DB::Applications_DB::removeApplication(const std::string &appName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.applications WHERE `appName`=:appName;", {{":appName", MAKE_VAR(STRING, appName)}});
}

bool IdentityManager_DB::Applications_DB::doesApplicationExist(const std::string &appName)
{
    bool ret = false;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    ret = _parent->m_sqlConnector->qSelectSingleRow("SELECT `appDescription` FROM iam.applications WHERE `appName`=:appName LIMIT 1;", {{":appName", MAKE_VAR(STRING, appName)}}, {});
    return ret;
}

bool IdentityManager_DB::Applications_DB::updateApplicationAttributes(const std::string &appName, const ApplicationAttributes &appAttributes)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("UPDATE iam.applications SET "
                                               "`canUserAutoRegister`=:canUserAutoRegister, `appSyncEnabled`=:appSyncEnabled, "
                                               "`appSyncCanRetrieveAppAccountsList`=:appSyncCanRetrieveAppAccountsList WHERE `appName`=:appName;",
                                               {{":appName", MAKE_VAR(STRING, appName)},
                                                {":canUserAutoRegister", MAKE_VAR(BOOL, appAttributes.canUserAutoRegister)},
                                                {":appSyncEnabled", MAKE_VAR(BOOL, appAttributes.appSyncEnabled)},
                                                {":appSyncCanRetrieveAppAccountsList", MAKE_VAR(BOOL, appAttributes.appSyncCanRetrieveAppAccountsList)}});
}

std::optional<IdentityManager::Applications::ApplicationAttributes> IdentityManager_DB::Applications_DB::getApplicationAttributes(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    Abstract::BOOL canAdminModifyApplicationSecurityContext;
    Abstract::BOOL canUserAutoRegister;
    Abstract::BOOL appSyncEnabled;
    Abstract::BOOL appSyncCanRetrieveAppAccountsList;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `canAdminModifyApplicationSecurityContext`, `canUserAutoRegister`, `appSyncEnabled`, `appSyncCanRetrieveAppAccountsList` "
                                                  "FROM iam.applications WHERE `appName`=:appName LIMIT 1;",
                                                  {{":appName", MAKE_VAR(STRING, appName)}},
                                                  {&canAdminModifyApplicationSecurityContext, &canUserAutoRegister, &appSyncEnabled, &appSyncCanRetrieveAppAccountsList}))
    {
        IdentityManager::Applications::ApplicationAttributes attrs;
        attrs.canAdminModifyApplicationSecurityContext = canAdminModifyApplicationSecurityContext.getValue();
        attrs.canUserAutoRegister = canUserAutoRegister.getValue();
        attrs.appSyncEnabled = appSyncEnabled.getValue();
        attrs.appSyncCanRetrieveAppAccountsList = appSyncCanRetrieveAppAccountsList.getValue();
        return attrs;
    }
    return std::nullopt;
}

std::string IdentityManager_DB::Applications_DB::getApplicationDescription(const std::string &appName)
{
    std::string ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING description;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `appDescription` FROM iam.applications WHERE `appName`=:appName LIMIT 1;", {{":appName", MAKE_VAR(STRING, appName)}}, {&description}))
    {
        return description.getValue();
    }
    return "";
}

std::string IdentityManager_DB::Applications_DB::getApplicationAPIKey(const std::string &appName)
{
    std::string ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING apiKey;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `apiKey` FROM iam.applications WHERE `appName`=:appName LIMIT 1;", {{":appName", MAKE_VAR(STRING, appName)}}, {&apiKey}))
    {
        return Encoders::decodeFromBase64Obf(apiKey.getValue());
    }
    return "";
}

bool IdentityManager_DB::Applications_DB::updateApplicationAPIKey(const std::string &appName, const std::string &apiKey)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("UPDATE iam.applications SET `apiKey`=:apiKey WHERE `appName`=:appName;",
                                               {{":appName", MAKE_VAR(STRING, appName)}, {":apiKey", MAKE_VAR(STRING, Encoders::encodeToBase64Obf(apiKey))}});
}

bool IdentityManager_DB::Applications_DB::updateApplicationDescription(const std::string &appName, const std::string &applicationDescription)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("UPDATE iam.applications SET `appDescription`=:description WHERE `appName`=:appName;",
                                               {{":appName", MAKE_VAR(STRING, appName)}, {":description", MAKE_VAR(STRING, applicationDescription)}});
}

std::string IdentityManager_DB::Applications_DB::getApplicationNameByAPIKey(const std::string &apiKey)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
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
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING sAppName;
    auto i = _parent->m_sqlConnector->qSelect("SELECT `appName` FROM iam.applications;", {}, {&sAppName});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert(sAppName.getValue());
    }
    return ret;
}

bool IdentityManager_DB::Applications_DB::isApplicationAdmin(const std::string &appName, const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::BOOL isAppAdmin;
    if (!_parent->m_sqlConnector->qSelectSingleRow("SELECT `isAppAdmin` FROM iam.applicationAccounts WHERE `f_accountName`=:accountName AND `f_appName`=:appName;",
                                                   {{":appName", MAKE_VAR(STRING, appName)}, {":accountName", MAKE_VAR(STRING, accountName)}}, {&isAppAdmin}))
        return false;

    return !isAppAdmin.isNull() && isAppAdmin.getValue();
}

bool IdentityManager_DB::Applications_DB::validateApplicationAccount(const std::string &appName, const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    return _parent->m_sqlConnector->qSelectSingleRow("SELECT `f_appName` FROM iam.applicationAccounts WHERE `f_accountName`=:accountName AND `f_appName`=:appName;",
                                                     {{":appName", MAKE_VAR(STRING, appName)}, {":accountName", MAKE_VAR(STRING, accountName)}}, {});
}
std::set<std::string> IdentityManager_DB::Applications_DB::listApplicationAdmins(const std::string &appName)
{
    std::set<std::string> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING accountName;
    auto i = _parent->m_sqlConnector->qSelect("SELECT `f_accountName` FROM iam.applicationAccounts WHERE `f_appName`=:appName AND `isAppAdmin`='1';", {{":appName", MAKE_VAR(STRING, appName)}},
                                              {&accountName});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert(accountName.getValue());
    }

    return ret;
}

std::set<std::string> IdentityManager_DB::Applications_DB::listApplicationAccounts(const std::string &appName)
{
    std::set<std::string> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING accountName;
    auto i = _parent->m_sqlConnector->qSelect("SELECT `f_accountName` FROM iam.applicationAccounts WHERE `f_appName`=:appName;", {{":appName", MAKE_VAR(STRING, appName)}}, {&accountName});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert(accountName.getValue());
    }

    return ret;
}

std::set<std::string> IdentityManager_DB::Applications_DB::listAccountApplications(const std::string &accountName)
{
    std::set<std::string> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING applicationName;
    auto i = _parent->m_sqlConnector->qSelect("SELECT `f_appName` FROM iam.applicationAccounts WHERE `f_accountName`=:accountName;", {{":accountName", MAKE_VAR(STRING, accountName)}},
                                              {&applicationName});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert(applicationName.getValue());
    }

    return ret;
}

bool IdentityManager_DB::Applications_DB::addAccountToApplication(const std::string &appName, const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.applicationAccounts (`f_accountName`,`f_appName`) VALUES(:accountName,:appName);",
                                               {{":appName", MAKE_VAR(STRING, appName)}, {":accountName", MAKE_VAR(STRING, accountName)}});
}

bool IdentityManager_DB::Applications_DB::removeAccountFromApplication(const std::string &appName, const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    bool ret = false;
    ret = _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.applicationAccounts WHERE `f_appName`=:appName AND `f_accountName`=:accountName;",
                                              {{":appName", MAKE_VAR(STRING, appName)}, {":accountName", MAKE_VAR(STRING, accountName)}});
    return ret;
}

bool IdentityManager_DB::Applications_DB::changeApplicationAdmin(const std::string &appName, const std::string &accountName, bool isAppAdmin)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    return _parent->m_sqlConnector->qExecuteEx("UPDATE iam.applicationAccounts SET `isAppAdmin`=:isAppAdmin WHERE `f_accountName`=:accountName AND `f_appName`=:appName;",
                                               {{":appName", MAKE_VAR(STRING, appName)}, {":accountName", MAKE_VAR(STRING, accountName)}, {":isAppAdmin", MAKE_VAR(BOOL, isAppAdmin)}});
}

Json::Value IdentityManager_DB::Applications_DB::searchApplications(const json &dataTablesFilters)
{
    Json::Value ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    // DataTables:
    ret["draw"] = dataTablesFilters["draw"];

    uint64_t offset = JSON_ASUINT64(dataTablesFilters, "start", 0);
    uint64_t limit = JSON_ASUINT64(dataTablesFilters, "length", 0);

    // Manejo de ordenamiento (order)
    std::string orderByStatement = Helpers::DataTables::getOrderByStatement(dataTablesFilters);

    // Extract the search value from dataTablesFilters
    std::string searchValue = JSON_ASSTRING(dataTablesFilters["search"], "value", "");
    std::string whereFilters;

    // Build the SQL query with WHERE clause for DataTables search
    std::string sqlQueryStr = R"(
        SELECT `appName`,`f_appCreator`,`appDescription` FROM iam.applications
        )";

    // Add WHERE clause for search term if provided
    if (!searchValue.empty())
    {
        searchValue = "%" + searchValue + "%";
        whereFilters += "appName LIKE :SEARCHWORDS OR appDescription LIKE :SEARCHWORDS OR f_appCreator LIKE :SEARCHWORDS";
    }

    {
        Abstract::STRING appName, appCreator, appDescription;
        auto i = _parent->m_sqlConnector->qSelectWithFilters(sqlQueryStr, whereFilters, {{":SEARCHWORDS", MAKE_VAR(STRING, searchValue)}}, {&appName, &appCreator, &appDescription},
                                                             orderByStatement, // Order by
                                                             limit,            // LIMIT
                                                             offset            // OFFSET
        );

        while (i && i->isSuccessful() && i->step())
        {
            Json::Value row;

            // appName
            row["appName"] = appName.toJSON();
            // appCreator
            row["appCreator"] = appCreator.toJSON();
            // appDescription
            row["appDescription"] = appDescription.toJSON();

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

std::vector<AccountApplicationInfo> IdentityManager_DB::Applications_DB::listAccountApplicationsFullInfo(const std::string &accountName)
{
    std::vector<AccountApplicationInfo> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    // Query 1: Obtener apps basicas con JOIN
    {
        Abstract::STRING appName, appDescription;
        Abstract::BOOL isAppAdmin;
        Abstract::DATETIME enrollmentDate;

        auto i = _parent->m_sqlConnector->qSelect("SELECT a.`f_appName`, ap.`appDescription`, a.`isAppAdmin`, a.`enrollmentDate` "
                                                  "FROM iam.applicationAccounts a "
                                                  "JOIN iam.applications ap ON a.`f_appName` = ap.`appName` "
                                                  "WHERE a.`f_accountName` = :accountName;",
                                                  {{":accountName", MAKE_VAR(STRING, accountName)}}, {&appName, &appDescription, &isAppAdmin, &enrollmentDate});

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

    for ( AccountApplicationInfo & info: ret )
    {
        // Query 2: Obtener roles del account en esta app
        {
            Abstract::STRING roleName;
            auto j = _parent->m_sqlConnector->qSelect("SELECT `f_roleName` FROM iam.applicationRolesAccounts "
                                                      "WHERE `f_accountName` = :accountName AND `f_appName` = :appName;",
                                                      {{":accountName", MAKE_VAR(STRING, accountName)}, {":appName", MAKE_VAR(STRING, info.appName)}}, {&roleName});

            while (j && j->isSuccessful() && j->step())
            {
                std::string currentRole = roleName.getValue();
                info.roles.insert(currentRole);
            }
        }


        for (const std::string & currentRole : info.roles)
        {
            // Query 3: Obtener scopes de este rol
            Abstract::STRING scopeId;
            auto k = _parent->m_sqlConnector->qSelect("SELECT `f_scopeId` FROM iam.applicationRolesScopes "
                                                      "WHERE `f_appName` = :appName AND `f_roleName` = :roleName;",
                                                      {{":appName", MAKE_VAR(STRING, info.appName)}, {":roleName", MAKE_VAR(STRING, currentRole)}}, {&scopeId});

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
            auto l = _parent->m_sqlConnector->qSelect(
                "SELECT `f_scopeId` FROM iam.applicationScopeAccounts  WHERE `f_accountName` = :accountName AND `f_appName` = :appName;",
                {{":accountName", MAKE_VAR(STRING, accountName)}, {":appName", MAKE_VAR(STRING, info.appName)}}, {&scopeId});

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

bool IdentityManager_DB::Applications_DB::addWebLoginAllowedRedirectURIToApplication(const std::string &appName, const std::string &loginRedirectURI)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.applicationsWebLoginAllowedRedirectURIs (`f_appName`, `loginRedirectURI`) VALUES (:appName, :loginRedirectURI);",
                                               {{":appName", MAKE_VAR(STRING, appName)}, {":loginRedirectURI", MAKE_VAR(STRING, loginRedirectURI)}});
}

bool IdentityManager_DB::Applications_DB::removeWebLoginAllowedRedirectURIToApplication(const std::string &appName, const std::string &loginRedirectURI)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.applicationsWebLoginAllowedRedirectURIs WHERE `f_appName`=:appName AND `loginRedirectURI`=:loginRedirectURI;",
                                               {{":appName", MAKE_VAR(STRING, appName)}, {":loginRedirectURI", MAKE_VAR(STRING, loginRedirectURI)}});
}

std::list<std::string> IdentityManager_DB::Applications_DB::listWebLoginAllowedRedirectURIsFromApplication(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING loginRedirectURI;
    std::list<std::string> redirectURIs;

    auto i = _parent->m_sqlConnector->qSelect("SELECT `loginRedirectURI` FROM iam.applicationsWebLoginAllowedRedirectURIs WHERE `f_appName`=:appName;", {{":appName", MAKE_VAR(STRING, appName)}},
                                              {&loginRedirectURI});
    while (i && i->isSuccessful() && i->step())
    {
        redirectURIs.push_back(loginRedirectURI.getValue());
    }
    return redirectURIs;
}

bool IdentityManager_DB::Applications_DB::updateWebLoginDefaultRedirectURIForApplication(const std::string &appName, const std::string &loginRedirectURI)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("INSERT OR REPLACE INTO iam.applicationsWebLoginDefaultRedirectURI (`f_appName`, `f_loginRedirectURI`) VALUES (:appName, :loginRedirectURI);",
                                               {{":appName", MAKE_VAR(STRING, appName)}, {":loginRedirectURI", MAKE_VAR(STRING, loginRedirectURI)}});
}

std::string IdentityManager_DB::Applications_DB::getWebLoginDefaultRedirectURIForApplication(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING loginRedirectURI;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `f_loginRedirectURI` FROM iam.applicationsWebLoginDefaultRedirectURI WHERE `f_appName`=:appName;", {{":appName", MAKE_VAR(STRING, appName)}},
                                                  {&loginRedirectURI}))
    {
        return loginRedirectURI.getValue();
    }
    return "";
}

bool IdentityManager_DB::Applications_DB::setApplicationWebLoginCallbackURI(const std::string &appName, const std::string &callbackURI)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    bool ret = false;

    // Delete existing callback URI for the application if it exists
    _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.applicationsLoginCallbackURI WHERE `f_appName`=:appName;", {{":appName", MAKE_VAR(STRING, appName)}});

    // Insert new callback URI
    ret = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.applicationsLoginCallbackURI (`f_appName`, `callbackURI`) VALUES (:appName, :callbackURI);",
                                              {{":appName", MAKE_VAR(STRING, appName)}, {":callbackURI", MAKE_VAR(STRING, callbackURI)}});

    return ret;
}
std::string IdentityManager_DB::Applications_DB::getApplicationCallbackURI(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING callbackURI;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `callbackURI` FROM iam.applicationsLoginCallbackURI WHERE `f_appName`=:appName LIMIT 1;", {{":appName", MAKE_VAR(STRING, appName)}},
                                                  {&callbackURI}))
    {
        return callbackURI.getValue();
    }

    // Return an empty string if no callback URI is found
    return "";
}

bool IdentityManager_DB::Applications_DB::addWebLoginOriginURLToApplication(const std::string &appName, const std::string &originUrl)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.applicationsWebLoginOrigins (`f_appName`, `originUrl`) VALUES (:appName, :originUrl);",
                                               {{":appName", MAKE_VAR(STRING, appName)}, {":originUrl", MAKE_VAR(STRING, originUrl)}});
}

bool IdentityManager_DB::Applications_DB::removeWebLoginOriginURLToApplication(const std::string &appName, const std::string &originUrl)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.applicationsWebLoginOrigins WHERE `f_appName`=:appName AND `originUrl`=:originUrl;",
                                               {{":appName", MAKE_VAR(STRING, appName)}, {":originUrl", MAKE_VAR(STRING, originUrl)}});
}

std::list<std::string> IdentityManager_DB::Applications_DB::listWebLoginOriginUrlsFromApplication(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING originUrl;
    std::list<std::string> originUrls;

    auto i = _parent->m_sqlConnector->qSelect("SELECT `originUrl` FROM iam.applicationsWebLoginOrigins WHERE `f_appName`=:appName;", {{":appName", MAKE_VAR(STRING, appName)}}, {&originUrl});
    while (i && i->isSuccessful() && i->step())
    {
        originUrls.push_back(originUrl.getValue());
    }
    return originUrls;
}

bool IdentityManager_DB::Applications_DB::updateWebLoginJWTConfigForApplication(const ApplicationTokenProperties &tokenInfo)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("UPDATE iam.applicationsJWTTokenConfig SET "
                                               "sessionInactivityTimeout=:sessionInactivityTimeout, "
                                               "tokenType=:tokenType, includeApplicationScopes=:includeApplicationScopes, "
                                               "includeBasicAccountInfo=:includeBasicAccountInfo, allowRefreshTokenRenovation=:allowRefreshTokenRenovation, "
                                               "tokensConfigJSON=:tokensConfigJSON, "
                                               "maintainRevocationAndLogoutInfo=:maintainRevocationAndLogoutInfo WHERE f_appName=:appName;",
                                               {{":appName", MAKE_VAR(STRING, tokenInfo.appName)},
                                                {":sessionInactivityTimeout", MAKE_VAR(UINT32, tokenInfo.sessionInactivityTimeout)},
                                                {":tokenType", MAKE_VAR(STRING, tokenInfo.tokenType)},
                                                {":includeApplicationScopes", MAKE_VAR(BOOL, tokenInfo.includeApplicationScopes)},
                                                {":includeBasicAccountInfo", MAKE_VAR(BOOL, tokenInfo.includeBasicAccountInfo)},
                                                {":allowRefreshTokenRenovation", MAKE_VAR(BOOL, tokenInfo.allowRefreshTokenRenovation)},
                                                {":allowRefreshTokenRenovation", MAKE_VAR(BOOL, tokenInfo.allowRefreshTokenRenovation)},
                                                {":tokensConfigJSON", MAKE_VAR(STRING, tokenInfo.tokensConfiguration.toStyledString())},
                                                {":maintainRevocationAndLogoutInfo", MAKE_VAR(BOOL, tokenInfo.maintainRevocationAndLogoutInfo)}});
}

ApplicationTokenProperties IdentityManager_DB::Applications_DB::getWebLoginJWTConfigFromApplication(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    ApplicationTokenProperties tokenInfo;
    tokenInfo.appName = appName;

    // Define las variables para capturar los valores de la base de datos.
    Abstract::UINT32 sessionInactivityTimeout;
    Abstract::STRING tokenType, tokensConfigJSON;
    Abstract::BOOL includeApplicationScopes, includeBasicAccountInfo, maintainRevocationAndLogoutInfo, allowRefreshTokenRenovation;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT allowRefreshTokenRenovation,sessionInactivityTimeout, tokenType, "
                                                  "includeApplicationScopes, includeBasicAccountInfo, maintainRevocationAndLogoutInfo, tokensConfigJSON "
                                                  "FROM iam.applicationsJWTTokenConfig "
                                                  "WHERE f_appName=:appName;",
                                                  {{":appName", MAKE_VAR(STRING, appName)}},
                                                  {&allowRefreshTokenRenovation, &sessionInactivityTimeout, &tokenType, &includeApplicationScopes, &includeBasicAccountInfo,
                                                   &maintainRevocationAndLogoutInfo, &tokensConfigJSON}))
    {
        tokenInfo.sessionInactivityTimeout = sessionInactivityTimeout.getValue();
        tokenInfo.tokenType = tokenType.getValue();
        tokenInfo.includeApplicationScopes = includeApplicationScopes.getValue();
        tokenInfo.includeBasicAccountInfo = includeBasicAccountInfo.getValue();
        tokenInfo.maintainRevocationAndLogoutInfo = maintainRevocationAndLogoutInfo.getValue();
        tokenInfo.allowRefreshTokenRenovation = allowRefreshTokenRenovation.getValue();
        Mantids30::Helpers::JSONReader2 reader;
        reader.parse(tokensConfigJSON.getValue(), tokenInfo.tokensConfiguration);
    }
    return tokenInfo;
}

bool IdentityManager_DB::Applications_DB::setWebLoginJWTSigningKeyForApplication(const std::string &appName, const std::string &signingKey)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("UPDATE iam.applicationsJWTTokenConfig SET accessTokenSigningKey=:signingKey WHERE f_appName=:appName;",
                                               {{":appName", MAKE_VAR(STRING, appName)}, {":signingKey", MAKE_VAR(STRING, Helpers::Encoders::encodeToBase64Obf(signingKey, 0x8A376C54D999F187))}});
}

std::string IdentityManager_DB::Applications_DB::getWebLoginJWTSigningKeyForApplication(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    Abstract::STRING signingKey;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT accessTokenSigningKey FROM iam.applicationsJWTTokenConfig WHERE f_appName=:appName;", {{":appName", MAKE_VAR(STRING, appName)}},
                                                  {&signingKey}))
    {
        // SBO... -.- (protect your .db file)
        return Helpers::Encoders::decodeFromBase64Obf(signingKey.getValue(), 0x8A376C54D999F187);
    }
    return "";
}

bool IdentityManager_DB::Applications_DB::setWebLoginJWTValidationKeyForApplication(const std::string &appName, const std::string &validationKey)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qExecuteEx("UPDATE iam.applicationsJWTTokenConfig SET accessTokenValidationKey=:validationKey WHERE f_appName=:appName;",
                                               {{":appName", MAKE_VAR(STRING, appName)}, {":validationKey", MAKE_VAR(STRING, Helpers::Encoders::encodeToBase64Obf(validationKey, 0x8A376C54D999F187))}});
}

std::string IdentityManager_DB::Applications_DB::getWebLoginJWTValidationKeyForApplication(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    Abstract::STRING validationKey;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT accessTokenValidationKey FROM iam.applicationsJWTTokenConfig WHERE f_appName=:appName;", {{":appName", MAKE_VAR(STRING, appName)}},
                                                  {&validationKey}))
    {
        return Helpers::Encoders::decodeFromBase64Obf(validationKey.getValue(), 0x8A376C54D999F187);
    }
    return "";
}
