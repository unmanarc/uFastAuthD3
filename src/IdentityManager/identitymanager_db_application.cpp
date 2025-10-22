#include "identitymanager_db.h"
#include <Mantids30/Helpers/encoders.h>

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
using namespace Mantids30::Helpers;
using namespace Mantids30;
bool IdentityManager_DB::Applications_DB::addApplication(const std::string &appName,
                                                         const std::string &applicationDescription,
                                                         const std::string &appURL,
                                                         const std::string &apiKey,
                                                         const std::string &creatorAccountName,
                                                         const ApplicationAttributes & appAttributes,
                                                         bool initializeDefaultValues)
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
        bool appInsertSuccess = _parent->m_sqlConnector->execute("INSERT INTO iam.applications (`appName`, `f_appCreator`, `appDescription`, `apiKey`, "
                                                                 "`canAdminModifyApplicationSecurityContext`, `canUserAutoRegister`, `appSyncEnabled`, `appSyncCanRetrieveAppUserList`) VALUES (:appName, "
                                                                 ":appCreator, :description, :apiKey, :canAdminModifyApplicationSecurityContext, :canUserAutoRegister, :appSyncEnabled, :appSyncCanRetrieveAppUserList);",
                                                                 {{":appName", MAKE_VAR(STRING, appName)},
                                                                  {":appCreator", MAKE_VAR(STRING, creatorAccountName)},
                                                                  {":description", MAKE_VAR(STRING, applicationDescription)},
                                                                  {":apiKey", MAKE_VAR(STRING, Encoders::encodeToBase64Obf(apiKey))},
                                                                  {":canAdminModifyApplicationSecurityContext", MAKE_VAR(BOOL, appAttributes.canAdminModifyApplicationSecurityContext)},
                                                                  {":canUserAutoRegister", MAKE_VAR(BOOL, appAttributes.canUserAutoRegister)},
                                                                  {":appSyncEnabled", MAKE_VAR(BOOL, appAttributes.appSyncEnabled)},
                                                                  {":appSyncCanRetrieveAppUserList", MAKE_VAR(BOOL, appAttributes.appSyncCanRetrieveAppUserList)}});

        // If the insertion is successful, insert another row default values into iam.applicationsJWTTokenConfig.
        if (appInsertSuccess)
        {
            std::string randomSecret = Mantids30::Helpers::Random::createRandomString(64);
            tokenInsertSuccess = _parent->m_sqlConnector->execute("INSERT INTO iam.applicationsJWTTokenConfig (`f_appName`, `accessTokenSigningKey`, `accessTokenValidationKey`) "
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
    return _parent->m_sqlConnector->execute("DELETE FROM iam.applications WHERE `appName`=:appName;", {{":appName", MAKE_VAR(STRING, appName)}});
}

bool IdentityManager_DB::Applications_DB::doesApplicationExist(const std::string &appName)
{
    bool ret = false;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `appDescription` FROM iam.applications WHERE `appName`=:appName LIMIT 1;", {{":appName", MAKE_VAR(STRING, appName)}}, {});
    if (i.getResultsOK() && i.query->step())
    {
        ret = true;
    }
    return ret;
}

bool IdentityManager_DB::Applications_DB::updateApplicationAttributes(const std::string &appName, const ApplicationAttributes &appAttributes)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("UPDATE iam.applications SET "
                                            "`canUserAutoRegister`=:canUserAutoRegister, `appSyncEnabled`=:appSyncEnabled, "
                                            "`appSyncCanRetrieveAppUserList`=:appSyncCanRetrieveAppUserList WHERE `appName`=:appName;",
                                            {{":appName", MAKE_VAR(STRING, appName)},
                                             {":canUserAutoRegister", MAKE_VAR(BOOL, appAttributes.canUserAutoRegister)},
                                             {":appSyncEnabled", MAKE_VAR(BOOL, appAttributes.appSyncEnabled)},
                                             {":appSyncCanRetrieveAppUserList", MAKE_VAR(BOOL, appAttributes.appSyncCanRetrieveAppUserList)}});
}

std::optional<IdentityManager::Applications::ApplicationAttributes> IdentityManager_DB::Applications_DB::getApplicationAttributes(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    Abstract::BOOL canAdminModifyApplicationSecurityContext;
    Abstract::BOOL canUserAutoRegister;
    Abstract::BOOL appSyncEnabled;
    Abstract::BOOL appSyncCanRetrieveAppUserList;

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect(
        "SELECT `canAdminModifyApplicationSecurityContext`, `canUserAutoRegister`, `appSyncEnabled`, `appSyncCanRetrieveAppUserList` "
        "FROM iam.applications WHERE `appName`=:appName LIMIT 1;",
        {{":appName", MAKE_VAR(STRING, appName)}},
        {
            &canAdminModifyApplicationSecurityContext,
            &canUserAutoRegister,
            &appSyncEnabled,
            &appSyncCanRetrieveAppUserList
        }
    );

    if (i.getResultsOK() && i.query->step())
    {
        IdentityManager::Applications::ApplicationAttributes attrs;
        attrs.canAdminModifyApplicationSecurityContext = canAdminModifyApplicationSecurityContext.getValue();
        attrs.canUserAutoRegister = canUserAutoRegister.getValue();
        attrs.appSyncEnabled = appSyncEnabled.getValue();
        attrs.appSyncCanRetrieveAppUserList = appSyncCanRetrieveAppUserList.getValue();
        return attrs;
    }
    return std::nullopt;
}

std::string IdentityManager_DB::Applications_DB::getApplicationDescription(const std::string &appName)
{
    std::string ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING description;
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `appDescription` FROM iam.applications WHERE `appName`=:appName LIMIT 1;", {{":appName", MAKE_VAR(STRING, appName)}},
                                                                     {&description});
    if (i.getResultsOK() && i.query->step())
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
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `apiKey` FROM iam.applications WHERE `appName`=:appName LIMIT 1;", {{":appName", MAKE_VAR(STRING, appName)}}, {&apiKey});
    if (i.getResultsOK() && i.query->step())
    {
        return Encoders::decodeFromBase64Obf(apiKey.getValue());
    }
    return "";
}

bool IdentityManager_DB::Applications_DB::updateApplicationAPIKey(const std::string &appName, const std::string &apiKey)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("UPDATE iam.applications SET `apiKey`=:apiKey WHERE `appName`=:appName;",
                                            {{":appName", MAKE_VAR(STRING, appName)}, {":apiKey", MAKE_VAR(STRING, Encoders::encodeToBase64Obf(apiKey))}});
}

bool IdentityManager_DB::Applications_DB::updateApplicationDescription(const std::string &appName, const std::string &applicationDescription)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("UPDATE iam.applications SET `appDescription`=:description WHERE `appName`=:appName;",
                                            {{":appName", MAKE_VAR(STRING, appName)}, {":description", MAKE_VAR(STRING, applicationDescription)}});
}

std::string IdentityManager_DB::Applications_DB::getApplicationNameByAPIKey(const std::string &apiKey)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    Abstract::STRING appName;
    SQLConnector::QueryInstance queryResult = _parent->m_sqlConnector->qSelect("SELECT `appName` FROM iam.applications WHERE `apiKey` = :encodedApiKey LIMIT 1;",
                                                                               {
                                                                                   {":encodedApiKey", MAKE_VAR(STRING, Encoders::encodeToBase64Obf(apiKey))},
                                                                               },
                                                                               {&appName});
    if (queryResult.getResultsOK() && queryResult.query->step())
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
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `appName` FROM iam.applications;", {}, {&sAppName});
    while (i.getResultsOK() && i.query->step())
    {
        ret.insert(sAppName.getValue());
    }
    return ret;
}

bool IdentityManager_DB::Applications_DB::isApplicationAdmin(const std::string &appName, const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::BOOL isAppAdmin;
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `isAppAdmin` FROM iam.applicationAccounts WHERE `f_accountName`=:accountName AND `f_appName`=:appName;",
                                                                     {{":appName", MAKE_VAR(STRING, appName)}, {":accountName", MAKE_VAR(STRING, accountName)}}, {&isAppAdmin});
    if (!i.getResultsOK() || !i.query->step())
        return false;

    return !isAppAdmin.isNull() && isAppAdmin.getValue();
}

bool IdentityManager_DB::Applications_DB::validateApplicationAccount(const std::string &appName, const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `f_appName` FROM iam.applicationAccounts WHERE `f_accountName`=:accountName AND `f_appName`=:appName;",
                                                                     {{":appName", MAKE_VAR(STRING, appName)}, {":accountName", MAKE_VAR(STRING, accountName)}}, {});
    return (i.getResultsOK() && i.query->step());
}
std::set<std::string> IdentityManager_DB::Applications_DB::listApplicationAdmins(const std::string &appName)
{
    std::set<std::string> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING accountName;
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `f_accountName` FROM iam.applicationAccounts WHERE `f_appName`=:appName AND `isAppAdmin`='1';",
                                                                     {{":appName", MAKE_VAR(STRING, appName)}}, {&accountName});
    while (i.getResultsOK() && i.query->step())
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
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `f_accountName` FROM iam.applicationAccounts WHERE `f_appName`=:appName;", {{":appName", MAKE_VAR(STRING, appName)}},
                                                                     {&accountName});
    while (i.getResultsOK() && i.query->step())
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
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `f_appName` FROM iam.applicationAccounts WHERE `f_accountName`=:accountName;",
                                                                     {{":accountName", MAKE_VAR(STRING, accountName)}}, {&applicationName});
    while (i.getResultsOK() && i.query->step())
    {
        ret.insert(applicationName.getValue());
    }

    return ret;
}

bool IdentityManager_DB::Applications_DB::addAccountToApplication(const std::string &appName, const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("INSERT INTO iam.applicationAccounts (`f_accountName`,`f_appName`) VALUES(:accountName,:appName);",
                                            {{":appName", MAKE_VAR(STRING, appName)}, {":accountName", MAKE_VAR(STRING, accountName)}});
}

bool IdentityManager_DB::Applications_DB::removeAccountFromApplication(const std::string &appName, const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    bool ret = false;
    ret = _parent->m_sqlConnector->execute("DELETE FROM iam.applicationAccounts WHERE `f_appName`=:appName AND `f_accountName`=:accountName;",
                                           {{":appName", MAKE_VAR(STRING, appName)}, {":accountName", MAKE_VAR(STRING, accountName)}});
    return ret;
}

bool IdentityManager_DB::Applications_DB::changeApplicationAdmin(const std::string &appName, const std::string &accountName, bool isAppAdmin)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    return _parent->m_sqlConnector->execute("UPDATE iam.applicationAccounts SET `isAppAdmin`=:isAppAdmin WHERE `f_accountName`=:accountName AND `f_appName`=:appName;",
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
            static const std::vector<std::string> validFields = {"appName", "appDescription", "f_appCreator"};
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
        SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelectWithFilters(sqlQueryStr, whereFilters, {{":SEARCHWORDS", MAKE_VAR(STRING, searchValue)}},
                                                                                    {&appName, &appCreator, &appDescription},
                                                                                    orderByStatement, // Order by
                                                                                    limit,            // LIMIT
                                                                                    offset            // OFFSET
        );

        while (i.getResultsOK() && i.query->step())
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

        ret["recordsTotal"] = i.query->getTotalRecordsCount();
        ret["recordsFiltered"] = i.query->getFilteredRecordsCount();
    }

    return ret;
}
/*
std::list<ApplicationDetails> IdentityManager_DB::Applications_DB::searchApplications(std::string sSearchWords, size_t limit, size_t offset)
{
    std::list<ApplicationDetails> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING applicationName, appCreator, description;

    std::string sSqlQuery = "SELECT `appName`,`f_appCreator`,`appDescription` FROM iam.applications";

    if (!sSearchWords.empty())
    {
        sSearchWords = '%' + sSearchWords + '%';
        sSqlQuery += " WHERE (`appName` LIKE :SEARCHWORDS OR `appDescription` LIKE :SEARCHWORDS)";
    }

    if (limit)
        sSqlQuery += " LIMIT :LIMIT OFFSET :OFFSET";

    sSqlQuery += ";";

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect(sSqlQuery,
                                                                                      {{":SEARCHWORDS", MAKE_VAR(STRING, sSearchWords)},
                                                                                       {":LIMIT", MAKE_VAR(UINT64, limit)},
                                                                                       {":OFFSET", MAKE_VAR(UINT64, offset)}},
                                                                                      {&applicationName, &appCreator, &description});
    while (i.getResultsOK() && i.query->step())
    {
        ApplicationDetails rDetail;

        rDetail.appCreator = appCreator.getValue();
        rDetail.description = description.getValue();
        rDetail.applicationName = applicationName.getValue();

        ret.push_back(rDetail);
    }

    return ret;
}
*/
bool IdentityManager_DB::Applications_DB::addWebLoginAllowedRedirectURIToApplication(const std::string &appName, const std::string &loginRedirectURI)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("INSERT INTO iam.applicationsWebLoginAllowedRedirectURIs (`f_appName`, `loginRedirectURI`) VALUES (:appName, :loginRedirectURI);",
                                            {{":appName", MAKE_VAR(STRING, appName)}, {":loginRedirectURI", MAKE_VAR(STRING, loginRedirectURI)}});
}

bool IdentityManager_DB::Applications_DB::removeWebLoginAllowedRedirectURIToApplication(const std::string &appName, const std::string &loginRedirectURI)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("DELETE FROM iam.applicationsWebLoginAllowedRedirectURIs WHERE `f_appName`=:appName AND `loginRedirectURI`=:loginRedirectURI;",
                                            {{":appName", MAKE_VAR(STRING, appName)}, {":loginRedirectURI", MAKE_VAR(STRING, loginRedirectURI)}});
}

std::list<std::string> IdentityManager_DB::Applications_DB::listWebLoginAllowedRedirectURIsFromApplication(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING loginRedirectURI;
    std::list<std::string> redirectURIs;

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `loginRedirectURI` FROM iam.applicationsWebLoginAllowedRedirectURIs WHERE `f_appName`=:appName;",
                                                                     {{":appName", MAKE_VAR(STRING, appName)}}, {&loginRedirectURI});
    while (i.getResultsOK() && i.query->step())
    {
        redirectURIs.push_back(loginRedirectURI.getValue());
    }
    return redirectURIs;
}

bool IdentityManager_DB::Applications_DB::updateWebLoginDefaultRedirectURIForApplication(const std::string &appName, const std::string &loginRedirectURI)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("INSERT OR REPLACE INTO iam.applicationsWebLoginDefaultRedirectURI (`f_appName`, `f_loginRedirectURI`) VALUES (:appName, :loginRedirectURI);",
                                            {{":appName", MAKE_VAR(STRING, appName)}, {":loginRedirectURI", MAKE_VAR(STRING, loginRedirectURI)}});
}

std::string IdentityManager_DB::Applications_DB::getWebLoginDefaultRedirectURIForApplication(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING loginRedirectURI;
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `f_loginRedirectURI` FROM iam.applicationsWebLoginDefaultRedirectURI WHERE `f_appName`=:appName;",
                                                                     {{":appName", MAKE_VAR(STRING, appName)}}, {&loginRedirectURI});
    if (i.getResultsOK() && i.query->step())
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
    _parent->m_sqlConnector->execute("DELETE FROM iam.applicationsLoginCallbackURI WHERE `f_appName`=:appName;", {{":appName", MAKE_VAR(STRING, appName)}});

    // Insert new callback URI
    ret = _parent->m_sqlConnector->execute("INSERT INTO iam.applicationsLoginCallbackURI (`f_appName`, `callbackURI`) VALUES (:appName, :callbackURI);",
                                           {{":appName", MAKE_VAR(STRING, appName)}, {":callbackURI", MAKE_VAR(STRING, callbackURI)}});

    return ret;
}
std::string IdentityManager_DB::Applications_DB::getApplicationCallbackURI(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING callbackURI;

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `callbackURI` FROM iam.applicationsLoginCallbackURI WHERE `f_appName`=:appName LIMIT 1;",
                                                                     {{":appName", MAKE_VAR(STRING, appName)}}, {&callbackURI});
    if (i.getResultsOK() && i.query->step())
    {
        return callbackURI.getValue();
    }

    // Return an empty string if no callback URI is found
    return "";
}

bool IdentityManager_DB::Applications_DB::addWebLoginOriginURLToApplication(const std::string &appName, const std::string &originUrl)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("INSERT INTO iam.applicationsWebLoginOrigins (`f_appName`, `originUrl`) VALUES (:appName, :originUrl);",
                                            {{":appName", MAKE_VAR(STRING, appName)}, {":originUrl", MAKE_VAR(STRING, originUrl)}});
}

bool IdentityManager_DB::Applications_DB::removeWebLoginOriginURLToApplication(const std::string &appName, const std::string &originUrl)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("DELETE FROM iam.applicationsWebLoginOrigins WHERE `f_appName`=:appName AND `originUrl`=:originUrl;",
                                            {{":appName", MAKE_VAR(STRING, appName)}, {":originUrl", MAKE_VAR(STRING, originUrl)}});
}

std::list<std::string> IdentityManager_DB::Applications_DB::listWebLoginOriginUrlsFromApplication(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING originUrl;
    std::list<std::string> originUrls;

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `originUrl` FROM iam.applicationsWebLoginOrigins WHERE `f_appName`=:appName;", {{":appName", MAKE_VAR(STRING, appName)}},
                                                                     {&originUrl});
    while (i.getResultsOK() && i.query->step())
    {
        originUrls.push_back(originUrl.getValue());
    }
    return originUrls;
}

bool IdentityManager_DB::Applications_DB::updateWebLoginJWTConfigForApplication(const ApplicationTokenProperties &tokenInfo)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("UPDATE iam.applicationsJWTTokenConfig SET "
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

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT allowRefreshTokenRenovation,sessionInactivityTimeout, tokenType, "
                                                                     "includeApplicationScopes, includeBasicAccountInfo, maintainRevocationAndLogoutInfo, tokensConfigJSON "
                                                                     "FROM iam.applicationsJWTTokenConfig "
                                                                     "WHERE f_appName=:appName;",
                                                                     {{":appName", MAKE_VAR(STRING, appName)}},
                                                                     {&allowRefreshTokenRenovation, &sessionInactivityTimeout, &tokenType, &includeApplicationScopes,
                                                                      &includeBasicAccountInfo, &maintainRevocationAndLogoutInfo, &tokensConfigJSON});
    if (i.getResultsOK() && i.query->step())
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
    return _parent->m_sqlConnector->execute("UPDATE iam.applicationsJWTTokenConfig SET accessTokenSigningKey=:signingKey WHERE f_appName=:appName;",
                                            {{":appName", MAKE_VAR(STRING, appName)}, {":signingKey", MAKE_VAR(STRING, Helpers::Encoders::encodeToBase64Obf(signingKey, 0x8A376C54D999F187))}});
}

std::string IdentityManager_DB::Applications_DB::getWebLoginJWTSigningKeyForApplication(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    Abstract::STRING signingKey;

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT accessTokenSigningKey FROM iam.applicationsJWTTokenConfig WHERE f_appName=:appName;",
                                                                     {{":appName", MAKE_VAR(STRING, appName)}}, {&signingKey});
    if (i.getResultsOK() && i.query->step())
    {
        // SBO... -.- (protect your .db file)
        return Helpers::Encoders::decodeFromBase64Obf(signingKey.getValue(), 0x8A376C54D999F187);
    }
    return "";
}

bool IdentityManager_DB::Applications_DB::setWebLoginJWTValidationKeyForApplication(const std::string &appName, const std::string &validationKey)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("UPDATE iam.applicationsJWTTokenConfig SET accessTokenValidationKey=:validationKey WHERE f_appName=:appName;",
                                            {{":appName", MAKE_VAR(STRING, appName)}, {":validationKey", MAKE_VAR(STRING, Helpers::Encoders::encodeToBase64Obf(validationKey, 0x8A376C54D999F187))}});
}

std::string IdentityManager_DB::Applications_DB::getWebLoginJWTValidationKeyForApplication(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    Abstract::STRING validationKey;

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT accessTokenValidationKey FROM iam.applicationsJWTTokenConfig WHERE f_appName=:appName;",
                                                                     {{":appName", MAKE_VAR(STRING, appName)}}, {&validationKey});
    if (i.getResultsOK() && i.query->step())
    {
        return Helpers::Encoders::decodeFromBase64Obf(validationKey.getValue(), 0x8A376C54D999F187);
    }
    return "";
}
