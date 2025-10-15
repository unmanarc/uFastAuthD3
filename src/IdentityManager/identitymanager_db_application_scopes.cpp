#include "identitymanager_db.h"
#include <Mantids30/Threads/lock_shared.h>

#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_uint64.h>

using namespace Mantids30;
using namespace Mantids30::Memory;
using namespace Mantids30::Database;

bool IdentityManager_DB::AuthController_DB::addApplicationScope(const ApplicationScope &applicationScope)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("INSERT INTO iam.applicationScopes (`f_appName`,`scopeId`,`description`) VALUES(:appName,:scopeId,:description);",
                                          {{":appName", MAKE_VAR(STRING, applicationScope.appName)},
                                           {":scopeId", MAKE_VAR(STRING, applicationScope.id)},
                                           {":description", MAKE_VAR(STRING, applicationScope.description)}});
}

bool IdentityManager_DB::AuthController_DB::removeApplicationScope(const ApplicationScope &applicationScope)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("DELETE FROM iam.applicationScopes WHERE `scopeId`=:scopeId and `f_appName`=:appName;",
                                          {{":appName", MAKE_VAR(STRING, applicationScope.appName)}, {":scopeId", MAKE_VAR(STRING, applicationScope.id)}});
}

bool IdentityManager_DB::AuthController_DB::doesApplicationScopeExist(const ApplicationScope &applicationScope)
{
    bool ret = false;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    SQLConnector::QueryInstance i
        = _parent->m_sqlConnector->qSelect("SELECT `description` FROM iam.applicationScopes WHERE `scopeId`=:scopeId and `f_appName`=:appName LIMIT 1;",
                                           {{":appName", MAKE_VAR(STRING, applicationScope.appName)}, {":scopeId", MAKE_VAR(STRING, applicationScope.id)}}, {});
    if (i.getResultsOK() && i.query->step())
    {
        ret = true;
    }
    return ret;
}

bool IdentityManager_DB::AuthController_DB::addApplicationScopeToRole(const ApplicationScope &applicationScope, const std::string &roleName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    return _parent->m_sqlConnector->execute("INSERT INTO iam.applicationRolesScopes (`f_appName`,`f_scopeId`,`f_roleName`) VALUES(:appName,:scopeId,:roleName);",
                                          {{":appName", MAKE_VAR(STRING, applicationScope.appName)},
                                           {":scopeId", MAKE_VAR(STRING, applicationScope.id)},
                                           {":roleName", MAKE_VAR(STRING, roleName)}});
}

bool IdentityManager_DB::AuthController_DB::removeApplicationScopeFromRole(const ApplicationScope &applicationScope, const std::string &roleName, bool lock)
{
    bool ret = false;
    if (lock)
        _parent->m_mutex.lock();
    ret = _parent->m_sqlConnector->execute("DELETE FROM iam.applicationRolesScopes WHERE `f_scopeId`=:scopeId and `f_appName`=:appName AND `f_roleName`=:roleName;",
                                         {{":appName", MAKE_VAR(STRING, applicationScope.appName)},
                                          {":scopeId", MAKE_VAR(STRING, applicationScope.id)},
                                          {":roleName", MAKE_VAR(STRING, roleName)}});
    if (lock)
        _parent->m_mutex.unlock();
    return ret;
}

bool IdentityManager_DB::AuthController_DB::addApplicationScopeToAccount(const ApplicationScope &applicationScope, const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("INSERT INTO iam.applicationScopeAccounts (`f_appName`,`f_scopeId`,`f_accountName`) VALUES(:appName,:scopeId,:accountName);",
                                          {{":appName", MAKE_VAR(STRING, applicationScope.appName)},
                                           {":scopeId", MAKE_VAR(STRING, applicationScope.id)},
                                           {":accountName", MAKE_VAR(STRING, accountName)}});
}

bool IdentityManager_DB::AuthController_DB::removeApplicationScopeFromAccount(const ApplicationScope &applicationScope, const std::string &accountName, bool lock)
{
    bool ret = false;
    if (lock)
        _parent->m_mutex.lock();
    ret = _parent->m_sqlConnector->execute("DELETE FROM iam.applicationScopeAccounts WHERE `f_scopeId`=:scopeId AND `f_appName`=:appName AND `f_accountName`=:accountName;",
                                         {{":appName", MAKE_VAR(STRING, applicationScope.appName)},
                                          {":scopeId", MAKE_VAR(STRING, applicationScope.id)},
                                          {":accountName", MAKE_VAR(STRING, accountName)}});
    if (lock)
        _parent->m_mutex.unlock();
    return ret;
}

bool IdentityManager_DB::AuthController_DB::updateApplicationScopeDescription(const ApplicationScope &applicationScope)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("UPDATE iam.applicationScopes SET `description`=:description WHERE `scopeId`=:scopeId AND `f_appName`=:appName;",
                                          {{":appName", MAKE_VAR(STRING, applicationScope.appName)},
                                           {":scopeId", MAKE_VAR(STRING, applicationScope.id)},
                                           {":description", MAKE_VAR(STRING, applicationScope.description)}});
}

std::string IdentityManager_DB::AuthController_DB::getApplicationScopeDescription(const ApplicationScope &applicationScope)
{
    std::string ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING description;
    SQLConnector::QueryInstance i
        = _parent->m_sqlConnector->qSelect("SELECT `description` FROM iam.applicationScopes WHERE `scopeId`=:scopeId AND `f_appName`=:appName LIMIT 1;",
                                           {{":appName", MAKE_VAR(STRING, applicationScope.appName)}, {":scopeId", MAKE_VAR(STRING, applicationScope.id)}}, {&description});
    if (i.getResultsOK() && i.query->step())
    {
        return description.getValue();
    }
    return "";
}

std::set<ApplicationScope> IdentityManager_DB::AuthController_DB::listApplicationScopes(const std::string &applicationName)
{
    std::set<ApplicationScope> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING sAppName, sScopeId, sDescription;

    std::string sqlQuery = "SELECT `f_appName`,`scopeId` FROM iam.applicationScopes;";
    if (!applicationName.empty())
        sqlQuery = "SELECT `f_appName`,`scopeId`,`description` FROM iam.applicationScopes WHERE `f_appName`=:appName;";

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect(sqlQuery, {{":appName", MAKE_VAR(STRING, applicationName)}}, {&sAppName, &sScopeId, &sDescription});
    while (i.getResultsOK() && i.query->step())
    {
        ret.insert({sAppName.getValue(), sScopeId.getValue(), sDescription.getValue()});
    }
    return ret;
}

std::set<std::string> IdentityManager_DB::AuthController_DB::listAccountsOnApplicationScope(const ApplicationScope &applicationScope, bool lock)
{
    std::set<std::string> ret;
    if (lock)
        _parent->m_mutex.lockShared();

    Abstract::STRING accountName;
    SQLConnector::QueryInstance i
        = _parent->m_sqlConnector->qSelect("SELECT `f_accountName` FROM iam.applicationScopeAccounts WHERE `f_scopeId`=:scopeId AND `f_appName`=:appName;",
                                           {{":appName", MAKE_VAR(STRING, applicationScope.appName)}, {":scopeId", MAKE_VAR(STRING, applicationScope.id)}}, {&accountName});
    while (i.getResultsOK() && i.query->step())
    {
        ret.insert(accountName.getValue());
    }

    if (lock)
        _parent->m_mutex.unlockShared();
    return ret;
}

Json::Value IdentityManager_DB::AuthController_DB::searchApplicationScopes(const json &dataTablesFilters)
{
    Json::Value ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    // DataTables:
    ret["draw"] = dataTablesFilters["draw"];

    std::string appName = JSON_ASSTRING(dataTablesFilters,"appName","");

    uint64_t offset = JSON_ASUINT64(dataTablesFilters,"start",0);
    uint64_t limit = JSON_ASUINT64(dataTablesFilters,"length",0);

    std::string orderByStatement;

    // Manejo de ordenamiento (order)
    const Json::Value& orderArray = dataTablesFilters["order"];
    if (JSON_ISARRAY_D(orderArray) && orderArray.size()>0)
    {
        const Json::Value& orderArrayElement = orderArray[0];
        std::string columnName = getColumnNameFromColumnPos(dataTablesFilters,JSON_ASUINT(orderArrayElement,"column",0));
        std::string dir = JSON_ASSTRING(orderArrayElement,"dir","desc");

        auto isValidField = [](const std::string& c) -> bool {
            static const std::vector<std::string> validFields = {
                "scopeId", "description"
            };
            return std::find(validFields.begin(), validFields.end(), c) != validFields.end();
        };

        if (isValidField(columnName))
        {
            orderByStatement = "`" + columnName + "` ";
            orderByStatement += (dir == "desc") ? "DESC" : "ASC";
        }
    }

    // Extract the search value from dataTablesFilters
    std::string searchValue = JSON_ASSTRING(dataTablesFilters["search"],"value","");
    std::string whereFilters = "";

    // Build the SQL query with WHERE clause for DataTables search
    std::string sqlQueryStr = R"(
        SELECT `scopeId`,`description` FROM iam.applicationScopes WHERE `f_appName` = :APPNAME
        )";


    // Add WHERE clause for search term if provided
    if (!searchValue.empty())
    {
        searchValue = "%" + searchValue + "%";
        whereFilters += "`scopeId` LIKE :SEARCHWORDS OR `description` LIKE :SEARCHWORDS";
    }

    {
        Abstract::STRING scopeId, description;
        SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelectWithFilters(sqlQueryStr,
                                                                                    whereFilters,
                                                                                    {
                                                                                        {":SEARCHWORDS", MAKE_VAR(STRING, searchValue)},
                                                                                        {":APPNAME", MAKE_VAR(STRING, appName)}
                                                                                    },
                                                                                    {&scopeId, &description},
                                                                                    orderByStatement, // Order by
                                                                                    limit, // LIMIT
                                                                                    offset // OFFSET
                                                                                    );

        while (i.getResultsOK() && i.query->step())
        {
            Json::Value row;

            // scopeId
            row["scopeId"] = scopeId.toJSON();
            // description
            row["description"] = description.toJSON();

            ret["data"].append(row);
        }

        ret["recordsTotal"] = i.query->getTotalRecordsCount();
        ret["recordsFiltered"] = i.query->getFilteredRecordsCount();
    }

    return ret;
}

bool IdentityManager_DB::AuthController_DB::validateAccountDirectApplicationScope(const std::string &accountName, const ApplicationScope &applicationScope)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `f_accountName` FROM iam.applicationScopeAccounts WHERE "
                                                                                      "`f_scopeId`=:scopeId AND `f_accountName`=:accountName AND `f_appName`=:appName;",
                                                                                      {{":scopeId", MAKE_VAR(STRING, applicationScope.id)},
                                                                                       {":appName", MAKE_VAR(STRING, applicationScope.appName)},
                                                                                       {":accountName", MAKE_VAR(STRING, accountName)}},
                                                                                      {});
    return (i.getResultsOK() && i.query->step());
}
