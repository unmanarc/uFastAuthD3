#include "identitymanager_db.h"
#include <Mantids30/Helpers/datatables.h>
#include <Mantids30/Threads/lock_shared.h>

#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_uint64.h>

using namespace Mantids30;
using namespace Mantids30::Memory;
using namespace Mantids30::Database;

bool IdentityManager_DB::ApplicationScopes_DB::validateApplicationScopeOnRole(const std::string &roleName, const ApplicationScope &scope, bool lock)
{
    bool ret = false;
    if (lock)
    {
        _parent->m_mutex.lock_shared();
    }

    ret = _parent->m_sqlConnector->qSelectSingleRow("SELECT `f_roleName` FROM iam.applicationRolesScopes WHERE `f_scopeId`=:scopeId AND `f_appName`=:appName AND `f_roleName`=:roleName;",
                                                    {{":scopeId", MAKE_VAR(STRING, scope.id)}, {":appName", MAKE_VAR(STRING, scope.appName)}, {":roleName", MAKE_VAR(STRING, roleName)}}, {});

    if (lock)
    {
        _parent->m_mutex.unlock_shared();
    }

    return ret;
}

std::set<ApplicationScope> IdentityManager_DB::ApplicationScopes_DB::getRoleApplicationScopes(const std::string &appName, const std::string &roleName, bool lock)
{
    std::set<ApplicationScope> ret;

    if (lock)
    {
        _parent->m_mutex.lock_shared();
    }

    Abstract::STRING sScopeName, sDescription;
    std::shared_ptr<Query> i = _parent->m_sqlConnector
                                   ->qSelect("SELECT ars.`f_scopeId`,ascope.description FROM iam.applicationRolesScopes ars LEFT JOIN iam.applicationScopes ascope ON (ars.`f_scopeId` = "
                                             "ascope.scopeId AND ars.`f_appName` = ascope.f_appName) WHERE ars.`f_roleName`=:roleName AND ars.`f_appName`=:appName;",
                                             {{":roleName", MAKE_VAR(STRING, roleName)}, {":appName", MAKE_VAR(STRING, appName)}}, {&sScopeName, &sDescription});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert({appName, sScopeName.getValue(), sDescription.getValue()});
    }

    if (lock)
    {
        _parent->m_mutex.unlock_shared();
    }

    return ret;
}

std::set<std::string> IdentityManager_DB::ApplicationScopes_DB::getApplicationRolesForScope(const ApplicationScope &applicationScope, bool lock)
{
    std::set<std::string> ret;
    if (lock)
    {
        _parent->m_mutex.lock_shared();
    }

    Abstract::STRING roleName;
    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `f_roleName` FROM iam.applicationRolesScopes WHERE `f_scopeId`=:scopeId AND `f_appName`=:appName;",
                                                                {{":appName", MAKE_VAR(STRING, applicationScope.appName)}, {":scopeId", MAKE_VAR(STRING, applicationScope.id)}}, {&roleName});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert(roleName.getValue());
    }

    if (lock)
    {
        _parent->m_mutex.unlock_shared();
    }
    return ret;
}
std::set<ApplicationScope> IdentityManager_DB::ApplicationScopes_DB::getAccountDirectApplicationScopes(const std::string &accountUUID, bool lock)
{
    std::set<ApplicationScope> ret;
    if (lock)
    {
        _parent->m_mutex.lock_shared();
    }

    Abstract::STRING appName, scopeId;
    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `f_appName`,`f_scopeId` FROM iam.applicationScopeAccounts WHERE `f_accountUUID`=:accountUUID;",
                                                                {{":accountUUID", MAKE_VAR(STRING, accountUUID)}}, {&appName, &scopeId});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert({appName.getValue(), scopeId.getValue()});
    }

    if (lock)
    {
        _parent->m_mutex.unlock_shared();
    }
    return ret;
}

bool IdentityManager_DB::ApplicationScopes_DB::createApplicationScope(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    bool success = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.applicationScopes (`f_appName`,`scopeId`,`description`) VALUES(:appName,:scopeId,:description);",
                                                       {{":appName", MAKE_VAR(STRING, applicationScope.appName)},
                                                        {":scopeId", MAKE_VAR(STRING, applicationScope.id)},
                                                        {":description", MAKE_VAR(STRING, applicationScope.description)}});

    if (success)
    {
        _parent->logSecurityEventApplicationScopes(applicationScope.appName, applicationScope.id, "", SecurityEventAction::CREATE, "New application scope added", performedBy, clientDetails);
    }

    return success;
}

bool IdentityManager_DB::ApplicationScopes_DB::removeApplicationScope(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    bool success = _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.applicationScopes WHERE `scopeId`=:scopeId and `f_appName`=:appName;",
                                                       {{":appName", MAKE_VAR(STRING, applicationScope.appName)}, {":scopeId", MAKE_VAR(STRING, applicationScope.id)}});

    if (success)
    {
        _parent->logSecurityEventApplicationScopes(applicationScope.appName, applicationScope.id, "", SecurityEventAction::DELETE, "Application scope removed", performedBy, clientDetails);
    }

    return success;
}

bool IdentityManager_DB::ApplicationScopes_DB::doesApplicationScopeExist(const ApplicationScope &applicationScope)
{
    bool ret = false;
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `description` FROM iam.applicationScopes WHERE `scopeId`=:scopeId and `f_appName`=:appName LIMIT 1;",
                                                  {{":appName", MAKE_VAR(STRING, applicationScope.appName)}, {":scopeId", MAKE_VAR(STRING, applicationScope.id)}}, {}))
    {
        ret = true;
    }
    return ret;
}

bool IdentityManager_DB::ApplicationScopes_DB::addApplicationScopeToRole(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope,
                                                                         const std::string &roleName)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);

    bool success = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.applicationRolesScopes (`f_appName`,`f_scopeId`,`f_roleName`) VALUES(:appName,:scopeId,:roleName);",
                                                       {{":appName", MAKE_VAR(STRING, applicationScope.appName)},
                                                        {":scopeId", MAKE_VAR(STRING, applicationScope.id)},
                                                        {":roleName", MAKE_VAR(STRING, roleName)}});

    if (success)
    {
        _parent->logSecurityEventApplicationScopes(applicationScope.appName, applicationScope.id, roleName, SecurityEventAction::ASSIGN_ROLE, "Application scope added to role", performedBy,
                                                   clientDetails);
    }

    return success;
}

bool IdentityManager_DB::ApplicationScopes_DB::removeApplicationScopeFromRole(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope,
                                                                              const std::string &roleName, bool lock)
{
    bool ret = false;
    if (lock)
    {
        _parent->m_mutex.lock();
    }
    ret = _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.applicationRolesScopes WHERE `f_scopeId`=:scopeId and `f_appName`=:appName AND `f_roleName`=:roleName;",
                                              {{":appName", MAKE_VAR(STRING, applicationScope.appName)},
                                               {":scopeId", MAKE_VAR(STRING, applicationScope.id)},
                                               {":roleName", MAKE_VAR(STRING, roleName)}});

    if (ret)
    {
        _parent->logSecurityEventApplicationScopes(applicationScope.appName, applicationScope.id, roleName, SecurityEventAction::REVOKE_ROLE, "Application scope removed from role", performedBy,
                                                   clientDetails);
    }

    if (lock)
    {
        _parent->m_mutex.unlock();
    }
    return ret;
}

bool IdentityManager_DB::ApplicationScopes_DB::_addApplicationScopeToAccount(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope,
                                                                             const std::string &accountUUID)
{
    bool success = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.applicationScopeAccounts (`f_appName`,`f_scopeId`,`f_accountUUID`) VALUES(:appName,:scopeId,:accountUUID);",
                                                       {{":appName", MAKE_VAR(STRING, applicationScope.appName)},
                                                        {":scopeId", MAKE_VAR(STRING, applicationScope.id)},
                                                        {":accountUUID", MAKE_VAR(STRING, accountUUID)}});

    if (success)
    {
        _parent->logSecurityEventApplicationScopes(applicationScope.appName, applicationScope.id, accountUUID, SecurityEventAction::ASSIGN_ACCOUNT, "Application scope added to account", performedBy,
                                                   clientDetails);
    }

    return success;
}

bool IdentityManager_DB::ApplicationScopes_DB::addApplicationScopeToAccount(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope,
                                                                            const std::string &accountUUID)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    return _addApplicationScopeToAccount(clientDetails, performedBy, applicationScope, accountUUID);
}

bool IdentityManager_DB::ApplicationScopes_DB::removeApplicationScopeFromAccount(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope,
                                                                                 const std::string &accountUUID, bool lock)
{
    bool ret = false;
    if (lock)
    {
        _parent->m_mutex.lock();
    }
    ret = _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.applicationScopeAccounts WHERE `f_scopeId`=:scopeId AND `f_appName`=:appName AND `f_accountUUID`=:accountUUID;",
                                              {{":appName", MAKE_VAR(STRING, applicationScope.appName)},
                                               {":scopeId", MAKE_VAR(STRING, applicationScope.id)},
                                               {":accountUUID", MAKE_VAR(STRING, accountUUID)}});

    if (ret)
    {
        _parent->logSecurityEventApplicationScopes(applicationScope.appName, applicationScope.id, accountUUID, SecurityEventAction::REVOKE_ACCOUNT, "Application scope removed from account",
                                                   performedBy, clientDetails);
    }

    if (lock)
    {
        _parent->m_mutex.unlock();
    }
    return ret;
}

bool IdentityManager_DB::ApplicationScopes_DB::updateApplicationScopeDescription(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    bool success = _parent->m_sqlConnector->qExecuteEx("UPDATE iam.applicationScopes SET `description`=:description WHERE `scopeId`=:scopeId AND `f_appName`=:appName;",
                                                       {{":appName", MAKE_VAR(STRING, applicationScope.appName)},
                                                        {":scopeId", MAKE_VAR(STRING, applicationScope.id)},
                                                        {":description", MAKE_VAR(STRING, applicationScope.description)}});

    if (success)
    {
        _parent->logSecurityEventApplicationScopes(applicationScope.appName, applicationScope.id, "", SecurityEventAction::UPDATE, "Application scope description updated", performedBy, clientDetails);
    }

    return success;
}

std::string IdentityManager_DB::ApplicationScopes_DB::getApplicationScopeDescription(const ApplicationScope &applicationScope)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::STRING description;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `description` FROM iam.applicationScopes WHERE `scopeId`=:scopeId AND `f_appName`=:appName LIMIT 1;",
                                                  {{":appName", MAKE_VAR(STRING, applicationScope.appName)}, {":scopeId", MAKE_VAR(STRING, applicationScope.id)}}, {&description}))
    {
        return description.getValue();
    }
    return "";
}

std::set<ApplicationScope> IdentityManager_DB::ApplicationScopes_DB::listApplicationScopes(const std::string &applicationName)
{
    std::set<ApplicationScope> ret;
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::STRING sAppName, sScopeId, sDescription;

    std::string sqlQuery = "SELECT `f_appName`,`scopeId` FROM iam.applicationScopes;";
    if (!applicationName.empty())
    {
        sqlQuery = "SELECT `f_appName`,`scopeId`,`description` FROM iam.applicationScopes WHERE "
                   "`f_appName`=:appName;";
    }

    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect(sqlQuery, {{":appName", MAKE_VAR(STRING, applicationName)}}, {&sAppName, &sScopeId, &sDescription});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert({sAppName.getValue(), sScopeId.getValue(), sDescription.getValue()});
    }
    return ret;
}

std::set<std::string> IdentityManager_DB::ApplicationScopes_DB::listAccountsOnApplicationScope(const ApplicationScope &applicationScope, bool lock)
{
    std::set<std::string> ret;
    if (lock)
    {
        _parent->m_mutex.lock_shared();
    }

    Abstract::STRING accountUUID;
    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `f_accountUUID` FROM iam.applicationScopeAccounts WHERE `f_scopeId`=:scopeId AND `f_appName`=:appName;",
                                                                {{":appName", MAKE_VAR(STRING, applicationScope.appName)}, {":scopeId", MAKE_VAR(STRING, applicationScope.id)}}, {&accountUUID});
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert(accountUUID.getValue());
    }

    if (lock)
    {
        _parent->m_mutex.unlock_shared();
    }
    return ret;
}

Json::Value IdentityManager_DB::ApplicationScopes_DB::searchApplicationScopes(const Json::Value &dataTablesFilters)
{
    Json::Value ret;
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    // DataTables:
    ret["draw"] = dataTablesFilters["draw"];

    std::string appName = Helpers::JSON::ASSTRING(dataTablesFilters, "appName", "");

    uint64_t offset = Helpers::JSON::ASUINT64(dataTablesFilters, "start", 0);
    uint64_t limit = Helpers::JSON::ASUINT64(dataTablesFilters, "length", 0);

    // Manejo de ordenamiento (order)
    std::string orderByStatement = Helpers::DataTables::getOrderByStatement(dataTablesFilters);

    // Extract the search value from dataTablesFilters
    std::string searchValue = Helpers::JSON::ASSTRING(dataTablesFilters["search"], "value", "");
    std::string whereFilters;

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
        std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelectWithFilters(sqlQueryStr, whereFilters, {{":SEARCHWORDS", MAKE_VAR(STRING, searchValue)}, {":APPNAME", MAKE_VAR(STRING, appName)}},
                                                                               {&scopeId, &description},
                                                                               orderByStatement, // Order by
                                                                               limit,            // LIMIT
                                                                               offset            // OFFSET
        );

        while (i && i->isSuccessful() && i->step())
        {
            Json::Value row;

            // scopeId
            row["scopeId"] = scopeId.getValue();
            // description
            row["description"] = description.getValue();

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

bool IdentityManager_DB::ApplicationScopes_DB::validateAccountDirectApplicationScope(const std::string &accountUUID, const ApplicationScope &applicationScope)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    return _parent->m_sqlConnector->qSelectSingleRow("SELECT `f_accountUUID` FROM iam.applicationScopeAccounts WHERE "
                                                     "`f_scopeId`=:scopeId AND `f_accountUUID`=:accountUUID AND `f_appName`=:appName;",
                                                     {{":scopeId", MAKE_VAR(STRING, applicationScope.id)},
                                                      {":appName", MAKE_VAR(STRING, applicationScope.appName)},
                                                      {":accountUUID", MAKE_VAR(STRING, accountUUID)}},
                                                     {});
}
