#include "identitymanager_db.h"
#include <Mantids30/Helpers/datatables.h>
#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_uint64.h>


using namespace Mantids30::Memory;
using namespace Mantids30::Database;
using namespace Mantids30;

bool IdentityManager_DB::ApplicationRoles_DB::createRole(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &roleName,
                                                      const std::string &roleDescription)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    bool success = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.applicationRoles (`f_appName`,`roleName`,`roleDescription`) VALUES(:appName,:roleName,:roleDescription);",
                                                       {{":appName", MAKE_VAR(STRING, appName)}, {":roleName", MAKE_VAR(STRING, roleName)}, {":roleDescription", MAKE_VAR(STRING, roleDescription)}});

    if (success)
    {
        _parent->logSecurityEventOnApplicationRoles(appName, roleName, "", SecurityEventAction::CREATE, "New application role added", performedBy, clientDetails);
    }

    return success;
}

bool IdentityManager_DB::ApplicationRoles_DB::removeRole(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &roleName)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    bool success = _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.applicationRoles WHERE `roleName`=:roleName AND `f_appName`=:appName;",
                                                       {{":roleName", MAKE_VAR(STRING, roleName)}, {":appName", MAKE_VAR(STRING, appName)}});

    if (success)
    {
        _parent->logSecurityEventOnApplicationRoles(appName, roleName, "", SecurityEventAction::DELETE, "Application role removed", performedBy, clientDetails);
    }

    return success;
}

bool IdentityManager_DB::ApplicationRoles_DB::doesRoleExist(const std::string &appName, const std::string &roleName)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);
    return _parent->m_sqlConnector->qSelectSingleRow("SELECT `roleName` FROM iam.applicationRoles WHERE `roleName`=:roleName AND `f_appName`=:appName;",
                                                     {{":roleName", MAKE_VAR(STRING, roleName)}, {":appName", MAKE_VAR(STRING, appName)}}, {});
}

bool IdentityManager_DB::ApplicationRoles_DB::_addAccountToRole(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &roleName, const std::string &accountUUID)
{
    bool success = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.applicationRolesAccounts (`f_roleName`,`f_accountUUID`,`f_appName`) VALUES(:roleName,:accountUUID,:appName);",
                                                       {{":roleName", MAKE_VAR(STRING, roleName)}, {":appName", MAKE_VAR(STRING, appName)}, {":accountUUID", MAKE_VAR(STRING, accountUUID)}});

    if (success)
    {
        _parent->logSecurityEventOnApplicationRoles(appName, roleName, accountUUID, SecurityEventAction::ASSIGN_ACCOUNT, "Account added to role", performedBy, clientDetails);
    }

    return success;
}


bool IdentityManager_DB::ApplicationRoles_DB::addAccountToRole(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &roleName,
                                                               const std::string &accountUUID)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    return _addAccountToRole(clientDetails,performedBy,appName,roleName,accountUUID);
}

bool IdentityManager_DB::ApplicationRoles_DB::removeAccountFromRole(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &roleName,
                                                                    const std::string &accountUUID, bool lock)
{
    bool ret = false;

    if (lock)
    {
        _parent->m_mutex.lock();
    }

    ret = _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.applicationRolesAccounts WHERE `f_roleName`=:roleName AND `f_appName`=:appName AND `f_accountUUID`=:accountUUID;",
                                              {{":roleName", MAKE_VAR(STRING, roleName)}, {":appName", MAKE_VAR(STRING, appName)}, {":accountUUID", MAKE_VAR(STRING, accountUUID)}});

    if (ret)
    {
        _parent->logSecurityEventOnApplicationRoles(appName, roleName, accountUUID, SecurityEventAction::REVOKE_ACCOUNT, "Account removed from role", performedBy, clientDetails);
    }

    if (lock)
    {
        _parent->m_mutex.unlock();
    }
    return ret;
}

bool IdentityManager_DB::ApplicationRoles_DB::updateRoleDescription(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &roleName,
                                                                    const std::string &roleDescription)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    bool success = _parent->m_sqlConnector->qExecuteEx("UPDATE iam.applicationRoles SET `roleDescription`=:roleDescription WHERE `roleName`=:roleName AND `f_appName`=:appName;",
                                                       {{":roleName", MAKE_VAR(STRING, roleName)}, {":roleDescription", MAKE_VAR(STRING, roleDescription)}, {":appName", MAKE_VAR(STRING, appName)}});

    if (success)
    {
        _parent->logSecurityEventOnApplicationRoles(appName, roleName, "", SecurityEventAction::UPDATE, "Application role description updated", performedBy, clientDetails);
    }

    return success;
}

std::set<std::string> IdentityManager_DB::ApplicationRoles_DB::listApplicationScopesOnApplicationRole(const std::string &appName, const std::string &roleName)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);
    std::set<std::string> scopes;
    Abstract::STRING scopeId;
    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `f_scopeId` FROM iam.applicationRolesScopes WHERE `f_appName`=:appName AND `f_roleName`=:roleName;",
                                                                {{":appName", MAKE_VAR(STRING, appName)}, {":roleName", MAKE_VAR(STRING, roleName)}}, {&scopeId});
    if (i && i->isSuccessful())
    {
        while (i->step())
        {
            scopes.insert(scopeId.getValue());
        }
    }
    return scopes;
}

std::string IdentityManager_DB::ApplicationRoles_DB::getApplicationRoleDescription(const std::string &appName, const std::string &roleName)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);
    Abstract::STRING roleDescription;
    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `roleDescription` FROM iam.applicationRoles WHERE `roleName`=:roleName AND `f_appName`=:appName LIMIT 1;",
                                                  {{":roleName", MAKE_VAR(STRING, roleName)}, {":appName", MAKE_VAR(STRING, appName)}}, {&roleDescription}))
    {
        return roleDescription.getValue();
    }
    return "";
}

std::set<ApplicationRole> IdentityManager_DB::ApplicationRoles_DB::getApplicationRolesList(const std::string &appName)
{
    std::set<ApplicationRole> ret;
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    Abstract::STRING roleName, description;
    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `roleName`,`roleDescription` FROM iam.applicationRoles WHERE `f_appName`=:appName;", {{":appName", MAKE_VAR(STRING, appName)}},
                                                                {&roleName, &description});
    while (i && i->isSuccessful() && i->step())
    {
        ApplicationRole r;

        r.appName = appName;
        r.description = description.getValue();
        r.id = roleName.getValue();

        ret.insert(r);
    }
    return ret;
}

std::set<std::string> IdentityManager_DB::ApplicationRoles_DB::getApplicationRoleAccounts(const std::string &appName, const std::string &roleName, bool lock)
{
    std::set<std::string> ret;
    if (lock)
    {
        _parent->m_mutex.lock_shared();
    }

    Abstract::STRING accountUUID;
    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `f_accountUUID` FROM iam.applicationRolesAccounts WHERE `f_roleName`=:roleName AND `f_appName`=:appName;",
                                                                {{":appName", MAKE_VAR(STRING, appName)}, {":roleName", MAKE_VAR(STRING, roleName)}}, {&accountUUID});
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

Json::Value IdentityManager_DB::ApplicationRoles_DB::searchApplicationRoles(const Json::Value &dataTablesFilters)
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
        SELECT `roleName`,`roleDescription` FROM iam.applicationRoles WHERE `f_appName` = :APPNAME
        )";

    // Add WHERE clause for search term if provided
    if (!searchValue.empty())
    {
        searchValue = "%" + searchValue + "%";
        whereFilters += "roleName LIKE :SEARCHWORDS OR roleDescription LIKE :SEARCHWORDS";
    }

    {
        Abstract::STRING roleName, roleDescription;
        std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelectWithFilters(sqlQueryStr, whereFilters, {{":SEARCHWORDS", MAKE_VAR(STRING, searchValue)}, {":APPNAME", MAKE_VAR(STRING, appName)}},
                                                                               {&roleName, &roleDescription},
                                                                               orderByStatement, // Order by
                                                                               limit,            // LIMIT
                                                                               offset            // OFFSET
        );

        while (i && i->isSuccessful() && i->step())
        {
            Json::Value row;

            // roleName
            row["roleName"] = roleName.getValue();
            // roleDescription
            row["roleDescription"] = roleDescription.getValue();

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

