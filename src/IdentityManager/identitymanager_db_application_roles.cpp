#include "Mantids30/Memory/a_bool.h"
#include "Mantids30/Memory/a_datetime.h"
#include "identitymanager_db.h"
#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_uint64.h>
#include <Mantids30/Threads/lock_shared.h>

using namespace Mantids30::Memory;
using namespace Mantids30::Database;
using namespace Mantids30;

bool IdentityManager_DB::ApplicationRoles_DB::addRole(const std::string &appName, const std::string &roleName, const std::string &roleDescription)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("INSERT INTO iam.applicationRoles (`f_appName`,`roleName`,`roleDescription`) VALUES(:appName,:roleName,:roleDescription);",
                                          {{":appName", MAKE_VAR(STRING, appName)}, {":roleName", MAKE_VAR(STRING, roleName)}, {":roleDescription", MAKE_VAR(STRING, roleDescription)}});
}

bool IdentityManager_DB::ApplicationRoles_DB::removeRole(const std::string &appName, const std::string &roleName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("DELETE FROM iam.applicationRoles WHERE `roleName`=:roleName AND `f_appName`=:appName;",
                                          {{":roleName", MAKE_VAR(STRING, roleName)}, {":appName", MAKE_VAR(STRING, appName)}});
}

bool IdentityManager_DB::ApplicationRoles_DB::doesRoleExist(const std::string &appName, const std::string &roleName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `roleName` FROM iam.applicationRoles WHERE `roleName`=:roleName AND `f_appName`=:appName;",
                                                                     {{":roleName", MAKE_VAR(STRING, roleName)}, {":appName", MAKE_VAR(STRING, appName)}}, {});
    return (i.getResultsOK()) && i.query->step();
}

bool IdentityManager_DB::ApplicationRoles_DB::addAccountToRole(const std::string &appName, const std::string &roleName, const std::string &accountName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("INSERT INTO iam.applicationRolesAccounts (`f_roleName`,`f_accountName`,`f_appName`) VALUES(:roleName,:accountName,:appName);",
                                          {{":roleName", MAKE_VAR(STRING, roleName)},{":appName", MAKE_VAR(STRING, appName)},{":accountName", MAKE_VAR(STRING, accountName)}});
}

bool IdentityManager_DB::ApplicationRoles_DB::removeAccountFromRole(const std::string &appName, const std::string &roleName, const std::string &accountName, bool lock)
{
    bool ret = false;
    if (lock)
        _parent->m_mutex.lock();
    ret = _parent->m_sqlConnector->execute("DELETE FROM iam.applicationRolesAccounts WHERE `f_roleName`=:roleName AND `f_appName`=:appName AND `f_accountName`=:accountName;",
                                         {{":roleName", MAKE_VAR(STRING, roleName)},{":appName", MAKE_VAR(STRING, appName)}, {":accountName", MAKE_VAR(STRING, accountName)}});

    if (lock)
        _parent->m_mutex.unlock();
    return ret;
}

bool IdentityManager_DB::ApplicationRoles_DB::updateRoleDescription(const std::string &appName, const std::string &roleName, const std::string &roleDescription)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("UPDATE iam.applicationRoles SET `roleDescription`=:roleDescription WHERE `roleName`=:roleName AND `f_appName`=:appName;",
                                          {{":roleName", MAKE_VAR(STRING, roleName)}, {":roleDescription", MAKE_VAR(STRING, roleDescription)}, {":appName", MAKE_VAR(STRING, appName)}});
}

std::string IdentityManager_DB::ApplicationRoles_DB::getApplicationRoleDescription(const std::string &appName, const std::string &roleName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    Abstract::STRING roleDescription;
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `roleDescription` FROM iam.applicationRoles WHERE `roleName`=:roleName AND `f_appName`=:appName LIMIT 1;",
                                                                                      {{":roleName", MAKE_VAR(STRING, roleName)}, {":appName", MAKE_VAR(STRING, appName)}}, {&roleDescription});
    if (i.getResultsOK() && i.query->step())
    {
        return roleDescription.getValue();
    }
    return "";
}

std::set<ApplicationRole> IdentityManager_DB::ApplicationRoles_DB::getApplicationRolesList(const std::string &appName)
{
    std::set<ApplicationRole> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING roleId, description;
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `roleName`,`roleDescription` FROM iam.applicationRoles WHERE `f_appName`=:appName;", {{":appName", MAKE_VAR(STRING, appName)}}, {&roleId,&description});
    while (i.getResultsOK() && i.query->step())
    {
        ApplicationRole r;

        r.appName = appName;
        r.description = description.getValue();
        r.id = roleId.getValue();

        ret.insert(r);
    }
    return ret;
}

std::set<std::string> IdentityManager_DB::ApplicationRoles_DB::getApplicationRoleAccounts(const std::string &appName, const std::string &roleName, bool lock)
{
    std::set<std::string> ret;
    if (lock)
        _parent->m_mutex.lockShared();

    Abstract::STRING accountName;
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `f_accountName` FROM iam.applicationRolesAccounts WHERE `f_roleName`=:roleName AND `f_appName`=:appName;",
                                                                                      {{":appName", MAKE_VAR(STRING, appName)},{":roleName", MAKE_VAR(STRING, roleName)}}, {&accountName});
    while (i.getResultsOK() && i.query->step())
    {
        ret.insert(accountName.getValue());
    }

    if (lock)
        _parent->m_mutex.unlockShared();
    return ret;
}

Json::Value IdentityManager_DB::ApplicationRoles_DB::searchApplicationRoles(const json &dataTablesFilters)
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
                "roleName", "roleDescription"
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
        SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelectWithFilters(sqlQueryStr,
                                                                                    whereFilters,
                                                                                    {
                                                                                     {":SEARCHWORDS", MAKE_VAR(STRING, searchValue)},
                                                                                     {":APPNAME", MAKE_VAR(STRING, appName)}
                                                                                    },
                                                                                    {&roleName, &roleDescription},
                                                                                    orderByStatement, // Order by
                                                                                    limit, // LIMIT
                                                                                    offset // OFFSET
                                                                                    );

        while (i.getResultsOK() && i.query->step())
        {
            Json::Value row;

            // roleName
            row["roleName"] = roleName.toJSON();
            // roleDescription
            row["roleDescription"] = roleDescription.toJSON();

            ret["data"].append(row);
        }

        ret["recordsTotal"] = i.query->getTotalRecordsCount();
        ret["recordsFiltered"] = i.query->getFilteredRecordsCount();
    }

    return ret;
}
