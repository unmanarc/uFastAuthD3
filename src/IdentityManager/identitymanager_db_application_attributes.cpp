#include "identitymanager_db.h"
#include <Mantids30/Threads/lock_shared.h>

#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_uint64.h>

using namespace Mantids30;
using namespace Mantids30::Memory;
using namespace Mantids30::Database;

bool IdentityManager_DB::AuthController_DB::addApplicationScope(const ApplicationScope &applicationScope, const std::string &sDescription)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("INSERT INTO iam.applicationScopes (`f_appName`,`scopeId`,`description`) VALUES(:appName,:scopeId,:description);",
                                          {{":appName", MAKE_VAR(STRING, applicationScope.appName)},
                                           {":scopeId", MAKE_VAR(STRING, applicationScope.id)},
                                           {":description", MAKE_VAR(STRING, sDescription)}});
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

    return _parent->m_sqlConnector->execute("INSERT INTO iam.applicationScopeRoles (`f_appName`,`f_scopeId`,`f_roleName`) VALUES(:appName,:scopeId,:roleName);",
                                          {{":appName", MAKE_VAR(STRING, applicationScope.appName)},
                                           {":scopeId", MAKE_VAR(STRING, applicationScope.id)},
                                           {":roleName", MAKE_VAR(STRING, roleName)}});
}

bool IdentityManager_DB::AuthController_DB::removeApplicationScopeFromRole(const ApplicationScope &applicationScope, const std::string &roleName, bool lock)
{
    bool ret = false;
    if (lock)
        _parent->m_mutex.lock();
    ret = _parent->m_sqlConnector->execute("DELETE FROM iam.applicationScopeRoles WHERE `f_scopeId`=:scopeId and `f_appName`=:appName AND `f_roleName`=:roleName;",
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

bool IdentityManager_DB::AuthController_DB::updateApplicationScopeDescription(const ApplicationScope &applicationScope, const std::string &description)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);
    return _parent->m_sqlConnector->execute("UPDATE iam.applicationScopes SET `description`=:description WHERE `scopeId`=:scopeId AND `f_appName`=:appName;",
                                          {{":appName", MAKE_VAR(STRING, applicationScope.appName)},
                                           {":scopeId", MAKE_VAR(STRING, applicationScope.id)},
                                           {":description", MAKE_VAR(STRING, description)}});
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

    Abstract::STRING sAppName, sScopeId;

    std::string sqlQuery = "SELECT `f_appName`,`scopeId` FROM iam.applicationScopes;";
    if (!applicationName.empty())
        sqlQuery = "SELECT `f_appName`,`scopeId` FROM iam.applicationScopes WHERE `f_appName`=:appName;";

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect(sqlQuery, {{":appName", MAKE_VAR(STRING, applicationName)}}, {&sAppName, &sScopeId});
    while (i.getResultsOK() && i.query->step())
    {
        ret.insert({sAppName.getValue(), sScopeId.getValue()});
    }
    return ret;
}

std::set<std::string> IdentityManager_DB::AuthController_DB::getApplicationScopesForRole(const ApplicationScope &applicationScope, bool lock)
{
    std::set<std::string> ret;
    if (lock)
        _parent->m_mutex.lockShared();

    Abstract::STRING roleName;
    SQLConnector::QueryInstance i
        = _parent->m_sqlConnector->qSelect("SELECT `f_roleName` FROM iam.applicationScopeRoles WHERE `f_scopeId`=:scopeId AND `f_appName`=:appName;",
                                           {{":appName", MAKE_VAR(STRING, applicationScope.appName)}, {":scopeId", MAKE_VAR(STRING, applicationScope.id)}}, {&roleName});
    while (i.getResultsOK() && i.query->step())
    {
        ret.insert(roleName.getValue());
    }

    if (lock)
        _parent->m_mutex.unlockShared();
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

std::list<ApplicationScopeDetails> IdentityManager_DB::AuthController_DB::searchApplicationScopes(const std::string &appName, std::string sSearchWords, size_t limit, size_t offset)
{
    std::list<ApplicationScopeDetails> ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING scopeId, description;

    std::string sSqlQuery = "SELECT `scopeId`,`description` FROM iam.applications WHERE `f_appName`=:APPNAME";

    if (!sSearchWords.empty())
    {
        sSearchWords = '%' + sSearchWords + '%';
        sSqlQuery += " AND (`applicationName` LIKE :SEARCHWORDS OR `appDescription` LIKE :SEARCHWORDS)";
    }

    if (limit)
        sSqlQuery += " LIMIT :LIMIT OFFSET :OFFSET";

    sSqlQuery += ";";

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect(sSqlQuery,
                                                                                      {{":APPNAME", MAKE_VAR(STRING, appName)},
                                                                                       {":SEARCHWORDS", MAKE_VAR(STRING, sSearchWords)},
                                                                                       {":LIMIT", MAKE_VAR(UINT64, limit)},
                                                                                       {":OFFSET", MAKE_VAR(UINT64, offset)}},
                                                                                      {&scopeId, &description});
    while (i.getResultsOK() && i.query->step())
    {
        ApplicationScopeDetails rDetail;

        rDetail.description = description.getValue();
        rDetail.id = scopeId.getValue();

        ret.push_back(rDetail);
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
