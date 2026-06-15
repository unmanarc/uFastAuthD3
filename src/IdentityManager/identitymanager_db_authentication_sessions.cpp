#include "identitymanager_db.h"

#include <Mantids30/Helpers/datatables.h>
#include <Mantids30/Threads/lock_shared.h>

#include <Mantids30/Memory/a_bool.h>
#include <Mantids30/Memory/a_datetime.h>
#include <Mantids30/Memory/a_int32.h>
#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_uint32.h>
#include <Mantids30/Memory/a_uint64.h>
#include <Mantids30/Memory/a_var.h>
#include <memory>

using namespace Mantids30::Memory;
using namespace Mantids30::Database;
using namespace Mantids30;

uint32_t IdentityManager_DB::AuthController_DB::getAccountActiveSessionsCount(const std::string &accountName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    time_t now = time(nullptr);
    Abstract::UINT32 count;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT COUNT(*) FROM logs.applicationAccess_accountSessions "
                                                  "WHERE `f_accountName`=:accountName "
                                                  "  AND `logoutDateTime` IS NULL "
                                                  "  AND `refreshTokenExpiration` > CURRENT_TIMESTAMP; ",
                                                  {{":accountName", MAKE_VAR(STRING, accountName)}, {":now", MAKE_VAR(DATETIME, now)}}, {&count}))
    {
        return count.getValue();
    }
    return 0;
}

Json::Value IdentityManager_DB::AuthController_DB::searchAccountSessions(const std::string &accountName, const json &dataTablesFilters)
{
    Json::Value ret;
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    ret["draw"] = dataTablesFilters["draw"];

    uint64_t offset = JSON_ASUINT64(dataTablesFilters, "start", 0);
    uint64_t limit = JSON_ASUINT64(dataTablesFilters, "length", 0);

    std::string orderByStatement = Helpers::DataTables::getOrderByStatement(dataTablesFilters);
    std::string searchValue = JSON_ASSTRING(dataTablesFilters["search"], "value", "");
    std::string whereFilters = "`f_accountName` = :ACCOUNTNAME";

    std::string sqlQueryStr = R"(
           SELECT `f_accountName`, `f_schemeId`, `f_appName`,
                  `loginDateTime`, `loginIP`, `loginTLSCN`, `loginUserAgent`,
                  `refresherTokenId`, `accessTokenId`,
                  `accessTokenExpiration`, `refreshTokenExpiration`,
                  `logoutDateTime`, `logoutReason`
           FROM logs.applicationAccess_accountSessions
           )";

    // Build params map
    std::map<std::string, std::shared_ptr<Abstract::Var>> params;
    params[":ACCOUNTNAME"] = MAKE_VAR(STRING, accountName);

    if (!searchValue.empty())
    {
        searchValue = "%" + searchValue + "%";
        whereFilters += " AND (`f_appName` LIKE :SEARCH OR `loginIP` LIKE :SEARCH)";
        params[":SEARCH"] = MAKE_VAR(STRING, searchValue);
    }

    {
        Abstract::STRING f_accountName, f_schemeId, f_appName, loginDateTime, loginIP, loginTLSCN, loginUserAgent;
        Abstract::STRING refresherTokenId, accessTokenId;
        Abstract::DATETIME accessTokenExpiration, refreshTokenExpiration, logoutDateTime;
        Abstract::UINT32 logoutReason;

        std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelectWithFilters(sqlQueryStr, whereFilters, params,
                                                                               {&f_accountName, &f_schemeId, &f_appName, &loginDateTime, &loginIP, &loginTLSCN, &loginUserAgent, &refresherTokenId,
                                                                                &accessTokenId, &accessTokenExpiration, &refreshTokenExpiration, &logoutDateTime, &logoutReason},
                                                                               orderByStatement, limit, offset);

        while (i && i->isSuccessful() && i->step())
        {
            Json::Value row;
            row["f_accountName"] = f_accountName.toJSON();
            row["f_schemeId"] = f_schemeId.toJSON();
            row["f_appName"] = f_appName.toJSON();
            row["loginDateTime"] = loginDateTime.toJSON();
            row["loginIP"] = loginIP.toJSON();
            row["loginTLSCN"] = loginTLSCN.toJSON();
            row["loginUserAgent"] = loginUserAgent.toJSON();
            row["refresherTokenId"] = refresherTokenId.toJSON();
            row["accessTokenId"] = accessTokenId.toJSON();
            row["accessTokenExpiration"] = accessTokenExpiration.toJSON();
            row["refreshTokenExpiration"] = refreshTokenExpiration.toJSON();
            row["logoutDateTime"] = logoutDateTime.toJSON();
            row["logoutReason"] = logoutReason.toJSON();

            // Flag: session is still active?
            row["isActive"] = (logoutDateTime.isNull() && accessTokenExpiration.isInFuture() && refreshTokenExpiration.isInFuture());

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

void IdentityManager_DB::AuthController_DB::markExpiredAuthLogSessions()
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    time_t now = time(nullptr);

    // Mark entries where refreshToken has expired (covers both access and refresh)
    _parent->m_sqlConnector->qExecuteEx(
        R"(UPDATE logs.applicationAccess_accountSessions
           SET logoutReason = 2, logoutDateTime = CURRENT_TIMESTAMP
           WHERE refreshTokenExpiration < CURRENT_TIMESTAMP
           AND logoutReason IS NULL)",
        {{":now", MAKE_VAR(DATETIME, now)}});
}
