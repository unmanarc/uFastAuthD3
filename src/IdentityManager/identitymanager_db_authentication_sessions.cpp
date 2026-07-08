#include "identitymanager_db.h"

#include <Mantids30/Helpers/datatables.h>


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

uint32_t IdentityManager_DB::AuthController_DB::getAccountActiveSessionsCount(const std::string &accountUUID)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    time_t now = time(nullptr);
    Abstract::UINT32 count;

    if (_parent->m_sqlConnector->qSelectSingleRow("SELECT COUNT(*) FROM logs.applicationAccess_accountSessions "
                                                  "WHERE `f_accountUUID`=:accountUUID "
                                                  "  AND `logoutDateTime` IS NULL "
                                                  "  AND `refreshTokenExpiration` > CURRENT_TIMESTAMP; ",
                                                  {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":now", MAKE_VAR(DATETIME, now)}}, {&count}))
    {
        return count.getValue();
    }
    return 0;
}

Json::Value IdentityManager_DB::AuthController_DB::searchAccountSessions(const std::string &accountUUID, const Json::Value &dataTablesFilters)
{
    Json::Value ret;
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    ret["draw"] = dataTablesFilters["draw"];

    uint64_t offset = Helpers::JSON::ASUINT64(dataTablesFilters, "start", 0);
    uint64_t limit = Helpers::JSON::ASUINT64(dataTablesFilters, "length", 0);

    std::string orderByStatement = Helpers::DataTables::getOrderByStatement(dataTablesFilters);
    std::string searchValue = Helpers::JSON::ASSTRING(dataTablesFilters["search"], "value", "");
    std::string whereFilters = "`f_accountUUID` = :ACCOUNTNAME";

    std::string sqlQueryStr = R"(
           SELECT `f_accountUUID`, `f_schemeId`, `f_appName`,
                  `loginDateTime`, `loginIP`, `loginTLSCN`, `loginUserAgent`,
                  `refresherTokenId`, `accessTokenId`,
                  `accessTokenExpiration`, `refreshTokenExpiration`,
                  `logoutDateTime`, `logoutReason`
           FROM logs.applicationAccess_accountSessions
           )";

    // Build params map
    std::map<std::string, std::shared_ptr<Abstract::Var>> params;
    params[":ACCOUNTNAME"] = MAKE_VAR(STRING, accountUUID);

    if (!searchValue.empty())
    {
        searchValue = "%" + searchValue + "%";
        whereFilters += " AND (`f_appName` LIKE :SEARCH OR `loginIP` LIKE :SEARCH)";
        params[":SEARCH"] = MAKE_VAR(STRING, searchValue);
    }

    {
        Abstract::STRING f_accountUUID, f_schemeId, f_appName, loginDateTime, loginIP, loginTLSCN, loginUserAgent;
        Abstract::STRING refresherTokenId, accessTokenId;
        Abstract::DATETIME accessTokenExpiration, refreshTokenExpiration, logoutDateTime;
        Abstract::UINT32 logoutReason;

        std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelectWithFilters(sqlQueryStr, whereFilters, params,
                                                                               {&f_accountUUID, &f_schemeId, &f_appName, &loginDateTime, &loginIP, &loginTLSCN, &loginUserAgent, &refresherTokenId,
                                                                                &accessTokenId, &accessTokenExpiration, &refreshTokenExpiration, &logoutDateTime, &logoutReason},
                                                                               orderByStatement, limit, offset);

        while (i && i->isSuccessful() && i->step())
        {
            Json::Value row;
            row["f_accountUUID"] = f_accountUUID.getValue();
            row["f_schemeId"] = f_schemeId.getValue();
            row["f_appName"] = f_appName.getValue();
            row["loginDateTime"] = loginDateTime.getValue();
            row["loginIP"] = loginIP.getValue();
            row["loginTLSCN"] = loginTLSCN.getValue();
            row["loginUserAgent"] = loginUserAgent.getValue();
            row["refresherTokenId"] = refresherTokenId.getValue();
            row["accessTokenId"] = accessTokenId.getValue();
            row["accessTokenExpiration"] = accessTokenExpiration.getValue();
            row["refreshTokenExpiration"] = refreshTokenExpiration.getValue();
            row["logoutDateTime"] = logoutDateTime.getValue();
            row["logoutReason"] = logoutReason.getValue();

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
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);

    time_t now = time(nullptr);

    // Mark entries where refreshToken has expired (covers both access and refresh)
    _parent->m_sqlConnector->qExecuteEx(
        R"(UPDATE logs.applicationAccess_accountSessions
           SET logoutReason = 2, logoutDateTime = CURRENT_TIMESTAMP
           WHERE refreshTokenExpiration < CURRENT_TIMESTAMP
           AND logoutReason IS NULL)",
        {{":now", MAKE_VAR(DATETIME, now)}});
}
