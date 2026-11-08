#include "adminportal_endpoints.h"
#include "globals.h"

using namespace Mantids30;

void AdminPortal_Endpoints::addEndpoints(const std::shared_ptr<Endpoints> &endpoints)
{
    addEndpoints_AccountCredentials(endpoints);
    addEndpoints_Accounts(endpoints);
    addEndpoints_Scopes(endpoints);
    addEndpoints_Applications(endpoints);
    addEndpoints_Roles(endpoints);
    addEndpoints_AuthController(endpoints);
    addEndpoints_Activities(endpoints);
}

boost::json::array AdminPortal_Endpoints::scopeListtoJSON(const std::set<ApplicationScope> &scopes)
{
    boost::json::array x{};
    for (const ApplicationScope &scope : scopes)
    {
        boost::json::object entry{
            {"appName",     scope.appName},
            {"id",          scope.id},
            {"description", Globals::getIdentityManager()->applicationScopes->getApplicationScopeDescription(scope)},
        };
        x.push_back(entry);
    }
    return x;
}

std::set<ApplicationScope> AdminPortal_Endpoints::iScopesLeftListForRole(const std::string &appName, const std::string &roleName)
{
    std::set<ApplicationScope> scopesLeft = Globals::getIdentityManager()->applicationScopes->listApplicationScopes(appName);
    std::set<ApplicationScope> roleScopes = Globals::getIdentityManager()->applicationScopes->getRoleApplicationScopes(appName, roleName);

    for (const ApplicationScope &roleScope : roleScopes)
    {
        scopesLeft.erase(roleScope);
    }

    return scopesLeft;
}
