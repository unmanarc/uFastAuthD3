#include "webadmin_endpoints.h"
#include "../globals.h"

using namespace Mantids30;

void WebAdmin_Endpoints::addEndpoints(std::shared_ptr<Endpoints> endpoints)
{
    addEndpoints_Accounts(endpoints);
    addEndpoints_Scopes(endpoints);
    addEndpoints_Applications(endpoints);
    addEndpoints_Roles(endpoints);
    addEndpoints_AuthController(endpoints);
    addEndpoints_Activities(endpoints);
}

json WebAdmin_Endpoints::scopeListToJSON(const std::set<ApplicationScope> &scopes)
{
    json x;
    int i = 0;
    for (const auto &scope : scopes)
    {
        x[i]["appName"] = scope.appName;
        x[i]["id"] = scope.id;
        x[i++]["description"] = Globals::getIdentityManager()->authController->getApplicationScopeDescription(scope);
    }
    return x;
}

std::set<ApplicationScope> WebAdmin_Endpoints::iScopesLeftListForRole(const std::string &appName, const std::string &roleName)
{
    auto scopesLeft = Globals::getIdentityManager()->authController->listApplicationScopes(appName);
    auto roleScopes = Globals::getIdentityManager()->authController->getRoleApplicationScopes(appName,roleName);

    for (const auto &roleScope : roleScopes)
    {
        scopesLeft.erase(roleScope);
    }
    return scopesLeft;
}
