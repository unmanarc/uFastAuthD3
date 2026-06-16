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

json AdminPortal_Endpoints::scopeListToJSON(const std::set<ApplicationScope> &scopes)
{
    json x;
    int i = 0;
    for (const ApplicationScope &scope : scopes)
    {
        x[i]["appName"] = scope.appName;
        x[i]["id"] = scope.id;
        x[i++]["description"] = Globals::getIdentityManager()->authController->getApplicationScopeDescription(scope);
    }
    return x;
}

std::set<ApplicationScope> AdminPortal_Endpoints::iScopesLeftListForRole(const std::string &appName, const std::string &roleName)
{
    std::set<ApplicationScope> scopesLeft = Globals::getIdentityManager()->authController->listApplicationScopes(appName);
    std::set<ApplicationScope> roleScopes = Globals::getIdentityManager()->authController->getRoleApplicationScopes(appName, roleName);

    for (const ApplicationScope &roleScope : roleScopes)
    {
        scopesLeft.erase(roleScope);
    }

    return scopesLeft;
}
