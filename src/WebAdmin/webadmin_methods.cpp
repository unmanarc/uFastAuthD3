#include "webadmin_methods.h"
#include "../globals.h"

using namespace Mantids30;

void WebAdmin_Methods::addMethods(std::shared_ptr<MethodsHandler> methods)
{
    addMethods_Accounts(methods);
    addMethods_Scopes(methods);
    addMethods_Applications(methods);
    addMethods_Roles(methods);
    addMethods_AuthController(methods);
    addMethods_Activities(methods);
}

json WebAdmin_Methods::scopeListToJSON(const std::set<ApplicationScope> &scopes)
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

std::set<ApplicationScope> WebAdmin_Methods::iScopesLeftListForRole(const std::string &appName, const std::string &roleName)
{
    auto scopesLeft = Globals::getIdentityManager()->authController->listApplicationScopes(appName);
    auto roleScopes = Globals::getIdentityManager()->authController->getRoleApplicationScopes(appName,roleName);

    for (const auto &roleScope : roleScopes)
    {
        scopesLeft.erase(roleScope);
    }
    return scopesLeft;
}
