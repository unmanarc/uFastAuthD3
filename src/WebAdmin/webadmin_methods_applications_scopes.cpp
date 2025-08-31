#include "webadmin_methods_applications_scopes.h"

#include "../globals.h"
#include "defs.h"
#include "webadmin_methods.h"
#include <Mantids30/Program_Logs/applog.h>

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocols;

void WebAdminMethods_ApplicationsScopes::addMethods_Scopes(std::shared_ptr<MethodsHandler> methods)
{
    using SecurityOptions = Mantids30::API::RESTful::MethodsHandler::SecurityOptions;

    // Application Scopes

    methods->addResource(MethodsHandler::POST, "addApplicationScope", &addApplicationScope, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::POST, "removeApplicationScope", &removeApplicationScope, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::POST, "addApplicationScopeToRole", &addApplicationScopeToRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::POST, "removeApplicationScopeFromRole", &removeApplicationScopeFromRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::POST, "addApplicationScopeToAccount", &addApplicationScopeToAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::POST, "removeApplicationScopeFromAccount", &removeApplicationScopeFromAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::POST, "updateApplicationScopeDescription", &updateApplicationScopeDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::GET, "getApplicationScopeDescription", &getApplicationScopeDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "listApplicationScopes", &listApplicationScopes, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "getApplicationScopesForRole", &getApplicationScopesForRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "listAccountsOnApplicationScope", &listAccountsOnApplicationScope, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "searchApplicationScopes", &searchApplicationScopes, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "scopesLeftListForRole", &scopesLeftListForRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::POST, "addApplicationScope", &addApplicationScope, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::POST, "removeApplicationScope", &removeApplicationScope, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::POST, "addApplicationScopeToRole", &addApplicationScopeToRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::POST, "removeApplicationScopeFromRole", &removeApplicationScopeFromRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::POST, "addApplicationScopeToAccount", &addApplicationScopeToAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::POST, "removeApplicationScopeFromAccount", &removeApplicationScopeFromAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::POST, "updateApplicationScopeDescription", &updateApplicationScopeDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::GET, "getApplicationScopeDescription", &getApplicationScopeDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "listApplicationScopes", &listApplicationScopes, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "getApplicationScopesForRole", &getApplicationScopesForRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "listAccountsOnApplicationScope", &listAccountsOnApplicationScope, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "searchApplicationScopes", &searchApplicationScopes, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "scopesLeftListForRole", &scopesLeftListForRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
}

void WebAdminMethods_ApplicationsScopes::addApplicationScope(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    // Don't modify scope from our directory.
    if (appName == DB_APPNAME)
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Can't add application scope to the IAM");
        return;
    }

    if (!Globals::getIdentityManager()->authController->addApplicationScope({appName, JSON_ASSTRING(*request.inputJSON, "id", "")}, JSON_ASSTRING(*request.inputJSON, "description", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_ApplicationsScopes::removeApplicationScope(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    // Don't modify scope from our directory.
    if (appName == DB_APPNAME)
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Can't remove application scope to the IAM");
        return;
    }

    if (!Globals::getIdentityManager()->authController->removeApplicationScope({appName, JSON_ASSTRING(*request.inputJSON, "id", "")}))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_ApplicationsScopes::addApplicationScopeToRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->authController->addApplicationScopeToRole({JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "id", "")},
                                                                                       JSON_ASSTRING(*request.inputJSON, "roleName", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_ApplicationsScopes::removeApplicationScopeFromRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->authController->removeApplicationScopeFromRole({JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "id", "")},
                                                                                            JSON_ASSTRING(*request.inputJSON, "roleName", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_ApplicationsScopes::addApplicationScopeToAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->authController->addApplicationScopeToAccount({JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "id", "")},
                                                                                          JSON_ASSTRING(*request.inputJSON, "accountName", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_ApplicationsScopes::removeApplicationScopeFromAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->authController->removeApplicationScopeFromAccount({JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "id", "")},
                                                                                               JSON_ASSTRING(*request.inputJSON, "accountName", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_ApplicationsScopes::updateApplicationScopeDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    // Don't modify scopes from our directory.
    if (appName == DB_APPNAME)
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Can't update application scope to the IAM");
    }

    if (!Globals::getIdentityManager()->authController->removeApplicationScopeFromAccount({appName, JSON_ASSTRING(*request.inputJSON, "id", "")},
                                                                                               JSON_ASSTRING(*request.inputJSON, "getApplicationScopeDescription", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_ApplicationsScopes::listApplicationScopes(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = WebAdmin_Methods::scopeListToJSON(Globals::getIdentityManager()->authController->listApplicationScopes(JSON_ASSTRING(*request.inputJSON, "appName", "")));
}

void WebAdminMethods_ApplicationsScopes::getApplicationScopesForRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(
        Globals::getIdentityManager()->authController->getApplicationScopesForRole({JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "id", "")}));
}

void WebAdminMethods_ApplicationsScopes::listAccountsOnApplicationScope(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(
        Globals::getIdentityManager()->authController->listAccountsOnApplicationScope({JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "id", "")}));
}

void WebAdminMethods_ApplicationsScopes::getApplicationScopeDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->authController->getApplicationScopeDescription(
        {JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "id", "")});
}

void WebAdminMethods_ApplicationsScopes::searchApplicationScopes(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    json payloadOut;

    int i = 0;
    for (const auto &scope :
         Globals::getIdentityManager()->authController->searchApplicationScopes(JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "searchWords", ""),
                                                                                     JSON_ASUINT64(*request.inputJSON, "limit", 0), JSON_ASUINT64(*request.inputJSON, "offset", 0)))
    {
        payloadOut[i]["id"] = scope.id;
        payloadOut[i]["description"] = scope.description;
        i++;
    }
    (*response.responseJSON()) = payloadOut;
}

void WebAdminMethods_ApplicationsScopes::scopesLeftListForRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    auto scopesLeft = WebAdmin_Methods::iScopesLeftListForRole(JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "roleName", ""));
    (*response.responseJSON()) = WebAdmin_Methods::scopeListToJSON(scopesLeft);
}
