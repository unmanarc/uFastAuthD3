#include "webadmin_endpoints_application_scopes.h"

#include "globals.h"
#include "defs.h"
#include <regex>
#include <Mantids30/Program_Logs/applog.h>

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocols;

void WebAdminMethods_ApplicationsScopes::addEndpoints_Scopes(std::shared_ptr<Endpoints> endpoints)
{
    using SecurityOptions = Mantids30::API::RESTful::Endpoints::SecurityOptions;
    endpoints->addEndpoint(Endpoints::POST, "addApplicationScopeToAccount", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &addApplicationScopeToAccount);
    endpoints->addEndpoint(Endpoints::DELETE, "removeApplicationScopeFromAccount", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &removeApplicationScopeFromAccount);

    endpoints->addEndpoint(Endpoints::POST, "addApplicationScope", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &addApplicationScope);
    endpoints->addEndpoint(Endpoints::DELETE, "removeApplicationScope", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &removeApplicationScope);
    endpoints->addEndpoint(Endpoints::PUT, "addApplicationScopeToRole", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &addApplicationScopeToRole);
    endpoints->addEndpoint(Endpoints::DELETE, "removeApplicationScopeFromRole", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &removeApplicationScopeFromRole);
    endpoints->addEndpoint(Endpoints::GET, "searchApplicationScopes", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"}, nullptr, &searchApplicationScopes);

    // Application Scopes
/*
    endpoints->addEndpoint(Endpoints::POST, "updateApplicationScopeDescription", &updateApplicationScopeDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    endpoints->addEndpoint(Endpoints::GET, "getApplicationScopeDescription", &getApplicationScopeDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    endpoints->addEndpoint(Endpoints::GET, "listApplicationScopes", &listApplicationScopes, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    endpoints->addEndpoint(Endpoints::GET, "getApplicationRolesForScope", &getApplicationRolesForScope, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    endpoints->addEndpoint(Endpoints::GET, "listAccountsOnApplicationScope", &listAccountsOnApplicationScope, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    endpoints->addEndpoint(Endpoints::GET, "scopesLeftListForRole", &scopesLeftListForRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    endpoints->addEndpoint(Endpoints::POST, "addApplicationScope", &addApplicationScope, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    endpoints->addEndpoint(Endpoints::DELETE, "removeApplicationScope", &removeApplicationScope, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    endpoints->addEndpoint(Endpoints::POST, "addApplicationScopeToRole", &addApplicationScopeToRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    endpoints->addEndpoint(Endpoints::PATCH, "updateApplicationScopeDescription", &updateApplicationScopeDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    endpoints->addEndpoint(Endpoints::GET, "getApplicationScopeDescription", &getApplicationScopeDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    endpoints->addEndpoint(Endpoints::GET, "listApplicationScopes", &listApplicationScopes, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    endpoints->addEndpoint(Endpoints::GET, "getApplicationRolesForScope", &getApplicationRolesForScope, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    endpoints->addEndpoint(Endpoints::GET, "listAccountsOnApplicationScope", &listAccountsOnApplicationScope, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    endpoints->addEndpoint(Endpoints::GET, "searchApplicationScopes", &searchApplicationScopes, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    endpoints->addEndpoint(Endpoints::GET, "scopesLeftListForRole", &scopesLeftListForRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});*/
}

API::APIReturn WebAdminMethods_ApplicationsScopes::addApplicationScopeToAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    // Extract and validate input values
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string scopeId = JSON_ASSTRING(*request.inputJSON, "scopeId", "");
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (appName.empty() || scopeId.empty() || accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_parameters", "Parameters cannot be empty");
        return response;
    }

    // Perform the operation
    if (!Globals::getIdentityManager()->authController->addApplicationScopeToAccount({appName, scopeId}, accountName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
    return response;
}

API::APIReturn WebAdminMethods_ApplicationsScopes::removeApplicationScopeFromAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    // Extract and validate input values
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string scopeId = JSON_ASSTRING(*request.inputJSON, "scopeId", "");
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (appName.empty() || scopeId.empty() || accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_parameters", "Parameters cannot be empty");
        return response;
    }

    // Perform the operation
    if (!Globals::getIdentityManager()->authController->removeApplicationScopeFromAccount({appName, scopeId}, accountName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
    return response;
}
API::APIReturn WebAdminMethods_ApplicationsScopes::addApplicationScope(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string scopeId = JSON_ASSTRING(*request.inputJSON, "scopeId", "");
    std::string scopeDescription = JSON_ASSTRING(*request.inputJSON, "scopeDescription", "");

    // Validate input parameters
    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_parameters", "Application name cannot be empty");
        return response;
    }

    if (scopeId.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_parameters", "Scope ID cannot be empty");
        return response;
    }

    // Validate scopeId format: [0-9A-Z_]+
    const std::regex scopeIdPattern("^[0-9A-Z_-]+$");
    if (!std::regex_match(scopeId, scopeIdPattern))
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_parameters", "Scope ID must match the pattern [0-9A-Z_-]+");
        return response;
    }

    // Don't modify scope from our directory.
    if (appName == DB_APPNAME)
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Can't add application scope to the IAM");
        return response;
    }

    if (!Globals::getIdentityManager()->authController->addApplicationScope({appName, scopeId,scopeDescription}))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "The application scope may already exist.");
    }

    return response;
}

API::APIReturn WebAdminMethods_ApplicationsScopes::removeApplicationScope(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string scopeId = JSON_ASSTRING(*request.inputJSON, "scopeId", "");

    // Validate input parameters
    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_parameters", "Application name cannot be empty");
        return response;
    }

    if (scopeId.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_parameters", "Scope ID cannot be empty");
        return response;
    }

    // Don't modify scope from our directory.
    if (appName == DB_APPNAME)
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Can't remove application scope to the IAM");
        return response;
    }

    if (!Globals::getIdentityManager()->authController->removeApplicationScope({appName, scopeId}))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }

    return response;
}

API::APIReturn WebAdminMethods_ApplicationsScopes::addApplicationScopeToRole(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    if (!Globals::getIdentityManager()->authController->addApplicationScopeToRole({JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "scopeId", "")},
                                                                                  JSON_ASSTRING(*request.inputJSON, "roleId", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the application scope to the role.");
    }

    return response;
}
API::APIReturn WebAdminMethods_ApplicationsScopes::removeApplicationScopeFromRole(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    if (!Globals::getIdentityManager()->authController->removeApplicationScopeFromRole({JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "scopeId", "")},
                                                                                       JSON_ASSTRING(*request.inputJSON, "roleId", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }

    return response;
}


API::APIReturn WebAdminMethods_ApplicationsScopes::searchApplicationScopes(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    return Globals::getIdentityManager()->authController->searchApplicationScopes(*request.inputJSON);
}

/*




void WebAdminMethods_ApplicationsScopes::updateApplicationScopeDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
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

void WebAdminMethods_ApplicationsScopes::listApplicationScopes(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = WebAdmin_Endpoints::scopeListToJSON(Globals::getIdentityManager()->authController->listApplicationScopes(JSON_ASSTRING(*request.inputJSON, "appName", "")));
}

void WebAdminMethods_ApplicationsScopes::getApplicationRolesForScope(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(
        Globals::getIdentityManager()->authController->getApplicationRolesForScope({JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "id", "")}));
}

void WebAdminMethods_ApplicationsScopes::listAccountsOnApplicationScope(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(
        Globals::getIdentityManager()->authController->listAccountsOnApplicationScope({JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "id", "")}));
}

void WebAdminMethods_ApplicationsScopes::getApplicationScopeDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->authController->getApplicationScopeDescription(
        {JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "id", "")});
}

void WebAdminMethods_ApplicationsScopes::scopesLeftListForRole(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    auto scopesLeft = WebAdmin_Endpoints::iScopesLeftListForRole(JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "roleName", ""));
    (*response.responseJSON()) = WebAdmin_Endpoints::scopeListToJSON(scopesLeft);
}*/
