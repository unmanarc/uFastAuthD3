#include "adminportal_endpoints_application_scopes.h"

#include "defs.h"
#include "globals.h"
#include <Mantids30/Program_Logs/applog.h>
#include <regex>

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocol;

void AdminPortal_Endpoints_ApplicationsScopes::addEndpoints_Scopes(const std::shared_ptr<Endpoints> &endpoints)
{
    using SecurityRequirements = API::Security::Requirements;
    endpoints->addEndpoint(HTTP::Method::POST, "addApplicationScopeToAccount", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &addApplicationScopeToAccount);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeApplicationScopeFromAccount", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &removeApplicationScopeFromAccount);

    endpoints->addEndpoint(HTTP::Method::POST, "createApplicationScope", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &createApplicationScope);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeApplicationScope", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &removeApplicationScope);
    endpoints->addEndpoint(HTTP::Method::PUT, "addApplicationScopeToRole", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &addApplicationScopeToRole);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeApplicationScopeFromRole", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &removeApplicationScopeFromRole);
    endpoints->addEndpoint(HTTP::Method::GET, "searchApplicationScopes", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_READ"}, nullptr, &searchApplicationScopes);
}

API::APIReturn AdminPortal_Endpoints_ApplicationsScopes::addApplicationScopeToAccount(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    // Extract and validate input values
    std::string appName = Helpers::JSON::ASSTRING(*request.inputJSON, "appName", "");
    std::string scopeId = Helpers::JSON::ASSTRING(*request.inputJSON, "scopeId", "");
    std::string accountUUID = Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", "");

    if (appName.empty() || scopeId.empty() || accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_parameters", "Parameters cannot be empty"};
    }

    // Perform the operation
    if (!Globals::getIdentityManager()->authController->addApplicationScopeToAccount(authClientDetails, request.jwtToken->getSubject(), {appName, scopeId}, accountUUID))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error"};
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationsScopes::removeApplicationScopeFromAccount(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    // Extract and validate input values
    std::string appName = Helpers::JSON::ASSTRING(*request.inputJSON, "appName", "");
    std::string scopeId = Helpers::JSON::ASSTRING(*request.inputJSON, "scopeId", "");
    std::string accountUUID = Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", "");

    if (appName.empty() || scopeId.empty() || accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_parameters", "Parameters cannot be empty"};
    }

    // Perform the operation
    if (!Globals::getIdentityManager()->authController->removeApplicationScopeFromAccount(authClientDetails, request.jwtToken->getSubject(), {appName, scopeId}, accountUUID))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error"};
    }
    return response;
}
API::APIReturn AdminPortal_Endpoints_ApplicationsScopes::createApplicationScope(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = Helpers::JSON::ASSTRING(*request.inputJSON, "appName", "");
    std::string scopeId = Helpers::JSON::ASSTRING(*request.inputJSON, "scopeId", "");
    std::string scopeDescription = Helpers::JSON::ASSTRING(*request.inputJSON, "scopeDescription", "");

    // Validate input parameters
    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_parameters", "Application name cannot be empty"};
    }

    if (scopeId.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_parameters", "Scope ID cannot be empty"};
    }

    // Validate scopeId format: [0-9A-Z_]+
    const std::regex scopeIdPattern("^[0-9A-Z_-]+$");
    if (!std::regex_match(scopeId, scopeIdPattern))
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_parameters", "Scope ID must match the pattern [0-9A-Z_-]+"};
    }

    // Don't modify scope from our directory.
    if (appName == IAM_ADMPORTAL_APPNAME)
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Can't add application scope to the IAM"};
    }

    if (!Globals::getIdentityManager()->authController->createApplicationScope(authClientDetails, request.jwtToken->getSubject(), {appName, scopeId, scopeDescription}))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "The application scope may already exist."};
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationsScopes::removeApplicationScope(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = Helpers::JSON::ASSTRING(*request.inputJSON, "appName", "");
    std::string scopeId = Helpers::JSON::ASSTRING(*request.inputJSON, "scopeId", "");

    // Validate input parameters
    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_parameters", "Application name cannot be empty"};
    }

    if (scopeId.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_parameters", "Scope ID cannot be empty"};
    }

    // Don't modify scope from our directory.
    if (appName == IAM_ADMPORTAL_APPNAME)
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Can't remove application scope to the IAM"};
    }

    if (!Globals::getIdentityManager()->authController->removeApplicationScope(authClientDetails, request.jwtToken->getSubject(), {appName, scopeId}))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error"};
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationsScopes::addApplicationScopeToRole(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    if (!Globals::getIdentityManager()->authController->addApplicationScopeToRole(authClientDetails, request.jwtToken->getSubject(),
                                                                                  {Helpers::JSON::ASSTRING(*request.inputJSON, "appName", ""), Helpers::JSON::ASSTRING(*request.inputJSON, "scopeId", "")},
                                                                                  Helpers::JSON::ASSTRING(*request.inputJSON, "roleId", "")))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the application scope to the role."};
    }

    return response;
}
API::APIReturn AdminPortal_Endpoints_ApplicationsScopes::removeApplicationScopeFromRole(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    if (!Globals::getIdentityManager()->authController->removeApplicationScopeFromRole(authClientDetails, request.jwtToken->getSubject(),
                                                                                       {Helpers::JSON::ASSTRING(*request.inputJSON, "appName", ""), Helpers::JSON::ASSTRING(*request.inputJSON, "scopeId", "")},
                                                                                       Helpers::JSON::ASSTRING(*request.inputJSON, "roleId", "")))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error"};
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationsScopes::searchApplicationScopes(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    return Globals::getIdentityManager()->authController->searchApplicationScopes(*request.inputJSON);
}
