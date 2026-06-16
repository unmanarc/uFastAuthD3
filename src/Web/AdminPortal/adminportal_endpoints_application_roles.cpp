#include "adminportal_endpoints_application_roles.h"

#include "Mantids30/API_EndpointsAndSessions/security.h"
#include "globals.h"
#include <Mantids30/Program_Logs/applog.h>

using namespace Mantids30;
using namespace Mantids30::Program;
using namespace Mantids30::Network::Protocol;

void AdminPortal_Endpoints_ApplicationRoles::addEndpoints_Roles(const std::shared_ptr<Endpoints> &endpoints)
{
    using SecurityRequirements = API::Security::Requirements;
    endpoints->addEndpoint(HTTP::Method::GET, "searchApplicationRoles", API::Security::Requirements::JWT_COOKIE_AUTH, {"APP_READ"}, nullptr, &searchApplicationRoles);
    endpoints->addEndpoint(HTTP::Method::POST, "addRole", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &addRole);
    endpoints->addEndpoint(HTTP::Method::GET, "getRoleInfo", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_READ"}, nullptr, &getRoleInfo);
    endpoints->addEndpoint(HTTP::Method::PATCH, "updateRoleDescription", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &updateRoleDescription);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeRole", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &removeRole);
    // Accounts roles:
    endpoints->addEndpoint(HTTP::Method::POST, "addApplicationRoleToAccount", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &addApplicationRoleToAccount);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeApplicationRoleFromAccount", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &removeApplicationRoleFromAccount);
}

API::APIReturn AdminPortal_Endpoints_ApplicationRoles::searchApplicationRoles(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    return Globals::getIdentityManager()->applicationRoles->searchApplicationRoles(*request.inputJSON);
}

API::APIReturn AdminPortal_Endpoints_ApplicationRoles::updateRoleDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = JSON_ASSTRING(*request.inputJSON, "roleName", "");
    std::string roleDescription = JSON_ASSTRING(*request.inputJSON, "roleDescription", "");

    if (roleName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role name cannot be empty.");
        return response;
    }

    if (appName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (roleDescription.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role description cannot be empty.");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationRoles->updateRoleDescription(authClientDetails, request.jwtToken->getSubject(), appName, roleName, roleDescription))
    {
        response.setError(HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the role description.");
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationRoles::addRole(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = JSON_ASSTRING(*request.inputJSON, "roleName", "");
    std::string roleDescription = JSON_ASSTRING(*request.inputJSON, "roleDescription", "");

    if (roleName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role name cannot be empty.");
        return response;
    }

    if (appName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (roleDescription.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role description cannot be empty.");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationRoles->addRole(authClientDetails, request.jwtToken->getSubject(), appName, roleName, roleDescription))
    {
        response.setError(HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to create the new role.\nThe role ID may already exist.");
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationRoles::getRoleInfo(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    json payloadOut;
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = JSON_ASSTRING(*request.inputJSON, "roleName", "");

    if (roleName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role name cannot be empty.");
        return response;
    }

    if (appName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    payloadOut["details"]["description"] = Globals::getIdentityManager()->applicationRoles->getApplicationRoleDescription(appName, roleName);

    int i = 0;
    std::set<std::string> roleAccounts = Globals::getIdentityManager()->applicationRoles->getApplicationRoleAccounts(appName, roleName);
    for (const std::string &accountName : roleAccounts)
    {
        payloadOut["accounts"][i] = accountName;
        i++;
    }

    std::set<ApplicationScope> usedScopes = Globals::getIdentityManager()->authController->getRoleApplicationScopes(appName, roleName);
    std::set<ApplicationScope> fullScopes = Globals::getIdentityManager()->authController->listApplicationScopes(appName);
    // Populate used scopes

    i = 0;
    for (const ApplicationScope &scope : usedScopes)
    {
        payloadOut["scopes"]["usedScopes"][i++] = scope.toJSON();
    }

    // Populate unused scopes
    i = 0;
    for (const ApplicationScope &scope : fullScopes)
    {
        if (usedScopes.find(scope) == usedScopes.end())
        {
            payloadOut["scopes"]["unusedScopes"][i++] = scope.toJSON();
        }
    }

    (*response.responseJSON()) = payloadOut;
    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationRoles::removeRole(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    const std::string roleName = JSON_ASSTRING(*request.inputJSON, "roleName", "");
    const std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (roleName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role ID is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationRoles->removeRole(authClientDetails, request.jwtToken->getSubject(), appName, roleName))
    {
        response.setError(HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the role");
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationRoles::addApplicationRoleToAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = JSON_ASSTRING(*request.inputJSON, "roleId", "");
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (roleName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role ID is required");
        return response;
    }

    if (accountName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationRoles->addAccountToRole(authClientDetails, request.jwtToken->getSubject(), appName, roleName, accountName))
    {
        response.setError(HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to assign the role to the account.");
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationRoles::removeApplicationRoleFromAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = JSON_ASSTRING(*request.inputJSON, "roleId", "");
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (roleName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role ID is required");
        return response;
    }

    if (accountName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationRoles->removeAccountFromRole(authClientDetails, request.jwtToken->getSubject(), appName, roleName, accountName))
    {
        response.setError(HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the role from the account.");
    }

    return response;
}
