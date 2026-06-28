#include "adminportal_endpoints_application_roles.h"

#include <Mantids30/API_EndpointsAndSessions/security.h>
#include "globals.h"
#include <Mantids30/Program_Logs/applog.h>

using namespace Mantids30;
using namespace Mantids30::Program;
using namespace Mantids30::Network::Protocol;

void AdminPortal_Endpoints_ApplicationRoles::addEndpoints_Roles(const std::shared_ptr<Endpoints> &endpoints)
{
    using SecurityRequirements = API::Security::Requirements;
    endpoints->addEndpoint(HTTP::Method::GET, "searchApplicationRoles", API::Security::Requirements::JWT_COOKIE_AUTH, {"APP_READ"}, nullptr, &searchApplicationRoles);
    endpoints->addEndpoint(HTTP::Method::POST, "createRole", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &createRole);
    endpoints->addEndpoint(HTTP::Method::GET, "getRoleInfo", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_READ"}, nullptr, &getRoleInfo);
    endpoints->addEndpoint(HTTP::Method::PATCH, "updateRoleDescription", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &updateRoleDescription);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeRole", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &removeRole);
    // Accounts roles:
    endpoints->addEndpoint(HTTP::Method::POST, "addApplicationRoleToAccount", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &addApplicationRoleToAccount);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeApplicationRoleFromAccount", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &removeApplicationRoleFromAccount);
}

API::APIReturn AdminPortal_Endpoints_ApplicationRoles::searchApplicationRoles(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    return Globals::getIdentityManager()->applicationRoles->searchApplicationRoles(*request.inputJSON);
}

API::APIReturn AdminPortal_Endpoints_ApplicationRoles::updateRoleDescription(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = Helpers::JSON::ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = Helpers::JSON::ASSTRING(*request.inputJSON, "roleName", "");
    std::string roleDescription = Helpers::JSON::ASSTRING(*request.inputJSON, "roleDescription", "");

    if (roleName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role name cannot be empty."};
    }

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required"};
    }

    if (roleDescription.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role description cannot be empty."};
    }

    if (!Globals::getIdentityManager()->applicationRoles->updateRoleDescription(authClientDetails, request.jwtToken->getSubject(), appName, roleName, roleDescription))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the role description."};
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationRoles::createRole(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = Helpers::JSON::ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = Helpers::JSON::ASSTRING(*request.inputJSON, "roleName", "");
    std::string roleDescription = Helpers::JSON::ASSTRING(*request.inputJSON, "roleDescription", "");

    if (roleName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role name cannot be empty."};
    }

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required"};
    }

    if (roleDescription.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role description cannot be empty."};
    }

    if (!Globals::getIdentityManager()->applicationRoles->createRole(authClientDetails, request.jwtToken->getSubject(), appName, roleName, roleDescription))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to create the new role.\nThe role ID may already exist."};
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationRoles::getRoleInfo(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    Json::Value payloadOut;
    std::string appName = Helpers::JSON::ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = Helpers::JSON::ASSTRING(*request.inputJSON, "roleName", "");

    if (roleName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role name cannot be empty."};
    }

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required"};
    }

    payloadOut["details"]["description"] = Globals::getIdentityManager()->applicationRoles->getApplicationRoleDescription(appName, roleName);

    int i = 0;
    std::set<std::string> roleAccounts = Globals::getIdentityManager()->applicationRoles->getApplicationRoleAccounts(appName, roleName);
    for (const std::string &accountUUID : roleAccounts)
    {
        payloadOut["accounts"][i] = accountUUID;
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

API::APIReturn AdminPortal_Endpoints_ApplicationRoles::removeRole(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    const std::string roleName = Helpers::JSON::ASSTRING(*request.inputJSON, "roleName", "");
    const std::string appName = Helpers::JSON::ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required"};
    }

    if (roleName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role ID is required"};
    }

    if (!Globals::getIdentityManager()->applicationRoles->removeRole(authClientDetails, request.jwtToken->getSubject(), appName, roleName))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the role"};
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationRoles::addApplicationRoleToAccount(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = Helpers::JSON::ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = Helpers::JSON::ASSTRING(*request.inputJSON, "roleId", "");
    std::string accountUUID = Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", "");

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required"};
    }

    if (roleName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role ID is required"};
    }

    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    if (!Globals::getIdentityManager()->applicationRoles->addAccountToRole(authClientDetails, request.jwtToken->getSubject(), appName, roleName, accountUUID))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to assign the role to the account."};
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationRoles::removeApplicationRoleFromAccount(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = Helpers::JSON::ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = Helpers::JSON::ASSTRING(*request.inputJSON, "roleId", "");
    std::string accountUUID = Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", "");

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required"};
    }

    if (roleName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role ID is required"};
    }

    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    if (!Globals::getIdentityManager()->applicationRoles->removeAccountFromRole(authClientDetails, request.jwtToken->getSubject(), appName, roleName, accountUUID))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the role from the account."};
    }

    return response;
}
