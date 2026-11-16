#include "adminportal_endpoints_application_roles.h"

#include <Mantids30/Server/WebRESTFul/security.h>
#include <Mantids30/DataFormat/JSON/json_accessors_array.h>
#include "globals.h"
#include <Mantids30/Runtime/Logs/applog.h>

using namespace Mantids30;
using namespace Mantids30::Protocol::HTTP;
using namespace Mantids30::Server::WebRESTFul;
using namespace Mantids30::Server::WebRESTFul;
using namespace Mantids30::Runtime;
using namespace Mantids30::Protocol;

void AdminPortal_Endpoints_ApplicationRoles::addEndpoints_Roles(const std::shared_ptr<Endpoints> &endpoints)
{
    using SecurityRequirements = Mantids30::Server::WebRESTFul::Security::Requirements;
    endpoints->addEndpoint(HTTP::Method::GET, "searchApplicationRoles", Mantids30::Server::WebRESTFul::Security::JWT_COOKIE_AUTH, {"APP_READ"}, nullptr, &searchApplicationRoles);
    endpoints->addEndpoint(HTTP::Method::POST, "createRole", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &createRole);
    endpoints->addEndpoint(HTTP::Method::GET, "getRoleInfo", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_READ"}, nullptr, &getRoleInfo);
    endpoints->addEndpoint(HTTP::Method::PATCH, "updateRoleDescription", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &updateRoleDescription);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeRole", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &removeRole);
    // Accounts roles:
    endpoints->addEndpoint(HTTP::Method::POST, "addApplicationRoleToAccount", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &addApplicationRoleToAccount);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeApplicationRoleFromAccount", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &removeApplicationRoleFromAccount);
}

APIReturn AdminPortal_Endpoints_ApplicationRoles::searchApplicationRoles(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    return Globals::getIdentityManager()->applicationRoles->searchApplicationRoles(*request.inputJSON);
}

APIReturn AdminPortal_Endpoints_ApplicationRoles::updateRoleDescription(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    APIReturn response;

    std::string appName(DataFormat::JSON::ASSTRING(*request.inputJSON, "appName", ""));
    std::string roleName (DataFormat::JSON::ASSTRING(*request.inputJSON, "roleName", ""));
    std::string roleDescription (DataFormat::JSON::ASSTRING(*request.inputJSON, "roleDescription", ""));

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

    if (!Globals::getIdentityManager()->applicationRoles->updateRoleDescription(authClientDetails,request.jwtToken->getSubject(), appName, roleName, roleDescription))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the role description."};
    }
    return response;
}

APIReturn AdminPortal_Endpoints_ApplicationRoles::createRole(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    APIReturn response;

    std::string appName(DataFormat::JSON::ASSTRING(*request.inputJSON, "appName", ""));
    std::string roleName (DataFormat::JSON::ASSTRING(*request.inputJSON, "roleName", ""));
    std::string roleDescription (DataFormat::JSON::ASSTRING(*request.inputJSON, "roleDescription", ""));

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

    if (!Globals::getIdentityManager()->applicationRoles->createRole(authClientDetails,request.jwtToken->getSubject(), appName, roleName, roleDescription))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to create the new role.\nThe role ID may already exist."};
    }

    return response;
}

APIReturn AdminPortal_Endpoints_ApplicationRoles::getRoleInfo(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    std::string appName(DataFormat::JSON::ASSTRING(*request.inputJSON, "appName", ""));
    std::string roleName (DataFormat::JSON::ASSTRING(*request.inputJSON, "roleName", ""));

    if (roleName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role name cannot be empty."};
    }

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required"};
    }

    // Accounts:
    boost::json::array accounts{};
    std::set<std::string> roleAccounts = Globals::getIdentityManager()->applicationRoles->getApplicationRoleAccounts(appName, roleName);
    for (const std::string &accountUUID : roleAccounts)
    {
        DataFormat::JSON::ARRAY_APPEND(accounts, boost::json::value(accountUUID));
    }

    // Scopes:
    std::set<ApplicationScope> usedScopes = Globals::getIdentityManager()->applicationScopes->getRoleApplicationScopes(appName, roleName);
    std::set<ApplicationScope> fullScopes = Globals::getIdentityManager()->applicationScopes->listApplicationScopes(appName);

    // Populate used scopes
    boost::json::array usedScopesOut{};
    for (const ApplicationScope &scope : usedScopes)
    {
        DataFormat::JSON::ARRAY_APPEND(usedScopesOut, scope.toJSON());
    }

    // Populate unused scopes
    boost::json::array unusedScopesOut{};
    for (const ApplicationScope &scope : fullScopes)
    {
        if (usedScopes.find(scope) == usedScopes.end())
        {
            DataFormat::JSON::ARRAY_APPEND(unusedScopesOut, scope.toJSON());
        }
    }

    return boost::json::value{
        {"details", boost::json::object{
            {"description", Globals::getIdentityManager()->applicationRoles->getApplicationRoleDescription(appName, roleName)},
        }},
        {"accounts", accounts},
        {"scopes", boost::json::object{
            {"usedScopes",   usedScopesOut},
            {"unusedScopes", unusedScopesOut},
        }},
    };
}

APIReturn AdminPortal_Endpoints_ApplicationRoles::removeRole(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    APIReturn response;
    const std::string roleName (DataFormat::JSON::ASSTRING(*request.inputJSON, "roleName", ""));
    const std::string appName(DataFormat::JSON::ASSTRING(*request.inputJSON, "appName", ""));

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required"};
    }

    if (roleName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Role ID is required"};
    }

    if (!Globals::getIdentityManager()->applicationRoles->removeRole(authClientDetails,request.jwtToken->getSubject(), appName, roleName))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the role"};
    }
    return response;
}

APIReturn AdminPortal_Endpoints_ApplicationRoles::addApplicationRoleToAccount(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    APIReturn response;

    std::string appName(DataFormat::JSON::ASSTRING(*request.inputJSON, "appName", ""));
    std::string roleName (DataFormat::JSON::ASSTRING(*request.inputJSON, "roleName", ""));
    std::string accountUUID (DataFormat::JSON::ASSTRING(*request.inputJSON, "accountUUID", ""));

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

    if (!Globals::getIdentityManager()->applicationRoles->addAccountToRole(authClientDetails,request.jwtToken->getSubject(), appName, roleName, accountUUID))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to assign the role to the account."};
    }
    return response;
}

APIReturn AdminPortal_Endpoints_ApplicationRoles::removeApplicationRoleFromAccount(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    APIReturn response;

    std::string appName(DataFormat::JSON::ASSTRING(*request.inputJSON, "appName", ""));
    std::string roleName (DataFormat::JSON::ASSTRING(*request.inputJSON, "roleName", ""));
    std::string accountUUID (DataFormat::JSON::ASSTRING(*request.inputJSON, "accountUUID", ""));

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

    if (!Globals::getIdentityManager()->applicationRoles->removeAccountFromRole(authClientDetails,request.jwtToken->getSubject(), appName, roleName, accountUUID))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the role from the account."};
    }

    return response;
}
