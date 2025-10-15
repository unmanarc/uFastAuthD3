#include "webadmin_endpoints_application_roles.h"

#include "../globals.h"
#include <Mantids30/Program_Logs/applog.h>

#include "webadmin_endpoints.h"

using namespace Mantids30::Program;
using namespace Mantids30;

using namespace Mantids30::Network::Protocols;

void WebAdminMethods_ApplicationRoles::addEndpoints_Roles(std::shared_ptr<Endpoints> endpoints)
{
    using SecurityOptions = Mantids30::API::RESTful::Endpoints::SecurityOptions;
    endpoints->addEndpoint(Endpoints::GET,    "searchApplicationRoles",        SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"},     nullptr, &searchApplicationRoles);
    endpoints->addEndpoint(Endpoints::POST,   "addRole",            SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"},   nullptr, &addRole);
    endpoints->addEndpoint(Endpoints::GET,    "getRoleInfo",        SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"},     nullptr, &getRoleInfo);
    endpoints->addEndpoint(Endpoints::PATCH,  "updateRoleDescription",SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"},   nullptr, &updateRoleDescription);
    endpoints->addEndpoint(Endpoints::DELETE, "removeRole",         SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"},   nullptr, &removeRole);
    // Accounts roles:
    endpoints->addEndpoint(Endpoints::POST,   "addApplicationRoleToAccount", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &addApplicationRoleToAccount);
    endpoints->addEndpoint(Endpoints::DELETE, "removeApplicationRoleFromAccount", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &removeApplicationRoleFromAccount);


    // Roles
    /*
    endpoints->addEndpoint(Endpoints::GET, "doesRoleExist", &doesRoleExist, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    endpoints->addEndpoint(Endpoints::GET, "validateApplicationScopeOnRole", &validateApplicationScopeOnRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    endpoints->addEndpoint(Endpoints::GET, "getApplicationRoleDescription", &getApplicationRoleDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    endpoints->addEndpoint(Endpoints::GET, "getApplicationRolesList", &getApplicationRolesList, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    endpoints->addEndpoint(Endpoints::GET, "getRoleApplicationScopes", &getRoleApplicationScopes, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    endpoints->addEndpoint(Endpoints::GET, "getApplicationRoleAccounts", &getApplicationRoleAccounts, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    */
}


API::APIReturn WebAdminMethods_ApplicationRoles::searchApplicationRoles(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    return Globals::getIdentityManager()->applicationRoles->searchApplicationRoles(*request.inputJSON);
}

API::APIReturn WebAdminMethods_ApplicationRoles::updateRoleDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = JSON_ASSTRING(*request.inputJSON, "roleName", "");
    std::string roleDescription = JSON_ASSTRING(*request.inputJSON, "roleDescription", "");

    if (roleName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request","Role name cannot be empty.");
        return response;
    }

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (roleDescription.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request","Role description cannot be empty.");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationRoles->updateRoleDescription(appName, roleName, roleDescription))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the role description.");
    }
    return response;
}


API::APIReturn WebAdminMethods_ApplicationRoles::addRole(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = JSON_ASSTRING(*request.inputJSON, "roleName", "");
    std::string roleDescription = JSON_ASSTRING(*request.inputJSON, "roleDescription", "");

    if (roleName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request","Role name cannot be empty.");
        return response;
    }

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (roleDescription.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request","Role description cannot be empty.");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationRoles->addRole(appName, roleName, roleDescription))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to create the new role.\nThe role ID may already exist.");
    }

    return response;
}


API::APIReturn WebAdminMethods_ApplicationRoles::getRoleInfo(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    json payloadOut;
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = JSON_ASSTRING(*request.inputJSON, "roleName", "");

    if (roleName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request","Role name cannot be empty.");
        return response;
    }

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    payloadOut["details"]["description"] = Globals::getIdentityManager()->applicationRoles->getApplicationRoleDescription(appName,roleName);

    int i = 0;
    std::set<std::string> roleAccounts = Globals::getIdentityManager()->applicationRoles->getApplicationRoleAccounts(appName,roleName);
    for (const std::string &accountName : roleAccounts)
    {
        payloadOut["accounts"][i] = accountName;
        i++;
    }

    std::set<ApplicationScope> usedScopes = Globals::getIdentityManager()->authController->getRoleApplicationScopes(appName,roleName);
    std::set<ApplicationScope> fullScopes = Globals::getIdentityManager()->authController->listApplicationScopes(appName);
    // Populate used scopes

    i=0;
    for (const auto &scope : usedScopes)
    {
        payloadOut["scopes"]["usedScopes"][i++] = scope.toJSON();
    }

    // Populate unused scopes
    i=0;
    for (const auto &scope : fullScopes)
    {
        if (usedScopes.find(scope) == usedScopes.end())
        {
            payloadOut["scopes"]["unusedScopes"][i++] = scope.toJSON();
        }
    }

    (*response.responseJSON()) = payloadOut;
    return response;
}


API::APIReturn WebAdminMethods_ApplicationRoles::removeRole(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    const std::string roleName = JSON_ASSTRING(*request.inputJSON, "roleName", "");
    const std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (roleName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Role ID is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationRoles->removeRole(appName,roleName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the role");
    }
    return response;
}

API::APIReturn WebAdminMethods_ApplicationRoles::addApplicationRoleToAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = JSON_ASSTRING(*request.inputJSON, "roleId", "");
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (roleName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Role ID is required");
        return response;
    }

    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationRoles->addAccountToRole(appName, roleName, accountName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to assign the role to the account.");
    }
    return response;
}

API::APIReturn WebAdminMethods_ApplicationRoles::removeApplicationRoleFromAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = JSON_ASSTRING(*request.inputJSON, "roleId", "");
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (roleName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Role ID is required");
        return response;
    }

    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationRoles->removeAccountFromRole(appName, roleName, accountName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the role from the account.");
    }

    return response;
}

/*


void WebAdminMethods_ApplicationRoles::doesRoleExist(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->roles->doesRoleExist(JSON_ASSTRING(*request.inputJSON, "roleName", ""));
}





void WebAdminMethods_ApplicationRoles::validateApplicationScopeOnRole(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->authController->validateApplicationScopeOnRole(JSON_ASSTRING(*request.inputJSON, "roleName", ""),
                                                                                                                    {JSON_ASSTRING(*request.inputJSON, "appName", ""),
                                                                                                                     JSON_ASSTRING(*request.inputJSON, "id", "")});
}

void WebAdminMethods_ApplicationRoles::getApplicationRoleDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->roles->getApplicationRoleDescription(JSON_ASSTRING(*request.inputJSON, "roleName", ""));
}

void WebAdminMethods_ApplicationRoles::getApplicationRolesList(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->roles->getApplicationRolesList());
}

void WebAdminMethods_ApplicationRoles::getRoleApplicationScopes(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = WebAdmin_Endpoints::scopeListToJSON(Globals::getIdentityManager()->authController->getRoleApplicationScopes(JSON_ASSTRING(*request.inputJSON, "roleName", "")));
}

void WebAdminMethods_ApplicationRoles::getApplicationRoleAccounts(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->roles->getApplicationRoleAccounts(JSON_ASSTRING(*request.inputJSON, "roleName", "")));
}

void WebAdminMethods_ApplicationRoles::searchApplicationRoles(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    json x;
    int i = 0;
    for (const auto &strVal : Globals::getIdentityManager()->roles->searchApplicationRoles(JSON_ASSTRING(*request.inputJSON, "searchWords", ""), JSON_ASUINT64(*request.inputJSON, "limit", 0),
                                                                                JSON_ASUINT64(*request.inputJSON, "offset", 0)))
    {
        x[i]["description"] = strVal.description;
        x[i]["roleName"] = strVal.roleName;
        i++;
    }
    (*response.responseJSON()) = x;
}
*/
