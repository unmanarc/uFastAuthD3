#include "webadmin_methods_application_roles.h"

#include "../globals.h"
#include <Mantids30/Program_Logs/applog.h>

#include "webadmin_methods.h"

using namespace Mantids30::Program;
using namespace Mantids30;

using namespace Mantids30::Network::Protocols;

void WebAdminMethods_ApplicationRoles::addMethods_Roles(std::shared_ptr<MethodsHandler> methods)
{
    using SecurityOptions = Mantids30::API::RESTful::MethodsHandler::SecurityOptions;
    methods->addResource(MethodsHandler::GET, "searchRoles", &searchRoles, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::POST, "addRole", &addRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::GET, "getRoleInfo", &getRoleInfo, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::PATCH, "updateRoleDescription", &updateRoleDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::DELETE, "removeRole", &removeRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});

    // Accounts roles:
    methods->addResource(MethodsHandler::POST, "addApplicationRoleToAccount", &addApplicationRoleToAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::DELETE, "removeApplicationRoleFromAccount", &removeApplicationRoleFromAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});


    // Roles
    /*
    methods->addResource(MethodsHandler::GET, "doesRoleExist", &doesRoleExist, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "validateApplicationScopeOnRole", &validateApplicationScopeOnRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "getRoleDescription", &getRoleDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "getRolesList", &getRolesList, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "getRoleApplicationScopes", &getRoleApplicationScopes, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "getRoleAccounts", &getRoleAccounts, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    */
}


API::APIReturn WebAdminMethods_ApplicationRoles::searchRoles(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    return Globals::getIdentityManager()->applicationRoles->searchRoles(*request.inputJSON);
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

    payloadOut["details"]["description"] = Globals::getIdentityManager()->applicationRoles->getRoleDescription(appName,roleName);

    int i = 0;
    std::set<std::string> roleAccounts = Globals::getIdentityManager()->applicationRoles->getRoleAccounts(appName,roleName);
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

void WebAdminMethods_ApplicationRoles::getRoleDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->roles->getRoleDescription(JSON_ASSTRING(*request.inputJSON, "roleName", ""));
}

void WebAdminMethods_ApplicationRoles::getRolesList(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->roles->getRolesList());
}

void WebAdminMethods_ApplicationRoles::getRoleApplicationScopes(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = WebAdmin_Methods::scopeListToJSON(Globals::getIdentityManager()->authController->getRoleApplicationScopes(JSON_ASSTRING(*request.inputJSON, "roleName", "")));
}

void WebAdminMethods_ApplicationRoles::getRoleAccounts(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->roles->getRoleAccounts(JSON_ASSTRING(*request.inputJSON, "roleName", "")));
}

void WebAdminMethods_ApplicationRoles::searchRoles(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    json x;
    int i = 0;
    for (const auto &strVal : Globals::getIdentityManager()->roles->searchRoles(JSON_ASSTRING(*request.inputJSON, "searchWords", ""), JSON_ASUINT64(*request.inputJSON, "limit", 0),
                                                                                JSON_ASUINT64(*request.inputJSON, "offset", 0)))
    {
        x[i]["description"] = strVal.description;
        x[i]["roleName"] = strVal.roleName;
        i++;
    }
    (*response.responseJSON()) = x;
}
*/
