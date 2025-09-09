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
    methods->addResource(MethodsHandler::GET, "searchRoles", &searchRoles, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_READ"});
    methods->addResource(MethodsHandler::POST, "addRole", &addRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_CREATE"});
    methods->addResource(MethodsHandler::GET, "getRoleInfo", &getRoleInfo, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_READ"});
    methods->addResource(MethodsHandler::PATCH, "updateRoleDescription", &updateRoleDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_MODIFY"});
    methods->addResource(MethodsHandler::DELETE, "removeRole", &removeRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_DELETE"});

    // Roles
    /*
    methods->addResource(MethodsHandler::POST, "addAccountToRole", &addAccountToRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_MODIFY"});
    methods->addResource(MethodsHandler::DELETE, "removeAccountFromRole", &removeAccountFromRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_MODIFY"});
    methods->addResource(MethodsHandler::GET, "doesRoleExist", &doesRoleExist, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_READ"});
    methods->addResource(MethodsHandler::GET, "validateApplicationScopeOnRole", &validateApplicationScopeOnRole, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_READ"});
    methods->addResource(MethodsHandler::GET, "getRoleDescription", &getRoleDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_READ"});
    methods->addResource(MethodsHandler::GET, "getRolesList", &getRolesList, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_READ"});
    methods->addResource(MethodsHandler::GET, "getRoleApplicationScopes", &getRoleApplicationScopes, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_READ"});
    methods->addResource(MethodsHandler::GET, "getRoleAccounts", &getRoleAccounts, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ROLE_READ"});
    */
}


void WebAdminMethods_ApplicationRoles::searchRoles(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->applicationRoles->searchRoles(*request.inputJSON);
}

void WebAdminMethods_ApplicationRoles::updateRoleDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = JSON_ASSTRING(*request.inputJSON, "roleName", "");
    std::string roleDescription = JSON_ASSTRING(*request.inputJSON, "roleDescription", "");

    if (roleName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request","Role name cannot be empty.");
        return;
    }

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return;
    }

    if (roleDescription.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request","Role description cannot be empty.");
        return;
    }

    if (!Globals::getIdentityManager()->applicationRoles->updateRoleDescription(appName, roleName, roleDescription))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the role description.");
    }
}


void WebAdminMethods_ApplicationRoles::addRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = JSON_ASSTRING(*request.inputJSON, "roleName", "");
    std::string roleDescription = JSON_ASSTRING(*request.inputJSON, "roleDescription", "");

    if (roleName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request","Role name cannot be empty.");
        return;
    }

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return;
    }

    if (roleDescription.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request","Role description cannot be empty.");
        return;
    }

    if (!Globals::getIdentityManager()->applicationRoles->addRole(appName, roleName, roleDescription))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to create the new role.\nThe role ID may already exist.");
    }
}


void WebAdminMethods_ApplicationRoles::getRoleInfo(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    // TODO: optimize:
    json payloadOut;
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string roleName = JSON_ASSTRING(*request.inputJSON, "roleName", "");

    if (roleName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request","Role name cannot be empty.");
        return;
    }

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return;
    }

    payloadOut["details"]["description"] = Globals::getIdentityManager()->applicationRoles->getRoleDescription(appName,roleName);

    int i = 0;
    auto roleAccounts = Globals::getIdentityManager()->applicationRoles->getRoleAccounts(appName,roleName);
    for (const auto &accountName : roleAccounts)
    {
        auto getAccountDetails = Globals::getIdentityManager()->accounts->getAccountDetails(accountName);
        payloadOut["accounts"][i]["name"] = accountName;
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
}


void WebAdminMethods_ApplicationRoles::removeRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    const std::string roleName = JSON_ASSTRING(*request.inputJSON, "roleName", "");
    const std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (!Globals::getIdentityManager()->applicationRoles->removeRole(appName,roleName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the role");
    }
}


/*


void WebAdminMethods_ApplicationRoles::doesRoleExist(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->roles->doesRoleExist(JSON_ASSTRING(*request.inputJSON, "roleName", ""));
}

void WebAdminMethods_ApplicationRoles::addAccountToRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->roles->addAccountToRole(JSON_ASSTRING(*request.inputJSON, "roleName", ""), JSON_ASSTRING(*request.inputJSON, "accountName", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_ApplicationRoles::removeAccountFromRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->roles->removeAccountFromRole(JSON_ASSTRING(*request.inputJSON, "roleName", ""), JSON_ASSTRING(*request.inputJSON, "accountName", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}



void WebAdminMethods_ApplicationRoles::validateApplicationScopeOnRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->authController->validateApplicationScopeOnRole(JSON_ASSTRING(*request.inputJSON, "roleName", ""),
                                                                                                                    {JSON_ASSTRING(*request.inputJSON, "appName", ""),
                                                                                                                     JSON_ASSTRING(*request.inputJSON, "id", "")});
}

void WebAdminMethods_ApplicationRoles::getRoleDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->roles->getRoleDescription(JSON_ASSTRING(*request.inputJSON, "roleName", ""));
}

void WebAdminMethods_ApplicationRoles::getRolesList(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->roles->getRolesList());
}

void WebAdminMethods_ApplicationRoles::getRoleApplicationScopes(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = WebAdmin_Methods::scopeListToJSON(Globals::getIdentityManager()->authController->getRoleApplicationScopes(JSON_ASSTRING(*request.inputJSON, "roleName", "")));
}

void WebAdminMethods_ApplicationRoles::getRoleAccounts(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->roles->getRoleAccounts(JSON_ASSTRING(*request.inputJSON, "roleName", "")));
}

void WebAdminMethods_ApplicationRoles::searchRoles(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
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
