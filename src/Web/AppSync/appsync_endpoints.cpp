#include "appsync_endpoints.h"

#include <Mantids30/DataFormat_JWT/jwt.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Helpers/random.h>
#include <Mantids30/Program_Logs/applog.h>
#include <Mantids30/Program_Logs/loglevels.h>
#include <Mantids30/Protocol_HTTP/hdr_cookie.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>
#include <Mantids30/Protocol_HTTP/rsp_status.h>

#include <boost/algorithm/string.hpp>
#include <json/value.h>
#include <string>

#include "IdentityManager/ds_account.h"
#include "globals.h"

using namespace Mantids30;
using namespace Mantids30::Program;
using namespace Mantids30::API::RESTful;
using namespace Mantids30::Network::Protocol;
using namespace Mantids30::DataFormat;
/**
 * @brief Add API endpoints for application synchronization
 * @param methods Shared pointer to the methods handler for registering REST endpoints
 */
void AppSync_Endpoints::addAPIEndpoints(const std::shared_ptr<Endpoints> &endpoints)
{
    using SecurityRequirements = API::Security::Requirements;

    // Web API Endpoints:
    endpoints->addEndpoint(HTTP::Method::POST, "getApplicationAccountsList", SecurityRequirements::NONE, {}, nullptr, &getApplicationAccountsList);
    endpoints->addEndpoint(HTTP::Method::POST, "getApplicationJWTConfig", SecurityRequirements::NONE, {}, nullptr, &getApplicationJWTConfig);
    endpoints->addEndpoint(HTTP::Method::POST, "getApplicationJWTValidationKey", SecurityRequirements::NONE, {}, nullptr, &getApplicationJWTValidationKey);
    endpoints->addEndpoint(HTTP::Method::POST, "updateAccessControlContext", SecurityRequirements::NONE, {}, nullptr, &updateAccessControlContext);
    //    endpoints->addEndpoint(HTTP::Method::POST, "getApplicationJWTSigningKey", SecurityRequirements::NONE, {}, nullptr, &getApplicationJWTSigningKey);
}

void AppSync_Endpoints::updateAppScopes(const std::string &appName, const std::string &ipAddress, const Json::Value &proposedScopes)
{
    ClientDetails clientDetails;
    clientDetails.ipAddress = ipAddress;
    std::string performedBy = "00000000-0000-4000-8000-000000000001";

    // Current elements...
    std::set<ApplicationScope> currentScopes = Globals::getIdentityManager()->applicationScopes->listApplicationScopes(appName);
    if (proposedScopes.isArray())
    {
        std::set<std::string> proposedScopeIds;
        for (const Json::Value &scope : proposedScopes)
        {
            std::string id = Helpers::JSON::ASSTRING(scope, "id", "");
            if (!id.empty())
            {
                proposedScopeIds.insert(id);
                ApplicationScope newScope;
                newScope.appName = appName;
                newScope.id = id;
                newScope.description = Helpers::JSON::ASSTRING(scope, "description", "");

                // Check if scope exists
                std::set<ApplicationScope>::iterator existingScope = currentScopes.find(newScope);
                if (existingScope != currentScopes.end())
                {
                    // If description changed, update it
                    if (existingScope->description != newScope.description)
                    {
                        LOG_APP->log2(__func__, "", ipAddress, Logs::LogLevel::INFO, "Updating description for scope '%s' in application '%s'.", id.c_str(), appName.c_str());
                        Globals::getIdentityManager()->applicationScopes->updateApplicationScopeDescription(clientDetails, performedBy, newScope);
                    }
                }
                else
                {
                    // Add new scope
                    LOG_APP->log2(__func__, "", ipAddress, Logs::LogLevel::INFO, "Adding new scope '%s' to application '%s'.", id.c_str(), appName.c_str());
                    Globals::getIdentityManager()->applicationScopes->createApplicationScope(clientDetails, performedBy, newScope);
                }
            }
        }

        // Remove scopes that are not in proposed list
        for (const ApplicationScope &currentScope : currentScopes)
        {
            if (proposedScopeIds.find(currentScope.id) == proposedScopeIds.end())
            {
                LOG_APP->log2(__func__, "", ipAddress, Logs::LogLevel::INFO, "Removing scope '%s' from application '%s'.", currentScope.id.c_str(), appName.c_str());
                Globals::getIdentityManager()->applicationScopes->removeApplicationScope(clientDetails, performedBy, currentScope);
            }
        }
    }
}

void AppSync_Endpoints::updateAppRoles(const std::string &appName, const std::string &ipAddress, const Json::Value &proposedRoles)
{
    ClientDetails clientDetails;
    clientDetails.ipAddress = ipAddress;
    std::string performedBy = "00000000-0000-4000-8000-000000000001";

    std::set<ApplicationRole> currentRoles = Globals::getIdentityManager()->applicationRoles->getApplicationRolesList(appName);

    // Store proposed role data for scope processing later
    std::map<std::string, Json::Value> proposedRoleData;

    if (proposedRoles.isArray())
    {
        std::set<std::string> proposedRoleIds;
        for (const Json::Value &role : proposedRoles)
        {
            std::string id = Helpers::JSON::ASSTRING(role, "id", "");
            if (id.empty())
            {
                continue; // skip invalid entries
            }
            proposedRoleIds.insert(id);
            proposedRoleData[id] = role; // Store for scope processing

            std::string description = Helpers::JSON::ASSTRING(role, "description", "");
            ApplicationRole newRole;
            newRole.appName = appName;
            newRole.id = id;
            newRole.description = description;
            // Check if role exists
            std::set<ApplicationRole>::iterator existingRole = currentRoles.find(newRole);
            if (existingRole != currentRoles.end())
            {
                // If description changed, update it
                if (existingRole->description != newRole.description)
                {
                    LOG_APP->log2(__func__, "", ipAddress, Logs::LogLevel::INFO, "Updating description for role '%s' in application '%s'.", id.c_str(), appName.c_str());
                    Globals::getIdentityManager()->applicationRoles->updateRoleDescription(clientDetails, performedBy, appName, id, description);
                }
            }
            else
            {
                // Add new role
                LOG_APP->log2(__func__, "", ipAddress, Logs::LogLevel::INFO, "Adding new role '%s' to application '%s'.", id.c_str(), appName.c_str());
                Globals::getIdentityManager()->applicationRoles->createRole(clientDetails, performedBy, appName, id, description);
            }
        }
        // Remove roles that are not in proposed list
        for (const ApplicationRole &currentRole : currentRoles)
        {
            if (proposedRoleIds.find(currentRole.id) == proposedRoleIds.end())
            {
                LOG_APP->log2(__func__, "", ipAddress, Logs::LogLevel::INFO, "Removing role '%s' from application '%s'.", currentRole.id.c_str(), appName.c_str());
                Globals::getIdentityManager()->applicationRoles->removeRole(clientDetails, performedBy, appName, currentRole.id);
            }
        }
    }

    // Process scopes for each role
    for (const auto &pair : proposedRoleData)
    {
        const std::string &roleId = pair.first;
        const Json::Value &roleData = pair.second;

        Json::Value roleScopes = roleData["scopes"];
        if (roleScopes.isArray())
        {
            // Get current scopes assigned to this role
            std::set<std::string> currentScopeIdsForRole = Globals::getIdentityManager()
                                                               ->applicationRoles->listApplicationScopesOnApplicationRole(appName, roleId); // This won't work correctly, need different approach

            // Collect proposed scope IDs
            std::set<std::string> proposedScopeIds;
            for (const Json::Value &scope : roleScopes)
            {
                std::string scopeId = scope.asString();
                if (!scopeId.empty())
                {
                    proposedScopeIds.insert(scopeId);

                    // Add scope to role if not already there
                    if (currentScopeIdsForRole.find(scopeId) == currentScopeIdsForRole.end())
                    {
                        ApplicationScope appScope;
                        appScope.appName = appName;
                        appScope.id = scopeId;
                        LOG_APP->log2(__func__, "", ipAddress, Logs::LogLevel::INFO, "Adding scope '%s' to role '%s' in application '%s'.", scopeId.c_str(), roleId.c_str(), appName.c_str());
                        Globals::getIdentityManager()->applicationScopes->addApplicationScopeToRole(clientDetails, performedBy, appScope, roleId);
                    }
                }
            }

            // Remove scopes that should no longer be assigned to this role
            for (const std::string &currentScopeId : currentScopeIdsForRole)
            {
                if (proposedScopeIds.find(currentScopeId) == proposedScopeIds.end())
                {
                    ApplicationScope appScope;
                    appScope.appName = appName;
                    appScope.id = currentScopeId;
                    LOG_APP->log2(__func__, "", ipAddress, Logs::LogLevel::INFO, "Removing scope '%s' from role '%s' in application '%s'.", currentScopeId.c_str(), roleId.c_str(), appName.c_str());
                    Globals::getIdentityManager()->applicationScopes->removeApplicationScopeFromRole(clientDetails, performedBy, appScope, roleId);
                }
            }
        }
    }
}

void AppSync_Endpoints::updateAppActivities(const std::string &appName, const std::string &ipAddress, const Json::Value &proposedActivities)
{
    ClientDetails clientDetails;
    clientDetails.ipAddress = ipAddress;
    std::string performedBy = "00000000-0000-4000-8000-000000000001";

    std::map<std::string, IdentityManager::ApplicationActivities::ActivityData> currentActivities = Globals::getIdentityManager()->applicationActivities->listApplicationActivities(appName);

    if (proposedActivities.isArray())
    {
        std::set<std::string> proposedActivityNames;

        for (const Json::Value &act : proposedActivities)
        {
            std::string name = Helpers::JSON::ASSTRING(act, "id", "");
            if (name.empty())
            {
                continue; // skip invalid entries
            }

            proposedActivityNames.insert(name);

            IdentityManager::ApplicationActivities::ActivityData activityData;
            activityData.fromJSON(act); // populate description, parentActivity, etc.

            std::map<std::string, IdentityManager::ApplicationActivities::ActivityData>::iterator currentIt = currentActivities.find(name);
            if (currentIt != currentActivities.end())
            {
                // Existing activity: check for changes
                const IdentityManager::ApplicationActivities::ActivityData &currentData = currentIt->second;

                if (currentData.description != activityData.description)
                {
                    LOG_APP->log2(__func__, "", ipAddress, Logs::LogLevel::INFO, "Updating description for activity '%s' in application '%s'.", name.c_str(), appName.c_str());
                    Globals::getIdentityManager()->applicationActivities->setApplicationActivityDescription(clientDetails, performedBy, appName, name, activityData.description);
                }

                if (currentData.parentActivity != activityData.parentActivity)
                {
                    LOG_APP->log2(__func__, "", ipAddress, Logs::LogLevel::INFO, "Setting parent activity for activity '%s' in application '%s'.", name.c_str(), appName.c_str());
                    Globals::getIdentityManager()->applicationActivities->setApplicationActivityParentActivity(clientDetails, performedBy, appName, name, activityData.parentActivity);
                }
            }
            else
            {
                // New activity
                LOG_APP->log2(__func__, "", ipAddress, Logs::LogLevel::INFO, "Adding new activity '%s' to application '%s'.", name.c_str(), appName.c_str());

                // First register basic activity data
                Globals::getIdentityManager()->applicationActivities->createApplicationActivity(clientDetails, performedBy, appName, name, activityData.description);

                // Then apply remaining metadata
                if (!activityData.parentActivity.empty())
                {
                    Globals::getIdentityManager()->applicationActivities->setApplicationActivityParentActivity(clientDetails, performedBy, appName, name, activityData.parentActivity);
                }
            }
        }

        // Remove obsolete activities not listed in request
        for (const auto &pair : currentActivities)
        {
            const std::string &existingActivityName = pair.first;
            if (proposedActivityNames.find(existingActivityName) == proposedActivityNames.end())
            {
                LOG_APP->log2(__func__, "", ipAddress, Logs::LogLevel::INFO, "Removing obsolete activity '%s' from application '%s'.", existingActivityName.c_str(), appName.c_str());
                Globals::getIdentityManager()->applicationActivities->removeApplicationActivity(clientDetails, performedBy, appName, existingActivityName);
            }
        }
    }
}

AppSync_Endpoints::APIReturn AppSync_Endpoints::validateAndFetchApplicationAttributes(const RequestContext &request, ClientDetails &authClientDetails, std::string &appName,
                                                                                      std::optional<IdentityManager::Applications::ApplicationAttributes> &attribs)
{
    appName = request.clientRequest->requestLine.urlVars()->getStringValue("APP");
    if (appName.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LogLevel::WARNING, "Missing application name in request.");
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "missing_app_name", "Application name is required."};
    }

    attribs = Globals::getIdentityManager()->applications->getApplicationAttributes(appName);
    if (!attribs.has_value())
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to retrieve the application attributes."};
    }

    if (!attribs->appSyncEnabled)
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "Application '%s' does not have sync enabled.", appName.c_str());
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "sync_not_enabled", "Application sync is not enabled."};
    }

    std::string apiKey = Helpers::JSON::ASSTRING(*request.inputJSON, "APIKEY", "");
    if (apiKey.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LogLevel::WARNING, "Missing API key in request for application '%s'.", appName.c_str());
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "missing_api_key", "API key is required."};
    }

    if (Globals::getIdentityManager()->applications->getApplicationNameByAPIKey(apiKey) != appName)
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "Invalid API Key for Application '%s'. Possible attack attempt.", appName.c_str());
        return {HTTP::Status::Code::S_401_UNAUTHORIZED, "invalid_api_key", "Invalid API Key for the specified application."};
    }

    return {}; // Success
}

AppSync_Endpoints::APIReturn AppSync_Endpoints::updateAccessControlContext(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    std::string appName;
    std::optional<IdentityManager::Applications::ApplicationAttributes> attribs;

    APIReturn result = validateAndFetchApplicationAttributes(request, authClientDetails, appName, attribs);
    if (result.getHTTPResponseCode() != HTTP::Status::Code::S_200_OK)
    {
        return result;
    }

    // Scopes, Roles, and Activities...
    // ------------------------------------------------------

    updateAppScopes(appName, authClientDetails.ipAddress, (*request.inputJSON)["scopes"]);
    updateAppRoles(appName, authClientDetails.ipAddress, (*request.inputJSON)["roles"]);
    updateAppActivities(appName, authClientDetails.ipAddress, (*request.inputJSON)["activities"]);

    return {}; // Success
}

AppSync_Endpoints::APIReturn AppSync_Endpoints::getApplicationAccountsList(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    std::string appName;
    std::optional<IdentityManager::Applications::ApplicationAttributes> attribs;

    APIReturn result = validateAndFetchApplicationAttributes(request, authClientDetails, appName, attribs);
    if (result.getHTTPResponseCode() != HTTP::Status::Code::S_200_OK)
    {
        return result;
    }

    if (!attribs->appSyncCanRetrieveAppAccountsList)
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "Application '%s' does not have user list retrieval enabled.", appName.c_str());
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "user_list_not_enabled", "Retrieving the application user list is not enabled for this application."};
    }

    // Retrieve and return the list of users
    std::set<std::string> accountList = Globals::getIdentityManager()->applications->listApplicationAccounts(appName);
    Json::Value response = Json::arrayValue;
    for (const std::string &accountUUID : accountList)
    {
        if (std::optional<AccountDetails> x = Globals::getIdentityManager()->accounts->getAccountDetails(accountUUID, AccountDetailsToShow::APISYNC))
        {
            response.append(x->toJSON());
        }
    }

    return response;
}

/**
 * @brief Retrieve JWT configuration for a specified application
 * @param context Execution context (unused)
 * @param request Request parameters containing application name and API key
 * @param authClientDetails Client authentication details including IP address
 * @return APIReturn containing JWT configuration or error response
 */
AppSync_Endpoints::APIReturn AppSync_Endpoints::getApplicationJWTConfig(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    std::string appName;
    std::optional<IdentityManager::Applications::ApplicationAttributes> attribs;

    APIReturn result = validateAndFetchApplicationAttributes(request, authClientDetails, appName, attribs);
    if (result.getHTTPResponseCode() != HTTP::Status::Code::S_200_OK)
    {
        return result;
    }

    return Globals::getIdentityManager()->applications->getWebLoginJWTConfigFromApplication(appName).toJSON();
}

/**
 * @brief Retrieve JWT signing key for a specified application
 * @param context Execution context (unused)
 * @param request Request parameters containing application name and API key
 * @param authClientDetails Client authentication details including IP address
 * @return APIReturn containing JWT signing key or error response
 */ /*
AppSync_Endpoints::APIReturn AppSync_Endpoints::getApplicationJWTSigningKey(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    std::string appName;
    std::optional<IdentityManager::Applications::ApplicationAttributes> attribs;

    APIReturn result = validateAndFetchApplicationAttributes(request, authClientDetails, appName, attribs);
    if (result.getHTTPResponseCode() != HTTP::Status::Code::S_200_OK)
        return result;

    return (Json::Value) Globals::getIdentityManager()->applications->getWebLoginJWTSigningKeyForApplication(appName);
}
*/
/**
 * @brief Retrieve JWT validation key for a specified application
 * @param context Execution context (unused)
 * @param request Request parameters containing application name and API key
 * @param authClientDetails Client authentication details including IP address
 * @return APIReturn containing JWT validation key or error response
 */
AppSync_Endpoints::APIReturn AppSync_Endpoints::getApplicationJWTValidationKey(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    std::string appName;
    std::optional<IdentityManager::Applications::ApplicationAttributes> attribs;

    APIReturn result = validateAndFetchApplicationAttributes(request, authClientDetails, appName, attribs);
    if (result.getHTTPResponseCode() != HTTP::Status::Code::S_200_OK)
    {
        return result;
    }

    return Json::Value(Globals::getIdentityManager()->applications->getWebLoginJWTValidationKeyForApplication(appName));
}
