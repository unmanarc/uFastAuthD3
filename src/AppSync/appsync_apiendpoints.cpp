#include "appsync_apiendpoints.h"

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

#include "globals.h"

using namespace Mantids30;
using namespace Mantids30::Program;
using namespace Mantids30::API::RESTful;
using namespace Mantids30::Network::Protocols;
using namespace Mantids30::DataFormat;
/**
 * @brief Add API endpoints for application synchronization
 * @param methods Shared pointer to the methods handler for registering REST endpoints
 */
void AppSync_Endpoints::addAPIEndpoints(std::shared_ptr<Endpoints> endpoints)
{
    using SecurityOptions = Mantids30::API::RESTful::Endpoints::SecurityOptions;

    // Web API Endpoints:
    endpoints->addEndpoint(Endpoints::POST, "getApplicationJWTConfig", SecurityOptions::NO_AUTH, {}, nullptr, &getApplicationJWTConfig);
    endpoints->addEndpoint(Endpoints::POST, "getApplicationJWTSigningKey", SecurityOptions::NO_AUTH, {}, nullptr, &getApplicationJWTSigningKey);
    endpoints->addEndpoint(Endpoints::POST, "getApplicationJWTValidationKey", SecurityOptions::NO_AUTH, {}, nullptr, &getApplicationJWTValidationKey);
    endpoints->addEndpoint(Endpoints::POST, "updateAccessControlContext", SecurityOptions::NO_AUTH, {}, nullptr, &updateAccessControlContext);
}

AppSync_Endpoints::APIReturn AppSync_Endpoints::updateAccessControlContext(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = request.clientRequest->requestLine.urlVars()->getStringValue("APP");
    if (appName.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_WARN, "Missing application name in request during request.");
        return APIReturn(HTTP::Status::S_400_BAD_REQUEST, "missing_app_name", "Application name is required.");
    }

    if (!Globals::getIdentityManager()->applications->haveApplicationSyncEnabled(appName))
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Application '%s' does not have sync enabled.", appName.c_str());
        return APIReturn(HTTP::Status::S_400_BAD_REQUEST, "sync_not_enabled", "Application sync is not enabled.");
    }

    std::string apiKey = JSON_ASSTRING(*request.inputJSON, "APIKEY", "");
    if (apiKey.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_WARN, "Missing API key in request for application '%s' during request.", appName.c_str());
        return APIReturn(HTTP::Status::S_400_BAD_REQUEST, "missing_api_key", "API key is required.");
    }

    if (Globals::getIdentityManager()->applications->getApplicationNameByAPIKey(apiKey) != appName)
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid API Key for Application '%s'. Possible attack attempt.", appName.c_str());
        return APIReturn(HTTP::Status::S_401_UNAUTHORIZED, "invalid_api_key", "Invalid API Key for the specified application.");
    }

    // Scopes, Roles, and Activities...
    // ------------------------------------------------------

    Json::Value proposedScopes = (*request.inputJSON)["scopes"];
    // Current elements...
    std::set<ApplicationScope> currentScopes = Globals::getIdentityManager()->authController->listApplicationScopes(appName);
    if (proposedScopes.isArray())
    {
        std::set<std::string> proposedScopeIds;
        for (const auto &scope : proposedScopes)
        {
            std::string id = JSON_ASSTRING(scope, "id", "");
            if (!id.empty())
            {
                proposedScopeIds.insert(id);
                ApplicationScope newScope;
                newScope.appName = appName;
                newScope.id = id;
                newScope.description = JSON_ASSTRING(scope, "description", "");

                // Check if scope exists
                auto existingScope = currentScopes.find(newScope);
                if (existingScope != currentScopes.end())
                {
                    // If description changed, update it
                    if (existingScope->description != newScope.description)
                    {
                        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_INFO, "Updating description for scope '%s' in application '%s'.", id.c_str(), appName.c_str());
                        Globals::getIdentityManager()->authController->updateApplicationScopeDescription(newScope);
                    }
                }
                else
                {
                    // Add new scope
                    LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_INFO, "Adding new scope '%s' to application '%s'.", id.c_str(), appName.c_str());
                    Globals::getIdentityManager()->authController->addApplicationScope(newScope);
                }
            }
        }

        // Remove scopes that are not in proposed list
        for (const auto &currentScope : currentScopes)
        {
            if (proposedScopeIds.find(currentScope.id) == proposedScopeIds.end())
            {
                LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_INFO, "Removing scope '%s' from application '%s'.", currentScope.id.c_str(), appName.c_str());
                Globals::getIdentityManager()->authController->removeApplicationScope(currentScope);
            }
        }
    }

    Json::Value proposedRoles = (*request.inputJSON)["roles"];
    std::set<ApplicationRole> currentRoles = Globals::getIdentityManager()->applicationRoles->getApplicationRolesList(appName);

    if (proposedRoles.isArray())
    {
        std::set<std::string> proposedRoleIds;

        for (const auto &role : proposedRoles)
        {
            std::string id = JSON_ASSTRING(role, "id", "");
            if (id.empty())
                continue; // skip invalid entries

            proposedRoleIds.insert(id);

            std::string description = JSON_ASSTRING(role, "description", "");

            ApplicationRole newRole;
            newRole.appName = appName;
            newRole.id = id;
            newRole.description = description;

            // Check if role exists
            auto existingRole = currentRoles.find(newRole);
            if (existingRole != currentRoles.end())
            {
                // If description changed, update it
                if (existingRole->description != newRole.description)
                {
                    LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_INFO, "Updating description for role '%s' in application '%s'.", id.c_str(), appName.c_str());
                    Globals::getIdentityManager()->applicationRoles->updateRoleDescription(appName, id, description);
                }
            }
            else
            {
                // Add new role
                LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_INFO, "Adding new role '%s' to application '%s'.", id.c_str(), appName.c_str());
                Globals::getIdentityManager()->applicationRoles->addRole(appName, id, description);
            }
        }

        // Remove roles that are not in proposed list
        for (const auto &currentRole : currentRoles)
        {
            if (proposedRoleIds.find(currentRole.id) == proposedRoleIds.end())
            {
                LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_INFO, "Removing role '%s' from application '%s'.", currentRole.id.c_str(), appName.c_str());
                Globals::getIdentityManager()->applicationRoles->removeRole(appName, currentRole.id);
            }
        }
    }

    Json::Value proposedActivities = (*request.inputJSON)["activities"];
    std::map<std::string, IdentityManager::ApplicationActivities::ActivityData> currentActivities = Globals::getIdentityManager()->applicationActivities->listApplicationActivities(appName);

    if (proposedActivities.isArray())
    {
        std::set<std::string> proposedActivityNames;

        for (const auto &act : proposedActivities)
        {
            std::string name = JSON_ASSTRING(act, "name", "");
            if (name.empty())
                continue; // skip invalid entries

            proposedActivityNames.insert(name);

            IdentityManager::ApplicationActivities::ActivityData activityData;
            activityData.fromJSON(act); // populate description, parentActivity, etc.

            auto currentIt = currentActivities.find(name);
            if (currentIt != currentActivities.end())
            {
                // Existing activity: check for changes
                const auto &currentData = currentIt->second;

                if (currentData.description != activityData.description)
                {
                    LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_INFO, "Updating description for activity '%s' in application '%s'.", name.c_str(), appName.c_str());
                    Globals::getIdentityManager()->applicationActivities->setApplicationActivityDescription(appName, name, activityData.description);
                }

                if (currentData.parentActivity != activityData.parentActivity)
                {
                    LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_INFO, "Setting parent activity for activity '%s' in application '%s'.", name.c_str(), appName.c_str());
                    Globals::getIdentityManager()->applicationActivities->setApplicationActivityParentActivity(appName, name, activityData.parentActivity);
                }
            }
            else
            {
                // New activity
                LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_INFO, "Adding new activity '%s' to application '%s'.", name.c_str(), appName.c_str());

                // First register basic activity data
                Globals::getIdentityManager()->applicationActivities->addApplicationActivity(appName, name, activityData.description);

                // Then apply remaining metadata
                if (!activityData.parentActivity.empty())
                {
                    Globals::getIdentityManager()->applicationActivities->setApplicationActivityParentActivity(appName, name, activityData.parentActivity);
                }
            }
        }

        // Remove obsolete activities not listed in request
        for (const auto &pair : currentActivities)
        {
            const std::string &existingActivityName = pair.first;
            if (proposedActivityNames.find(existingActivityName) == proposedActivityNames.end())
            {
                LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_INFO, "Removing obsolete activity '%s' from application '%s'.", existingActivityName.c_str(), appName.c_str());
                Globals::getIdentityManager()->applicationActivities->removeApplicationActivity(appName, existingActivityName);
            }
        }
    }

    return APIReturn();
}

/**
 * @brief Retrieve JWT configuration for a specified application
 * @param context Execution context (unused)
 * @param request Request parameters containing application name and API key
 * @param authClientDetails Client authentication details including IP address
 * @return APIReturn containing JWT configuration or error response
 */
AppSync_Endpoints::APIReturn AppSync_Endpoints::getApplicationJWTConfig(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = request.clientRequest->requestLine.urlVars()->getStringValue("APP");
    if (appName.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_WARN, "Missing application name in request during request.");
        return APIReturn(HTTP::Status::S_400_BAD_REQUEST, "missing_app_name", "Application name is required.");
    }

    if (!Globals::getIdentityManager()->applications->haveApplicationSyncEnabled(appName))
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Application '%s' does not have sync enabled.", appName.c_str());
        return APIReturn(HTTP::Status::S_400_BAD_REQUEST, "sync_not_enabled", "Application sync is not enabled.");
    }

    std::string apiKey = JSON_ASSTRING(*request.inputJSON, "APIKEY", "");
    if (apiKey.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_WARN, "Missing API key in request for application '%s' during request.", appName.c_str());
        return APIReturn(HTTP::Status::S_400_BAD_REQUEST, "missing_api_key", "API key is required.");
    }

    if (Globals::getIdentityManager()->applications->getApplicationNameByAPIKey(apiKey) == appName)
    {
        return Globals::getIdentityManager()->applications->getWebLoginJWTConfigFromApplication(appName).toJSON();
    }
    else
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid API Key for Application '%s'. Possible attack attempt.", appName.c_str());
        return APIReturn(HTTP::Status::S_401_UNAUTHORIZED, "invalid_api_key", "Invalid API Key for the specified application.");
    }
}

/**
 * @brief Retrieve JWT signing key for a specified application
 * @param context Execution context (unused)
 * @param request Request parameters containing application name and API key
 * @param authClientDetails Client authentication details including IP address
 * @return APIReturn containing JWT signing key or error response
 */
AppSync_Endpoints::APIReturn AppSync_Endpoints::getApplicationJWTSigningKey(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = request.clientRequest->requestLine.urlVars()->getStringValue("APP");
    if (appName.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_WARN, "Missing application name in request during request.");
        return APIReturn(HTTP::Status::S_400_BAD_REQUEST, "missing_app_name", "Application name is required.");
    }

    if (!Globals::getIdentityManager()->applications->haveApplicationSyncEnabled(appName))
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Application '%s' does not have sync enabled.", appName.c_str());
        return APIReturn(HTTP::Status::S_400_BAD_REQUEST, "sync_not_enabled", "Application sync is not enabled.");
    }

    std::string apiKey = JSON_ASSTRING(*request.inputJSON, "APIKEY", "");
    if (apiKey.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_WARN, "Missing API key in request for application '%s' during request.", appName.c_str());
        return APIReturn(HTTP::Status::S_400_BAD_REQUEST, "missing_api_key", "API key is required.");
    }

    if (Globals::getIdentityManager()->applications->getApplicationNameByAPIKey(apiKey) == appName)
    {
        return (Json::Value) Globals::getIdentityManager()->applications->getWebLoginJWTSigningKeyForApplication(appName);
    }
    else
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid API Key for Application '%s'. Possible attack attempt.", appName.c_str());
        return APIReturn(HTTP::Status::S_401_UNAUTHORIZED, "invalid_api_key", "Invalid API Key for the specified application.");
    }
}

/**
 * @brief Retrieve JWT validation key for a specified application
 * @param context Execution context (unused)
 * @param request Request parameters containing application name and API key
 * @param authClientDetails Client authentication details including IP address
 * @return APIReturn containing JWT validation key or error response
 */
AppSync_Endpoints::APIReturn AppSync_Endpoints::getApplicationJWTValidationKey(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = request.clientRequest->requestLine.urlVars()->getStringValue("APP");
    if (appName.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_WARN, "Missing application name in request during request.");
        return APIReturn(HTTP::Status::S_400_BAD_REQUEST, "missing_app_name", "Application name is required.");
    }

    if (!Globals::getIdentityManager()->applications->haveApplicationSyncEnabled(appName))
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Application '%s' does not have sync enabled.", appName.c_str());
        return APIReturn(HTTP::Status::S_400_BAD_REQUEST, "sync_not_enabled", "Application sync is not enabled.");
    }

    std::string apiKey = JSON_ASSTRING(*request.inputJSON, "APIKEY", "");
    if (apiKey.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_WARN, "Missing API key in request for application '%s' during request.", appName.c_str());
        return APIReturn(HTTP::Status::S_400_BAD_REQUEST, "missing_api_key", "API key is required.");
    }

    if (Globals::getIdentityManager()->applications->getApplicationNameByAPIKey(apiKey) == appName)
    {
        return (Json::Value) Globals::getIdentityManager()->applications->getWebLoginJWTValidationKeyForApplication(appName);
    }
    else
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid API Key for Application '%s'. Possible attack attempt.", appName.c_str());
        return APIReturn(HTTP::Status::S_401_UNAUTHORIZED, "invalid_api_key", "Invalid API Key for the specified application.");
    }
}
