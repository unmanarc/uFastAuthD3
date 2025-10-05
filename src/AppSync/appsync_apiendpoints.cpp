#include "appsync_apiendpoints.h"

#include "json/config.h"
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
void AppSync_Endpoints::addAPIEndpoints(std::shared_ptr<MethodsHandler> methods)
{
    using SecurityOptions = Mantids30::API::RESTful::MethodsHandler::SecurityOptions;

    // Web API Endpoints:
    methods->addResource(MethodsHandler::POST, "getApplicationJWTConfig", &getApplicationJWTConfig, nullptr, SecurityOptions::NO_AUTH, {});
    methods->addResource(MethodsHandler::POST, "getApplicationJWTSigningKey", &getApplicationJWTSigningKey, nullptr, SecurityOptions::NO_AUTH, {});
    methods->addResource(MethodsHandler::POST, "getApplicationJWTValidationKey", &getApplicationJWTValidationKey, nullptr, SecurityOptions::NO_AUTH, {});
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
        return (Json::Value)Globals::getIdentityManager()->applications->getWebLoginJWTSigningKeyForApplication(appName);
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
