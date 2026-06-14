#include "websessionauthhandler_serverimpl.h"
#include "config.h"
#include "defs.h"
#include "globals.h"
#include "websessionauthhandler_endpoints.h"

#include <Mantids30/Server_RESTfulWebAPI/config_builder.h>
#include <Mantids30/Server_RESTfulWebAPI/engine.h>

#include <boost/algorithm/string/predicate.hpp>
#include <memory>

// Imported namespaces are shortened and grouped for better readability
using namespace Mantids30;
using namespace Network;
using namespace Network::Sockets;
using namespace Network::Servers;
using namespace Program;

bool JWTDynamicTokenValidatorFunction(const std::string& accessTokenStr, const std::string& xAPIKeyStr, Mantids30::DataFormat::JWT::Token * accessToken)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    std::string appNameStr = identityManager->applications->getApplicationNameByAPIKey(xAPIKeyStr);

    // Now, search the application by the x-api-key:
    if (appNameStr.empty())
    {
        // app key not found...
        LOG_APP->log1(__func__, "", Logs::LEVEL_SECURITY_ALERT, "Invalid API key provided to the dynamic validator. Application not found.");
        return false;
    }

    ApplicationTokenProperties tokenProps = identityManager->applications->getWebLoginJWTConfigFromApplication(appNameStr);
    std::shared_ptr<Mantids30::DataFormat::JWT> validator = identityManager->applications->getAppJWTValidator(appNameStr);

    if (!validator->verify(accessTokenStr,accessToken))
    {
        LOG_APP->log1(__func__, "", Logs::LEVEL_SECURITY_ALERT, "Invalid Signature for JWT Token at app %s.", appNameStr.c_str());
        return false;
    }

    if (JSON_ASSTRING_D(accessToken->getClaim("app"), "") != appNameStr)
    {
        LOG_APP->log1(__func__, "", Logs::LEVEL_SECURITY_ALERT, "JWT Token missing app name %s.", appNameStr.c_str());
        return false;
    }

    if (JSON_ASSTRING_D(accessToken->getClaim("type"), "") != "access")
    {
        LOG_APP->log1(__func__, "", Logs::LEVEL_SECURITY_ALERT, "JWT Token missing app name %s.", appNameStr.c_str());
        return false;
    }

    return true;
}

// The app proxied the /auth to this service, so the origin should be what we define in the DB.
bool myDynamicOriginValidatorFunction(const std::string& origin, const std::string& xAPIKeyStr, const std::set<std::string> & configPermittedAPIOrigins)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    std::string appNameStr = identityManager->applications->getApplicationNameByAPIKey(xAPIKeyStr);

    std::set<std::string> origins = Globals::getIdentityManager()->applications->listWebLoginOriginUrlsFromApplication(appNameStr);

    return origins.count(origin);
}


bool myDynamicCallbackOriginValidatorFunction(const std::string& requestOrigin, const std::string& xAPIKeyStr, const std::set<std::string> & permittedCallbackOrigins)
{
    std::string appName = Globals::getIdentityManager()->applications->getApplicationNameByAPIKey(xAPIKeyStr);

    if (appName.empty())
    {
        LOG_APP->log2(__func__, "", "", Logs::LEVEL_SECURITY_ALERT, "Invalid API key provided. Application not found. (callback)");
        return false;
    }

    auto attribs = Globals::getIdentityManager()->applications->getApplicationAttributes(appName);

    if (!attribs->useEmbeddedAuthentication)
    {
        // Use the original (config) permitted Callback Origins
        return permittedCallbackOrigins.count(requestOrigin);
    }
    else
    {
        // Using embedded auth, the origin should be the same app URLs.
        std::set<std::string> origins = Globals::getIdentityManager()->applications->listWebLoginOriginUrlsFromApplication(appName);
        return origins.find(requestOrigin) != origins.end();
    }
}

bool WebSessionAuthHandler_ServerImpl::createService()
{
    boost::property_tree::ptree config = Globals::pConfig;

    try
    {
        config = config.get_child("WebSessionAuthHandlerService");
    }
    catch (boost::property_tree::ptree_error &e)
    {
        LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Configuration error: WebSessionAuthHandlerService not found: %s", e.what());
        return false;
    }

    RESTful::Engine *webSessionAuthHandlerServer = Program::Config::RESTful_Engine::createRESTfulEngine(config, LOG_APP, LOG_RPC, "Web Session Auth Handler", IAM_LOGINPORTAL_DEF_WEBROOTDIR, Program::Config::REST_ENGINE_NOCONFIG_JWT);

    if (!webSessionAuthHandlerServer)
        return false;

    // Set the software version:
    webSessionAuthHandlerServer->config.setSoftwareVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");


    // Specific JWT Token Validator given an API Key specifying the APP
    webSessionAuthHandlerServer->config.dynamicTokenValidator = JWTDynamicTokenValidatorFunction;

    // Specific origin validator given the Origin: and an API Key specifying the APP
    webSessionAuthHandlerServer->config.dynamicOriginValidator = myDynamicOriginValidatorFunction;

    // Specific callback origin validator given the Origin: and an API Key specifying the APP
    webSessionAuthHandlerServer->config.dynamicLoginCallbackOriginValidator = myDynamicCallbackOriginValidatorFunction;

    // Setup the methods handler for version 1:
    webSessionAuthHandlerServer->endpointsHandler[1] = std::make_shared<API::RESTful::Endpoints>();

    // This will validate the JWT, the app should match with this:
    webSessionAuthHandlerServer->config.appName = "_";

    // Add authentication methods
    WebSessionAuthHandler_Endpoints::addEndpoints(webSessionAuthHandlerServer->endpointsHandler[1]);

    webSessionAuthHandlerServer->startInBackground();

    for (const auto & i : webSessionAuthHandlerServer->getListenerSockets())
    {
        LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Web Session Auth Handler Service Listening @%s", i->getLastBindAddress().c_str());
    }

    return true;
}
