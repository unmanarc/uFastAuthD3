#include "loginportal_serverimpl.h"
#include "config.h"
#include "defs.h"
#include "globals.h"
#include "loginportal_endpoints.h"

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

bool appOriginValidatorFunction(const std::string &requestOrigin, const std::string &apikey, const std::set<std::string> &configPermittedAPIOrigins)
{
    if (!apikey.empty())
    {
        std::string appName = Globals::getIdentityManager()->applications->getApplicationNameByAPIKey(apikey);

        if (appName.empty())
        {
            LOG_APP->log2(__func__, "", "", Logs::LogLevel::SECURITY_ALERT, "Invalid API key provided. Application not found.");
            return false;
        }

        std::optional<IdentityManager::Applications::ApplicationAttributes> attribs = Globals::getIdentityManager()->applications->getApplicationAttributes(appName);

        if (!attribs.has_value())
        {
            LOG_APP->log2(__func__, "", "", Logs::LogLevel::SECURITY_ALERT, "Failed to obtain app '%s' attributes.", appName.c_str());
            return false;
        }

        if (!attribs->useEmbeddedAuthentication)
        {
            LOG_APP->log2(__func__, "", "", Logs::LogLevel::SECURITY_ALERT, "App '%s' lacks embedded auth.", appName.c_str());
            return false;
        }

        std::set<std::string> origins = Globals::getIdentityManager()->applications->listWebLoginOriginUrlsFromApplication(appName);
        return origins.find(requestOrigin) != origins.end();
    }
    else
    {
        return configPermittedAPIOrigins.count(requestOrigin);
    }
}

Protocol::HTTP::Status::Code dynamicInitialChecks(Mantids30::Network::Protocol::HTTP::HTTPv1_Base::Request *request, Mantids30::Network::Protocol::HTTP::HTTPv1_Base::Response *response)
{
    std::string keepAuthCookie = request->getCookie("KeepAuthentication");
    std::string accessTokenCookie = request->getCookie("AccessToken");
    std::string xApiHeader = request->getHeaderOption("x-api-key");

    if (!xApiHeader.empty())
    {
        if (!keepAuthCookie.empty() || !accessTokenCookie.empty())
        {
            return response->setRedirectLocation("/");
        }
    }

    return Protocol::HTTP::Status::Code::S_200_OK;
}

bool LoginPortal_ServerImpl::createService()
{
    boost::property_tree::ptree config = Globals::pConfig;

    try
    {
        config = config.get_child("LoginPortal");
    }
    catch (boost::property_tree::ptree_error &e)
    {
        LOG_APP->log0(__func__, Logs::LogLevel::INFO, "Configuration error: LoginPortal not found: %s", e.what());
        return false;
    }

    RESTful::Engine *loginWebServer = Program::Config::RESTful_Engine::createRESTfulEngine(config, LOG_APP, LOG_RPC, "Web Login", IAM_LOGINPORTAL_DEF_WEBROOTDIR,
                                                                                           Program::Config::REST_ENGINE_MANDATORY_SSL);

    if (!loginWebServer)
    {
        return false;
    }

    // Handle the login function for APP personalized site:
    loginWebServer->config.dynamicRequestHandlersByRoute["/logout"] = {&LoginPortal_Endpoints::handleLogoutDynamicRequest, nullptr};

    // Set the software version:
    loginWebServer->config.setSoftwareVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");

    // This will validate the JWT, the app should match with this:
    loginWebServer->config.appName = IAM_LOGINPORTAL_APPNAME;

    // Setup the methods handler for version 1:
    loginWebServer->endpointsHandler[1] = std::make_shared<API::RESTful::Endpoints>();

    // Set the validations against the LPToken
    loginWebServer->jwtAccessTokenName = "LPToken";

    // Set the login portal dynamic origin validation enabling some apps to embbed the service.
    loginWebServer->config.dynamicOriginValidator = appOriginValidatorFunction;

    // check if there is any session cookie and it comes from the proxy (embedded app auth), then, redirect.
    loginWebServer->config.dynamicInitialChecks = dynamicInitialChecks;

    // Add authentication methods
    LoginPortal_Endpoints::addEndpoints(loginWebServer->endpointsHandler[1]);

    loginWebServer->startInBackground();

    for (const std::shared_ptr<Sockets::Socket_Stream> &i : loginWebServer->getListenerSockets())
    {
        LOG_APP->log0(__func__, Logs::LogLevel::INFO, "Web Login Service Listening @%s", i->getLastBindAddress().c_str());
    }

    return true;
}
