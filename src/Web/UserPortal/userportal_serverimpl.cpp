#include "userportal_serverimpl.h"
#include "userportal_endpoints.h"

#include "config.h"
#include "defs.h"
#include "globals.h"

#include <Mantids30/Config_Builder/restful_engine.h>
#include <Mantids30/Server_RESTfulWebAPI/engine.h>
#include <boost/algorithm/string/predicate.hpp>
#include <memory>

// Imported namespaces are shortened and grouped for better readability
using namespace Mantids30;
using namespace Network;
using namespace Network::Sockets;
using namespace Network::Servers;
using namespace Program;

bool UserPortal_ServerImpl::createService()
{
    boost::property_tree::ptree config = Globals::pConfig;
    try
    {
        config = config.get_child("UserPortal");
    }
    catch (boost::property_tree::ptree_error &e)
    {
        LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Configuration error: UserPortal not found: %s", e.what());
        return false;
    }

    std::map<std::string, std::string> vars;
    vars["APIKEY"] = Globals::getIdentityManager()->applications->getApplicationAPIKey(IAM_USRPORTAL_APPNAME);

    RESTful::Engine *userPortalWebServer = Program::Config::RESTful_Engine::createRESTfulEngine(config, LOG_APP, LOG_RPC, "UserPortal", IAM_USRPORTAL_DEF_WEBROOTDIR,
                                                                                           Program::Config::REST_ENGINE_NOCONFIG_JWT | Program::Config::REST_ENGINE_MANDATORY_SSL, vars);

    if (!userPortalWebServer)
        return false;

    // JWT:
    userPortalWebServer->config.jwtValidator = Globals::getIdentityManager()->applications->getAppJWTValidator(IAM_USRPORTAL_APPNAME);
    if (!userPortalWebServer->config.jwtValidator)
    {
        LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "We need a JWT Validator for the IAM User Portal Web Server (2).");
        return false;
    }

    // This will validate the JWT, the app should match with this:
    userPortalWebServer->config.appName = IAM_USRPORTAL_APPNAME;

    // Set the software version:
    userPortalWebServer->config.setSoftwareVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");

    // Setup the methods handler for version 1:
    userPortalWebServer->endpointsHandler[1] = std::make_shared<API::RESTful::Endpoints>();

    // Add authentication methods
    UserPortal_Endpoints::addEndpoints(userPortalWebServer->endpointsHandler[1]);

    userPortalWebServer->startInBackground();

    LOG_APP->log0(__func__, Logs::LEVEL_INFO, "IAM User Portal Web Server Listening @%s", userPortalWebServer->getListenerSocket()->getLastBindAddress().c_str());

    return true;
}
