#include "adminportal_serverimpl.h"
#include "adminportal_endpoints.h"

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

bool AdminPortal_ServerImpl::createService()
{
    boost::property_tree::ptree config = Globals::pConfig;
    try
    {
        config = config.get_child("AdminPortal");
    }
    catch (boost::property_tree::ptree_error &e)
    {
        LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Configuration error: AdminPortal not found: %s", e.what());
        return false;
    }

    std::map<std::string, std::string> vars;
    vars["APIKEY"] = Globals::getIdentityManager()->applications->getApplicationAPIKey(IAM_ADMPORTAL_APPNAME);

    RESTful::Engine *adminPortalWebServer = Program::Config::RESTful_Engine::createRESTfulEngine(config, LOG_APP, LOG_RPC, "AdminPortal", IAM_ADMPORTAL_DEF_WEBROOTDIR,
                                                                                           Program::Config::REST_ENGINE_NOCONFIG_JWT | Program::Config::REST_ENGINE_MANDATORY_SSL, vars);

    if (!adminPortalWebServer)
        return false;

    // JWT:
    adminPortalWebServer->config.jwtValidator = Globals::getIdentityManager()->applications->getAppJWTValidator(IAM_ADMPORTAL_APPNAME);
    if (!adminPortalWebServer->config.jwtValidator)
    {
        LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "We need a JWT Validator for the IAM Portal Web Server (2).");
        return false;
    }

    // This will validate the JWT, the app should match with this:
    adminPortalWebServer->config.appName = IAM_ADMPORTAL_APPNAME;

    // Set the software version:
    adminPortalWebServer->config.setSoftwareVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");

    // Setup the methods handler for version 1:
    adminPortalWebServer->endpointsHandler[1] = std::make_shared<API::RESTful::Endpoints>();

    // Add authentication methods
    AdminPortal_Endpoints::addEndpoints(adminPortalWebServer->endpointsHandler[1]);

    adminPortalWebServer->startInBackground();

    LOG_APP->log0(__func__, Logs::LEVEL_INFO, "IAM Admin Portal Web Server Listening @%s", adminPortalWebServer->getListenerSocket()->getLastBindAddress().c_str());

    return true;
}
