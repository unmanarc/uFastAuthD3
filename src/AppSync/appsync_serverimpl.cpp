#include "appsync_serverimpl.h"
#include "config.h"
#include "defs.h"
#include "globals.h"
#include "appsync_apiendpoints.h"

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

bool AppSync_ServerImpl::createService()
{
    boost::property_tree::ptree config = Globals::pConfig;

    try
    {
        config = config.get_child("AppSyncWebService");
    }
    catch (boost::property_tree::ptree_error &e)
    {
        LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Configuration error: AppSyncWebService not found: %s", e.what());
        return false;
    }

    RESTful::Engine *webSessionAuthHandlerServer = Program::Config::RESTful_Engine::createRESTfulEngine(config, LOG_APP, LOG_RPC, "Application Synchronization Service", AUTHSERVER_WEBDIR, Program::Config::REST_ENGINE_NOCONFIG_JWT);

    if (!webSessionAuthHandlerServer)
        return false;

    // Set the software version:
    webSessionAuthHandlerServer->config.setSoftwareVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");

    // Setup the methods handler for version 1:
    webSessionAuthHandlerServer->endpointsHandler[1] = std::make_shared<API::RESTful::Endpoints>();

    // This will validate the JWT, the app should match with this:
    webSessionAuthHandlerServer->config.appName = "APPSYNC";

    // Add authentication methods
    AppSync_Endpoints::addAPIEndpoints(webSessionAuthHandlerServer->endpointsHandler[1]);

    webSessionAuthHandlerServer->startInBackground();

    LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Application Synchronization Service Listening @%s", webSessionAuthHandlerServer->getListenerSocket()->getLastBindAddress().c_str());

    return true;
}
