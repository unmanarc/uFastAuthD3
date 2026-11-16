#include "appsync_serverimpl.h"
#include "appsync_endpoints.h"
#include "config.h"
#include "defs.h"
#include "globals.h"

#include <Mantids30/ConfigBuilder/Server_WebRESTFul/config_builder.h>
#include <Mantids30/Server/WebRESTFul/engine.h>

#include <boost/algorithm/string/predicate.hpp>
#include <memory>

// Imported namespaces are shortened and grouped for better readability
using namespace Mantids30;
using namespace Mantids30::Network;
using namespace Mantids30::Network::Sockets;
using namespace Mantids30::Server::WebRESTFul;
using namespace Mantids30::Runtime;

bool AppSync_ServerImpl::createService()
{
    boost::property_tree::ptree config = Globals::pConfig;

    try
    {
        config = config.get_child("AppSyncWebService");
    }
    catch (boost::property_tree::ptree_error &e)
    {
        LOG_APP->log0(__func__, Logs::LogLevel::INFO, "Configuration error: AppSyncWebService not found: %s", e.what());
        return false;
    }

    Mantids30::Server::WebRESTFul::Engine *webSessionAuthHandlerServer = ConfigBuilder::Server_WebRESTFul::Builder::createRESTfulEngine(config, LOG_APP, LOG_RPC, "Application Synchronization Service", IAM_LOGINPORTAL_DEF_WEBROOTDIR,
                                                                                                        ConfigBuilder::Server_WebRESTFul::REST_ENGINE_NOCONFIG_JWT);

    if (!webSessionAuthHandlerServer)
    {
        return false;
    }

    // Set the software version:
    webSessionAuthHandlerServer->config.setSoftwareVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");

    // Setup the methods handler for version 1:
    webSessionAuthHandlerServer->endpointsHandler[1] = std::make_shared<Mantids30::Server::WebRESTFul::RESTful::Endpoints>();

    // This will validate the JWT, the app should match with this:
    webSessionAuthHandlerServer->config.appName = "APPSYNC";

    // Add authentication methods
    AppSync_Endpoints::addAPIEndpoints(webSessionAuthHandlerServer->endpointsHandler[1]);

    webSessionAuthHandlerServer->startInBackground();

    for (const std::shared_ptr<Sockets::Socket_Stream> &i : webSessionAuthHandlerServer->getListenerSockets())
    {
        LOG_APP->log0(__func__, Logs::LogLevel::INFO, "Application Synchronization Service Listening @%s", i->getLastBindAddress().c_str());
    }

    return true;
}
