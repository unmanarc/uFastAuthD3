#include <Mantids30/Config_Builder/program_logs.h>
#include <Mantids30/Helpers/file.h>
#include <Mantids30/Memory/a_bool.h>
#include <Mantids30/Net_Sockets/socket_tls.h>
#include <Mantids30/Program_Service/application.h>


#include "Web/UserPortal/userportal_serverimpl.h"
#include "Web/AdminPortal/adminportal_serverimpl.h"
#include "Web/LoginPortal/loginportal_serverimpl.h"
#include "Web/SessionAuthHandler/websessionauthhandler_serverimpl.h"
#include "Web/AppSync/appsync_serverimpl.h"
/*
#include "RPC1LoginServer2/fastrpcimpl.h"
#include "RPC1LoginServer2/rpc1loginserver2impl.h"
*/
#include "authstorageimpl.h"

#include "config.h"
#include "globals.h"

#include <sys/types.h>

#include <dirent.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <unistd.h>

#include <boost/property_tree/info_parser.hpp>

using namespace Mantids30;

class Main : public Program::Application
{
public:
    void _initvars(int, char *[], Program::Arguments::GlobalArguments *globalArguments)
    {
        // init variables (pre-config):
        globalArguments->setInifiniteWaitAtEnd(true);

        globalArguments->softwareLicense = "SSPLv1 (https://spdx.org/licenses/SSPL-1.0.html)";
        globalArguments->softwareDescription = PROJECT_DESCRIPTION;
        globalArguments->addAuthor({"Aarón Mizrachi", "dev@unmanarc.com"});
        globalArguments->setVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");

        globalArguments->addCommandLineOption("Service Options", 'c', "config-dir", "Configuration directory", "/etc/ufastauthd3", Memory::Abstract::Var::TYPE_STRING);
        globalArguments->addCommandLineOption("Recovery Options", 'r', "resetadmpw", "Reset Administrator Password", "false", Memory::Abstract::Var::TYPE_BOOL);
    }

    bool _config(int, char *argv[], Program::Arguments::GlobalArguments *globalArguments)
    {
        // process config:
        auto initLog = Program::Config::Logs::createInitLog();
        unsigned int logMode = Program::Logs::MODE_STANDARD;

        Network::Sockets::Socket_TLS::prepareTLS();

        Globals::setResetAdminPasswd(globalArguments->getCommandLineOptionBooleanValue("resetadmpw"));
        std::string configDir = globalArguments->getCommandLineOptionValue("config-dir")->toString();

        std::string configFile = configDir + "/ufastauthd3.conf";

        initLog->log0(__func__, Program::Logs::LEVEL_INFO, "Loading configuration: %s", (configFile).c_str());

        if (access(configDir.c_str(), R_OK))
        {
            initLog->log0(__func__, Program::Logs::LEVEL_CRITICAL, "Missing configuration dir: %s", configDir.c_str());
            return false;
        }

        //chdir(configDir.c_str());

        bool isConfigFileInsecure = true;
        if (!Helpers::File::isSensitiveConfigPermissionInsecure(configFile, &isConfigFileInsecure))
        {
            initLog->log0(__func__, Program::Logs::LEVEL_WARN, "The configuration 'ufastauthd3.conf' file is inaccessible, loading defaults...");
        }
        else
        {
            if (isConfigFileInsecure)
            {
                initLog->log0(__func__, Program::Logs::LEVEL_SECURITY_ALERT,
                              "The permissions of the '%s' file are currently not set to 0600. This may leave your API key exposed to potential security threats. To mitigate this risk, "
                              "we are changing the permissions of the file to ensure that your API key remains secure. Please ensure that you take necessary precautions to protect your API key and "
                              "update any affected applications or services as necessary.",configFile.c_str());

                if (Helpers::File::fixSensitiveConfigPermission(configFile))
                {
                    initLog->log0(__func__, Program::Logs::LEVEL_SECURITY_ALERT, "The permissions of the 'ufastauthd3.conf' file has been changed to 0600.");
                }
                else
                {
                    initLog->log0(__func__, Program::Logs::LEVEL_CRITICAL, "The permissions of the 'ufastauthd3.conf' file can't be changed.");
                    return false;
                }
            }

            try
            {
                boost::property_tree::info_parser::read_info(configFile, Globals::pConfig);
            }
            catch (const boost::property_tree::info_parser_error &ex)
            {
                initLog->log0(__func__, Program::Logs::LEVEL_CRITICAL,
                              "Unable to read configuration file '%s' (line %lu): %s",
                              configFile.c_str(),
                              static_cast<unsigned long>(ex.line()),
                              ex.what());
                return false;
            }
            catch (const std::exception &ex)
            {
                initLog->log0(__func__, Program::Logs::LEVEL_CRITICAL,
                              "Unexpected error while reading configuration file '%s': %s",
                              configFile.c_str(),
                              ex.what());
                return false;
            }
        }

        Globals::appLog = Program::Config::Logs::createAppLog(Globals::pConfig);
        Globals::rpcLog = Program::Config::Logs::createRPCLog(Globals::pConfig);

        return true;
    }

    int _start(int, char *[], Program::Arguments::GlobalArguments *globalArguments)
    {
        std::string configDir = globalArguments->getCommandLineOptionValue("config-dir")->toString();

        // start program.
        LOG_APP->log0(__func__, Program::Logs::LEVEL_INFO, "Starting... (Build date %s %s), PID: %" PRIi32, __DATE__, __TIME__, getpid());
        LOG_APP->log0(__func__, Program::Logs::LEVEL_INFO, "Using config dir: %s", configDir.c_str());

        // TODO: for MySQL/PostgreSQL Authenticator, how reconnect takes place?
        // Initiate the authenticator
        if (!AuthStorageImpl::createAuth())
        {
            _exit(-3);
        }

        /*
        // Creates the FastRPC Implementation
        Globals::setFastRPC(new FastRPCImpl); */

        // Dir Web Admin:
        if (!AdminPortal_ServerImpl::createService())
        {
            _exit(-5);
        }

        // Web Login:
        if (!LoginPortal_ServerImpl::createService())
        {
            _exit(-6);
        }

        // Web Login:
        if (!WebSessionAuthHandler_ServerImpl::createService())
        {
            _exit(-7);
        }

        if (!AppSync_ServerImpl::createService())
        {
            _exit(-8);
        }

        // Dir Web User:
        if (!UserPortal_ServerImpl::createService())
        {
            _exit(-9);
        }
        /*// Initiate the RPC Listener
        if (!RPC1LoginServer2Impl::createRPCListenerCAB())
        {
            _exit(-2);
        }
        // Initiate the RPC Listener
        if (!RPC1LoginServer2Impl::createRPCListenerPAB())
        {
            _exit(-4);
        }*/

        LOG_APP->log0(__func__, Program::Logs::LEVEL_INFO, (globalArguments->getDaemonName() + " initialized with PID: %" PRIi32).c_str(), getpid());

        return 0;
    }

    void _shutdown()
    {

    }
};

int main(int argc, char *argv[])
{
    Main *main = new Main;
    return StartApplication(argc, argv, main);
}
