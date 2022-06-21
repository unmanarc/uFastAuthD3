#include <mdz_prg_service/application.h>
#include <mdz_net_sockets/socket_tls.h>
#include <mdz_mem_vars/a_bool.h>

#include "loginauthmethods.h"

#include "loginrpcserverimpl.h"
#include "webserverimpl.h"
#include "authstorageimpl.h"

#include "globals.h"
#include "config.h"
#include "defs.h"

#include <sys/types.h>

#include <signal.h>
#include <dirent.h>
#include <unistd.h>
#include <inttypes.h>

using namespace AUTHSERVER;

using namespace Mantids::Application;

class Main : public Application
{
public:

    void _shutdown()
    {
    }

    int _start(int , char *[], Arguments::GlobalArguments *globalArguments)
    {
        std::string configDir = globalArguments->getCommandLineOptionValue("config-dir")->toString();

        // start program.
        Globals::getAppLog()->log(__func__, "","", Logs::LEVEL_INFO, 2048, "Starting... (Build date %s %s), PID: %" PRIi32,__DATE__, __TIME__, getpid());
        Globals::getAppLog()->log0(__func__,Logs::LEVEL_INFO, "Using config dir: %s", configDir.c_str());

        // TODO: for MySQL Authenticator, how reconnect takes place?
        // Initiate the authenticator
        if (!AUTHSERVER::AUTH::AuthStorageImpl::createAuth())
        {
            _exit(-3);
        }

        // Initiate the RPC Listener
        if (!AUTHSERVER::RPC::LoginRPCServerImpl::createRPCListener())
        {
            _exit(-2);
        }

        // Initiate the web server
        if (!AUTHSERVER::WEB::WebServerImpl::createWebServer())
        {
            _exit(-1);
        }

        Globals::getAppLog()->log0(__func__,Logs::LEVEL_INFO,  (globalArguments->getDaemonName() + " initialized with PID: %d").c_str(), getpid());

        return 0;
    }

    void _initvars(int , char *[], Arguments::GlobalArguments * globalArguments)
    {
        // init variables (pre-config):
        globalArguments->setInifiniteWaitAtEnd(true);

        globalArguments->setLicense("SSPLv1 (https://spdx.org/licenses/SSPL-1.0.html)");
        globalArguments->setAuthor("Aarón Mizrachi");
        globalArguments->setEmail("dev@unmanarc.com");
        globalArguments->setVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");
        globalArguments->setDescription(PROJECT_DESCRIPTION);

        globalArguments->addCommandLineOption("Service Options", 'c', "config-dir" , "Configuration directory"  , "/etc/ufastauthd", Mantids::Memory::Abstract::TYPE_STRING );
        globalArguments->addCommandLineOption("Recovery Options", 'r', "resetadmpw" , "Reset Administrator Password"  , "false", Mantids::Memory::Abstract::TYPE_BOOL );
    }

    bool _config(int , char *argv[], Arguments::GlobalArguments * globalArguments)
    {
        // process config:
        unsigned int logMode = Logs::MODE_STANDARD;

        Mantids::Network::TLS::Socket_TLS::prepareTLS();

        Logs::AppLog initLog(Logs::MODE_STANDARD);
        initLog.setPrintEmptyFields(true);
        initLog.setUsingColors(true);
        initLog.setUsingPrintDate(true);
        initLog.setModuleAlignSize(26);
        initLog.setUsingAttributeName(false);
        initLog.setStandardLogSeparator(",");

        Globals::setResetAdminPasswd(
                    ((Mantids::Memory::Abstract::BOOL *)globalArguments->getCommandLineOptionValue("resetadmpw"))->getValue()
                );

        std::string configDir = globalArguments->getCommandLineOptionValue("config-dir")->toString();

        initLog.log0(__func__,Logs::LEVEL_INFO, "Loading configuration: %s", (configDir + "/config.ini").c_str());

        boost::property_tree::ptree config_main;

        if (access(configDir.c_str(),R_OK))
        {
            initLog.log0(__func__,Logs::LEVEL_CRITICAL, "Missing configuration dir: %s", configDir.c_str());
            return false;
        }

        chdir(configDir.c_str());

        if (!access("config.ini",R_OK))
            boost::property_tree::ini_parser::read_ini("config.ini",config_main);
        else
        {
            initLog.log0(__func__,Logs::LEVEL_CRITICAL, "Missing configuration: %s", "/config.ini");
            return false;
        }

        *(Globals::getConfig_main()) = config_main;

        if ( config_main.get<bool>("Logs.ToSyslog",true) ) logMode|=Logs::MODE_SYSLOG;

        Globals::setAppLog(new Logs::AppLog(logMode));
        Globals::getAppLog()->setPrintEmptyFields(true);
        Globals::getAppLog()->setUsingColors(config_main.get<bool>("Logs.ShowColors",true));
        Globals::getAppLog()->setUsingPrintDate(config_main.get<bool>("Logs.ShowDate",true));
        Globals::getAppLog()->setModuleAlignSize(26);
        Globals::getAppLog()->setUsingAttributeName(false);
        Globals::getAppLog()->setStandardLogSeparator(",");
        Globals::getAppLog()->setDebug(Globals::getConfig_main()->get<bool>("Logs.Debug",false));


        Globals::setRPCLog(new Logs::RPCLog(logMode));
        Globals::getRPCLog()->setPrintEmptyFields(true);
        Globals::getRPCLog()->setUsingColors(config_main.get<bool>("Logs.ShowColors",true));
        Globals::getRPCLog()->setUsingPrintDate(config_main.get<bool>("Logs.ShowDate",true));
        Globals::getRPCLog()->setDisableDomain(true);
        Globals::getRPCLog()->setDisableModule(true);
        Globals::getRPCLog()->setModuleAlignSize(26);
        Globals::getRPCLog()->setUsingAttributeName(false);
        Globals::getRPCLog()->setStandardLogSeparator(",");
        Globals::getRPCLog()->setDebug(Globals::getConfig_main()->get<bool>("Logs.Debug",false));

        return true;
    }
};

int main(int argc, char *argv[])
{
    Main * main = new Main;
    return StartApplication(argc,argv,main);
}

