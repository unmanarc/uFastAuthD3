#pragma once

#include "Web/LoginPortal/logindirectorymanager.h"

#include <Mantids30/Program_Logs/applog.h>
#include <Mantids30/Program_Logs/rpclog.h>
#include <Mantids30/Protocol_FastRPC1/fastrpc.h>
#include <Mantids30/Server_WebCore/apiserver_core.h>

#include "IdentityManager/identitymanager.h"
#include "defs.h"

#include <boost/property_tree/ptree.hpp>

#define LOG_RPC Globals::rpcLog
#define LOG_APP Globals::appLog

class Globals
{
public:
    Globals() = default;

    static Mantids30::Program::Logs::RPCLog *getRPCLog();
    static void setRPCLog(Mantids30::Program::Logs::RPCLog *value);

    static Mantids30::Program::Logs::AppLog *getAppLog();
    static void setAppLog(Mantids30::Program::Logs::AppLog *value);

    //static boost::property_tree::ptree *getConfig();

    static inline IdentityManager *getIdentityManager() { return identityManager; }

    static void setIdentityManager(IdentityManager *value);

    static bool getDoCreateNewAdminAccount();
    static void setToCreateNewAdminAccount(const bool & newResetAdminPasswd);

    static LoginDirectoryManager *getLoginDirManager();
    static void setLoginDirManager(LoginDirectoryManager *newLoginDirManager);

    static Mantids30::Network::Servers::Web::APIServerCore *getWebLoginServer();
    static void setWebLoginServer(Mantids30::Network::Servers::Web::APIServerCore *newWebLoginServer);

/*
    static Mantids30::Network::Protocol::FastRPC::FastRPC1 *getFastRPC();
    static void setFastRPC(Mantids30::Network::Protocol::FastRPC::FastRPC1 *newFastRPC);
*/
    static std::shared_ptr<Mantids30::Program::Logs::RPCLog> rpcLog;
    static std::shared_ptr<Mantids30::Program::Logs::AppLog> appLog;
    static boost::property_tree::ptree pConfig;

private:
    static bool doCreateNewAdminAccount;
    static LoginDirectoryManager *loginDirManager;
    static IdentityManager *identityManager;
    static Mantids30::Network::Servers::Web::APIServerCore *webLoginServer;
    //    static Mantids30::Network::Protocol::FastRPC::FastRPC1 *fastRPC;
};
