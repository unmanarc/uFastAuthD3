#pragma once

#include "Web/LoginPortal/logindirectorymanager.h"

#include <Mantids30/Runtime/Logs/applog.h>
#include <Mantids30/Runtime/Logs/rpclog.h>
#include <Mantids30/Protocol/FastRPC1/fastrpc.h>
#include <Mantids30/Server/WebRESTFul/apiserver_core.h>

#include "IdentityManager/identitymanager.h"
#include "defs.h"

#include <boost/property_tree/ptree.hpp>

#define LOG_RPC Globals::rpcLog
#define LOG_APP Globals::appLog

class Globals
{
public:
    Globals() = default;

    static Mantids30::Runtime::Logs::RPCLog *getRPCLog();
    static void setRPCLog(Mantids30::Runtime::Logs::RPCLog *value);

    static Mantids30::Runtime::Logs::AppLog *getAppLog();
    static void setAppLog(Mantids30::Runtime::Logs::AppLog *value);

    static inline IdentityManager *getIdentityManager() { return identityManager; }

    static void setIdentityManager(IdentityManager *value);

    static bool getDoCreateNewAdminAccount();
    static void setToCreateNewAdminAccount(const bool & newResetAdminPasswd);

    static LoginDirectoryManager *getLoginDirManager();
    static void setLoginDirManager(LoginDirectoryManager *newLoginDirManager);

    static Mantids30::Server::WebRESTFul::APIServerCore *getWebLoginServer();
    static void setWebLoginServer(Mantids30::Server::WebRESTFul::APIServerCore *newWebLoginServer);

/*
    static Mantids30::Protocol::FastRPC1::FastRPC1 *getFastRPC();
    static void setFastRPC(Mantids30::Protocol::FastRPC1::FastRPC1 *newFastRPC);
*/
    static std::shared_ptr<Mantids30::Runtime::Logs::RPCLog> rpcLog;
    static std::shared_ptr<Mantids30::Runtime::Logs::AppLog> appLog;
    static boost::property_tree::ptree pConfig;

private:
    static bool doCreateNewAdminAccount;
    static LoginDirectoryManager *loginDirManager;
    static IdentityManager *identityManager;
    static Mantids30::Server::WebRESTFul::APIServerCore *webLoginServer;
    //    static Mantids30::Protocol::FastRPC1::FastRPC1 *fastRPC;
};
