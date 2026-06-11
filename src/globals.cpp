#include "globals.h"

LoginDirectoryManager *Globals::loginDirManager = nullptr;
IdentityManager *Globals::identityManager = nullptr;
std::shared_ptr<Mantids30::Program::Logs::AppLog> Globals::appLog = nullptr;
std::shared_ptr<Mantids30::Program::Logs::RPCLog> Globals::rpcLog = nullptr;
boost::property_tree::ptree Globals::pConfig;
bool Globals::resetAdminPasswd = false;
Mantids30::Network::Servers::Web::APIServerCore *Globals::webLoginServer = nullptr;

IdentityManager *Globals::getIdentityManager()
{
    return identityManager;
}

void Globals::setIdentityManager(IdentityManager *value)
{
    identityManager = value;
}

bool Globals::getResetAdminPasswd()
{
    return resetAdminPasswd;
}

void Globals::setResetAdminPasswd(bool newResetAdminPasswd)
{
    resetAdminPasswd = newResetAdminPasswd;
}

LoginDirectoryManager *Globals::getLoginDirManager()
{
    return loginDirManager;
}

void Globals::setLoginDirManager(LoginDirectoryManager *newLoginDirManager)
{
    loginDirManager = newLoginDirManager;
}

Mantids30::Network::Servers::Web::APIServerCore *Globals::getWebLoginServer()
{
    return webLoginServer;
}

void Globals::setWebLoginServer(Mantids30::Network::Servers::Web::APIServerCore *newWebLoginServer)
{
    webLoginServer = newWebLoginServer;
}
