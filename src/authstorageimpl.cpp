#include "authstorageimpl.h"
#include "Mantids30/Program_Logs/loglevels.h"
#include "globals.h"

#include <sys/stat.h>

#include <Mantids30/Program_Logs/applog.h>

#include <boost/algorithm/string/case_conv.hpp>

#include <Mantids30/DB_SQLite3/sqlconnector_sqlite3.h>
#include <Mantids30/Helpers/crypto.h>
#include <Mantids30/Helpers/random.h>

#include "defs.h"

#ifdef WIN32
#include <windows.h>
#endif

#include <fstream>

using namespace Mantids30::Database;
using namespace Mantids30::Program;
using namespace Mantids30;

bool AuthStorageImpl::createAuth()
{
    std::string sDriverName = Globals::pConfig.get<std::string>("Auth.Driver", "");
    std::string sDefaultUser = Globals::pConfig.get<std::string>("Auth.DefaultUser", "admin");

    IdentityManager_DB *identityManager = nullptr;

    if (boost::to_lower_copy(sDriverName) == "sqlite3")
    {
        SQLConnector_SQLite3 *dbConnector = new SQLConnector_SQLite3();

        dbConnector->setThrowCPPErrorOnQueryFailure(Globals::pConfig.get<bool>("Auth.TerminateOnSQLError", false));

        if (!dbConnector->connectInMemory())
        {
            LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error, Failed to create in-memory SQLite3 database");
            delete dbConnector;
            return false;
        }

        auto createFileIfNotExists = [](const std::string &path) -> bool
        {
            struct stat buffer;
            if (stat(path.c_str(), &buffer) == 0)
                return true;
            std::ofstream file(path);
            if (!file.is_open())
            {
                LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Failed to create database file: '%s'", path.c_str());
                return false;
            }
            file.close();
#ifdef WIN32
            _chmod(path.c_str(), _S_IREAD | _S_IWRITE);
#else
            chmod(path.c_str(), 0600);
#endif
            return true;
        };

        std::string dbFilePath = Globals::pConfig.get<std::string>("Auth.IAMMainFile", "");
        std::string dbLogsPath = Globals::pConfig.get<std::string>("Auth.IAMLogsFile", "");

        if (!createFileIfNotExists(dbFilePath))
        {
            delete dbConnector;
            return false;
        }

        if (!createFileIfNotExists(dbLogsPath))
        {
            delete dbConnector;
            return false;
        }

        if (!dbConnector->attach(dbFilePath, "iam"))
        {
            LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error, Failed to attach IAM SQLite3 database file: '%s'", dbFilePath.c_str());
            delete dbConnector;
            return false;
        }
        else
        {
            LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Opened IAM SQLite3 database file: '%s'", dbFilePath.c_str());
        }

        if (!dbConnector->attach(dbLogsPath, "logs"))
        {
            LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error, Failed to attach logs SQLite3 database file: '%s'", dbLogsPath.c_str());
            delete dbConnector;
            return false;
        }
        else
        {
            LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Opened logs SQLite3 database file: '%s'", dbLogsPath.c_str());
        }

        identityManager = new IdentityManager_DB(dbConnector);
    }
    /*    else if (boost::to_lower_copy(driver) == "postgresql")
    {
        // TODO:
        return false;
    }
    else if (boost::to_lower_copy(driver) == "mariadb")
    {
        // TODO:
        return false;
    }*/
    else
    {
        LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error, Authentication driver '%s' not implemented", sDriverName.c_str());
    }

    if (!identityManager)
        return false;

    std::string sInitPW;

    if (!identityManager->initializeDatabase())
    {
        LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error (Driver: %s), Unknown error during database scheme initialization.", sDriverName.c_str());
        return false;
    }

    bool r = true;
    bool appExisted, userExisted, defaultPasswordSchemesExisted;

    std::optional<uint32_t> schemeId = identityManager->authController->initializateDefaultPasswordSchemes(&defaultPasswordSchemesExisted);

    if (defaultPasswordSchemesExisted)
    {
        if (!schemeId.has_value())
        {
            r = false;
            LOG_APP->log0(__func__, Logs::LEVEL_ERR, "Default password scheme for simple login does not exist anymore.");
        }
        else
        {
            // Perfect, continue.
        }
    }
    else
    {
        if (!schemeId.has_value())
        {
            r = false;
            LOG_APP->log0(__func__, Logs::LEVEL_ERR, "Default password scheme for simple login can't be created.");
        }
        else
        {
            LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Default password scheme for simple login successfully created.");
        }
    }

    if (r)
    {
        r = r && identityManager->initializeAdminAccountWithPassword(sDefaultUser, &sInitPW, *schemeId, &userExisted);

        if (userExisted)
        {
            // User exist, do nothing.
            LOG_APP->log0(__func__, Logs::LEVEL_DEBUG, "Default user '%s' already exist.", sDefaultUser.c_str());
        }
        else
        {
            if (r)
            {
                LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Default user '%s' successfully created.", sDefaultUser.c_str());
            }
            else
            {
                LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Default user '%s' can't be created.", sDefaultUser.c_str());
                return false;
            }
        }
    }

    if (r)
    {
        r = r && identityManager->initializeApplicationWithScheme(IAM_ADMPORTAL_APPNAME, IAM_ADMPORTAL_DESCRIPTION, IAM_ADMPORTAL_URL, *schemeId, sDefaultUser, &appExisted);
        if (appExisted)
        {
            // User exist, do nothing.
            LOG_APP->log0(__func__, Logs::LEVEL_DEBUG, "App '%s' already exist.", IAM_ADMPORTAL_APPNAME);
        }
        else
        {
            if (r)
            {
                LOG_APP->log0(__func__, Logs::LEVEL_INFO, "APP '%s' successfully created.", IAM_ADMPORTAL_APPNAME);
            }
            else
            {
                LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "APP '%s' can't be created.", IAM_ADMPORTAL_APPNAME);
                return false;
            }
        }
    }

    if (r)
    {
        r = r && identityManager->initializeApplicationWithScheme(IAM_USRPORTAL_APPNAME, IAM_USRPORTAL_DESCRIPTION, IAM_USRPORTAL_URL, *schemeId, sDefaultUser, &appExisted);
        if (appExisted)
        {
            // User exist, do nothing.
            LOG_APP->log0(__func__, Logs::LEVEL_DEBUG, "App '%s' already exist.", IAM_USRPORTAL_APPNAME);
        }
        else
        {
            if (r)
            {
                LOG_APP->log0(__func__, Logs::LEVEL_INFO, "APP '%s' successfully created.", IAM_USRPORTAL_APPNAME);
            }
            else
            {
                LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "APP '%s' can't be created.", IAM_USRPORTAL_APPNAME);
                return false;
            }
        }
    }

    // Check account flags:
    auto accountFlags = identityManager->accounts->getAccountFlags(sDefaultUser);

    // Check for admin accounts:
    if (identityManager->accounts->doesAccountExist(sDefaultUser) && !accountFlags.admin)
    {
        // This account should be marked as admin.
        LOG_APP->log0(__func__, Logs::LEVEL_ERR, "Account '%s' detected without admin privileges. Manual intervention required to grant admin status.", sDefaultUser.c_str());
    }
    else if (identityManager->accounts->doesAccountExist(sDefaultUser) && identityManager->accounts->isAccountExpired(sDefaultUser))
    {
        // This account should not expire.
        LOG_APP->log0(__func__, Logs::LEVEL_ERR, "Account '%s' is currently expired. Reactivation required immediately to ensure proper system management.", sDefaultUser.c_str());
    }
    else if (identityManager->accounts->doesAccountExist(sDefaultUser) && !accountFlags.enabled)
    {
        // This account should not be disabled.
        LOG_APP->log0(__func__, Logs::LEVEL_ERR, "Account '%s' is disabled. Enable the account to maintain essential administrative functions.", sDefaultUser.c_str());
    }
    else if (identityManager->accounts->doesAccountExist(sDefaultUser) && !accountFlags.confirmed)
    {
        // This account should not be disabled.
        LOG_APP->log0(__func__, Logs::LEVEL_ERR, "Account '%s' exists but is unconfirmed. Confirmation is necessary for full functionality.", sDefaultUser.c_str());
    }

    // If password marked for reset, reset:
    if (Globals::getResetAdminPasswd())
    {
        LOG_APP->log0(__func__, Logs::LEVEL_WARN, "Password marked to be reseted...");
        std::string sInitPW;
        if (!schemeId.has_value() || !identityManager->authController->setAccountPasswordOnScheme(sDefaultUser, &sInitPW, *schemeId))
        {
            LOG_APP->log0(__func__, Logs::LEVEL_ERR, "Password not resetted (Maybe the account '%s' does not have admin privileges?)...", sDefaultUser.c_str());
            return false;
        }
    }

    if (!sInitPW.empty())
    {
        // Create the password file if there is a new password...
        if (!createPassFile(sInitPW))
            return false;
    }

    if (!configureApplication(identityManager, sDefaultUser))
        return false;

    Globals::setIdentityManager(identityManager);

    return true;
}

bool AuthStorageImpl::createPassFile(const std::string &sInitPW)
{
#ifndef WIN32
    std::string initPassOutFile = "/tmp/syspwd-" + Mantids30::Helpers::Random::createRandomString(8);
#else
    char tempPath[MAX_PATH + 1];
    GetTempPathA(MAX_PATH, tempPath);
    std::string initPassOutFile = tempPath + "\\syspwd-" + Mantids30::Helpers::Random::createRandomString(8) + ".txt";
#endif
    std::ofstream ofstr(initPassOutFile);
    if (ofstr.fail())
    {
        LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Failed to save the password account.");
        return false;
    }
#ifndef WIN32
    if (chmod(initPassOutFile.c_str(), 0600) != 0)
    {
        LOG_APP->log0(__func__, Logs::LEVEL_WARN, "Failed to chmod the password file (be careful with this file and content).");
    }
#else
    LOG_APP->log0(__func__, Logs::LEVEL_WARN, "Initial password was saved without special owner read-only privileges (be careful).");
#endif
    ofstr << sInitPW;
    ofstr.close();
    LOG_APP->log0(__func__, Logs::LEVEL_INFO, "File '%s' created with the super-user password. Login and change it immediatly", initPassOutFile.c_str());
    return true;
}

/*
bool AuthStorageImpl::resetAdminPwd(IdentityManager_DB *identityManager, std::string *sInitPW)
{
    *sInitPW = Mantids30::Helpers::Random::createRandomString(16);

    Credential credentialData;
    credentialData.hash = Helpers::Crypto::calcSHA256(*sInitPW);

    credentialData.
    credentialData.passwordFunction = FN_SHA256;
    credentialData.forceExpiration = true; // Expired (to be changed on the first login).

    return identityManager->authController->changeCredential("admin", credentialData);
}*/

bool AuthStorageImpl::configureApplication(IdentityManager_DB *identityManager, const std::string &owner)
{
    if (!identityManager->applications->doesApplicationExist(IAM_ADMPORTAL_APPNAME))
    {
        LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Application '%s' does not exist, aborting.", IAM_ADMPORTAL_APPNAME);
        return false;
    }
    std::list<ApplicationScope> appScopes = {
                                                {IAM_ADMPORTAL_APPNAME, "SELF_PWDCHANGE", "Change my own password"},
                                                {IAM_ADMPORTAL_APPNAME, "SELF_READ", "Read my own user data from the IAM system"},
                                                {IAM_ADMPORTAL_APPNAME, "SELF_DELETE", "Delete my own user"},
                                                {IAM_ADMPORTAL_APPNAME, "ACCOUNT_READ", "Read accounts data from the IAM system"},
                                                {IAM_ADMPORTAL_APPNAME, "ACCOUNT_DELETE", "Delete accounts from the IAM system"},
                                                {IAM_ADMPORTAL_APPNAME, "ACCOUNT_MODIFY", "Edit accounts details, roles, and scopes"},
                                                {IAM_ADMPORTAL_APPNAME, "ACCOUNT_PWDDCHANGE", "Change account passwords"},
                                                {IAM_ADMPORTAL_APPNAME, "ACCOUNT_DISABLE", "Disable/lock accounts"},
                                                {IAM_ADMPORTAL_APPNAME, "ACCOUNT_ENABLE", "Enable/unlock accounts"},
                                                {IAM_ADMPORTAL_APPNAME, "APP_CREATE", "Create applications on the IAM"},
                                                {IAM_ADMPORTAL_APPNAME, "APP_DELETE", "Delete application's from the IAM"},
                                                {IAM_ADMPORTAL_APPNAME, "APP_MODIFY", "Modify application data on the IAM"},
                                                {IAM_ADMPORTAL_APPNAME, "APP_READ", "Read application data from the IAM"},
                                                {IAM_ADMPORTAL_APPNAME, "AUTH_CREATE", "Create authentication schemes and slots on the IAM"},
                                                {IAM_ADMPORTAL_APPNAME, "AUTH_DELETE", "Delete authentication schemes and slots on the IAM"},
                                                {IAM_ADMPORTAL_APPNAME, "AUTH_MODIFY", "Modify authentication schemes and slots on the IAM"},
                                                {IAM_ADMPORTAL_APPNAME, "AUTH_READ", "Read authentication schemes and slots on the IAM"},
                                                {IAM_ADMPORTAL_APPNAME, "CONFIG_READ", "Read the configuration of the IAM"},
                                                {IAM_ADMPORTAL_APPNAME, "CONFIG_WRITE", "Write the configuration of the IAM"},
                                                {IAM_ADMPORTAL_APPNAME, "AUDIT_LOG_VIEW", "Access, export and view IAM audit logs"},
                                                {IAM_ADMPORTAL_APPNAME, "AUDIT_LOG_CLEAN", "Clean/remove audit logs"}
                                            };

    for (auto &scope : appScopes)
    {
        if (!identityManager->authController->doesApplicationScopeExist(scope))
        {
            LOG_APP->log0(__func__, Logs::LEVEL_WARN, "Scope '%s' does not exist, creating it.", scope.id.c_str());

            if (!identityManager->authController->addApplicationScope(scope))
            {
                LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Failed to create the scope '%s'.", scope.id.c_str());
                return false;
            }
        }
    }

    if (!identityManager->applications->validateApplicationAccount(IAM_ADMPORTAL_APPNAME, owner))
    {
        LOG_APP->log0(__func__, Logs::LEVEL_WARN, "Setting up '%s' user as application '%s' user.", owner.c_str(), IAM_ADMPORTAL_APPNAME);

        if (!identityManager->applications->addAccountToApplication(IAM_ADMPORTAL_APPNAME, owner))
        {
            LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Failed to set the '%s' account as application '%s' user.", owner.c_str(), IAM_ADMPORTAL_APPNAME);
            return false;
        }
    }

    if (!identityManager->applications->validateApplicationOwner(IAM_ADMPORTAL_APPNAME, owner))
    {
        LOG_APP->log0(__func__, Logs::LEVEL_WARN, "Setting up '%s' user as application '%s' owner.", owner.c_str(), IAM_ADMPORTAL_APPNAME);

        if (!identityManager->applications->addApplicationOwner(IAM_ADMPORTAL_APPNAME, owner))
        {
            LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Failed to set the '%s' account as application '%s' owner.", owner.c_str(), IAM_ADMPORTAL_APPNAME);
            return false;
        }
    }

    return true;
}
