#include "authstorageimpl.h"
#include <Mantids30/API_EndpointsAndSessions/session.h>
#include <Mantids30/Program_Logs/loglevels.h>
#include <Mantids30/Helpers/json.h>
#include "globals.h"

#include <optional>
#include <sys/stat.h>

#include <Mantids30/Program_Logs/applog.h>

#include <boost/algorithm/string/case_conv.hpp>

#include <Mantids30/DB_SQLite3/sqlconnector_sqlite3.h>
#include <Mantids30/Helpers/crypto.h>
#include <Mantids30/Helpers/random.h>

#include "defs.h"


#include <fstream>

#include "Web/AppSync/appsync_endpoints.h"

using namespace Mantids30::Database;
using namespace Mantids30::Program;
using namespace Mantids30;

bool AuthStorageImpl::createAuth()
{
    std::string sDriverName = Globals::pConfig.get<std::string>("Auth.Driver", "");

    IdentityManager_DB *identityManager = nullptr;

    if (boost::to_lower_copy(sDriverName) == "sqlite3")
    {
        SQLConnector_SQLite3 *dbConnector = new SQLConnector_SQLite3();

        dbConnector->setThrowCPPErrorOnQueryFailure(Globals::pConfig.get<bool>("Auth.TerminateOnSQLError", false));

        if (!dbConnector->connectInMemory())
        {
            LOG_APP->log0(__func__, Logs::LogLevel::CRITICAL, "Error, Failed to create in-memory SQLite3 database");
            delete dbConnector;
            return false;
        }

        std::function<bool(const std::string &)> createFileIfNotExists = [](const std::string &path) -> bool
        {
            struct stat buffer{};
            if (stat(path.c_str(), &buffer) == 0)
            {
                return true;
            }
            std::ofstream file(path);
            if (!file.is_open())
            {
                LOG_APP->log0(__func__, Logs::LogLevel::CRITICAL, "Failed to create database file: '%s'", path.c_str());
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
            LOG_APP->log0(__func__, Logs::LogLevel::CRITICAL, "Error, Failed to attach IAM SQLite3 database file: '%s'", dbFilePath.c_str());
            delete dbConnector;
            return false;
        }
        else
        {
            LOG_APP->log0(__func__, Logs::LogLevel::INFO, "Opened IAM SQLite3 database file: '%s'", dbFilePath.c_str());
        }

        if (!dbConnector->attach(dbLogsPath, "logs"))
        {
            LOG_APP->log0(__func__, Logs::LogLevel::CRITICAL, "Error, Failed to attach logs SQLite3 database file: '%s'", dbLogsPath.c_str());
            delete dbConnector;
            return false;
        }
        else
        {
            LOG_APP->log0(__func__, Logs::LogLevel::INFO, "Opened logs SQLite3 database file: '%s'", dbLogsPath.c_str());
        }

        identityManager = new IdentityManager_DB(dbConnector);
        Globals::setIdentityManager(identityManager);
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
        LOG_APP->log0(__func__, Logs::LogLevel::CRITICAL, "Error, Authentication driver '%s' not implemented", sDriverName.c_str());
    }

    if (!identityManager)
    {
        return false;
    }

//    std::optional<std::string> accountUUID;

    if (!identityManager->initializeDatabase())
    {
        LOG_APP->log0(__func__, Logs::LogLevel::CRITICAL, "Error (Driver: %s), Unknown error during database scheme initialization.", sDriverName.c_str());
        return false;
    }

    bool r = true;
    bool appExisted, defaultPasswordSchemesExisted;

    std::optional<uint32_t> schemeId = identityManager->authController->initializateDefaultPasswordSchemes(&defaultPasswordSchemesExisted);

    if (defaultPasswordSchemesExisted)
    {
        if (!schemeId.has_value())
        {
            r = false;
            LOG_APP->log0(__func__, Logs::LogLevel::ERR, "Default password scheme for simple login does not exist anymore.");
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
            LOG_APP->log0(__func__, Logs::LogLevel::ERR, "Default password scheme for simple login can't be created.");
        }
        else
        {
            LOG_APP->log0(__func__, Logs::LogLevel::INFO, "Default password scheme for simple login successfully created.");
        }
    }

    if (r)
    {
        if (!identityManager->initializeAdminAccountWithPasswordIfNotExist(*schemeId, Globals::getDoCreateNewAdminAccount()))
        {
            return false;
        }
    }

    // Helper struct to hold configuration for each app
    struct AppConfig
    {
        const char *name;
        const char *description;
        const char *url;
    };

    // Define the list of apps to initialize
    const std::vector<AppConfig> appsToInitialize = {{IAM_ADMPORTAL_APPNAME, IAM_ADMPORTAL_DESCRIPTION, IAM_ADMPORTAL_URL},
                                                     {IAM_USRPORTAL_APPNAME, IAM_USRPORTAL_DESCRIPTION, IAM_USRPORTAL_URL},
                                                     {IAM_LOGINPORTAL_APPNAME, IAM_LOGINPORTAL_DESCRIPTION, IAM_LOGINPORTAL_URL}};

    // Loop through each app configuration
    for (const AppConfig &app : appsToInitialize)
    {
        // Check previous result before proceeding
        if (!r)
        {
            break;
        }

        bool appExisted = false;

        // Attempt to initialize the application
        // Note: identityManager->initializeApplicationWithScheme returns a boolean success status
        // We chain it with 'r' to ensure we stop on the first failure
        r = identityManager->initializeApplicationWithScheme(app.name, app.description, app.url, *schemeId, &appExisted);

        // Log based on the result of this specific call
        if (appExisted)
        {
            // App already exists, this is not an error in this context
            LOG_APP->log0(__func__, Logs::LogLevel::DEBUG, "App '%s' already exists.", app.name);
        }
        else
        {
            if (r)
            {
                LOG_APP->log0(__func__, Logs::LogLevel::INFO, "APP '%s' successfully created.", app.name);
            }
            else
            {
                LOG_APP->log0(__func__, Logs::LogLevel::CRITICAL, "APP '%s' can't be created.", app.name);
                // Return false immediately on failure as per original logic
                return false;
            }
        }
    }

    if (identityManager->applicationActivities->getApplicationActivityDefaultScheme(IAM_LOGINPORTAL_APPNAME, "LOGIN") == std::nullopt)
    {
        identityManager->applicationActivities->createLoginActivity();
        // create activities.
        LOG_APP->log0(__func__, Logs::LogLevel::INFO, "APP '%s' LOGIN ACTIVITY successfully created.", IAM_LOGINPORTAL_APPNAME);
    }

    // If password marked for reset, reset:
/*    if (!.empty())
    {
        LOG_APP->log0(__func__, Logs::LogLevel::WARN, "Password marked to be reseted...");
        std::string sInitPW;
        IdentityManager::ClientDetails clientDetails;
        std::string performedBy = "00000000-0000-4000-8000-000000000000";

        std::optional<std::string> accountUUIDToChangePWD = Globals::getIdentityManager()->accounts->getAccountUUIDByAccountName(Globals::getDoCreateNewAdminAccount());

        if (accountUUIDToChangePWD.has_value())
        {
            if (!schemeId.has_value() || !identityManager->authController->setAccountPasswordOnScheme(clientDetails, performedBy, accountUUIDToChangePWD.value(), &sInitPW, *schemeId))
            {
                LOG_APP->log0(__func__, Logs::LogLevel::ERR, "Password not resetted (Maybe the account '%s' does not have admin privileges?)...", accountUUIDToChangePWD.value().c_str());
                return false;
            }
        }
    }
*/
/*    if (!sInitPW.empty())
    {
        // Create the password file if there is a new password...
        if (!(sInitPW))
        {
            return false;
        }
    }*/

    if (!configureAdminPortalApplication(identityManager))
    {
        return false;
    }

    if (!configureUserPortalApplication(identityManager))
    {
        return false;
    }

    return true;
}


/*
bool AuthStorageImpl::resetAdminPwd(IdentityManager_DB *identityManager, std::string *sInitPW)
{
    *sInitPW = Mantids30::Helpers::Random::createRandomString(16);

    Credential credentialData;
    credentialData.hash = Helpers::Crypto::calcSHA256(*sInitPW);

    credentialData.
    credentialData.passwordFunction = HashFunction::SHA256;
    credentialData.mustChange = true; // Expired (to be changed on the first login).

    return identityManager->authController->changeCredential("admin", credentialData);
}*/



bool AuthStorageImpl::configureAdminPortalApplication(IdentityManager_DB *identityManager)
{
    if (!identityManager->applications->doesApplicationExist(IAM_ADMPORTAL_APPNAME))
    {
        LOG_APP->log0(__func__, Logs::LogLevel::CRITICAL, "Application '%s' does not exist, aborting.", IAM_ADMPORTAL_APPNAME);
        return false;
    }

    AppSync_Endpoints::updateAppScopes(IAM_ADMPORTAL_APPNAME, "127.0.0.1", parseJSON(R"(
        [
            {
                "id": "SELF_PWDCHANGE",
                "description": "Change my own password"
            },
            {
                "id": "SELF_READ",
                "description": "Read my own user data from the IAM system"
            },
            {
                "id": "SELF_DELETE",
                "description": "Delete my own user"
            },
            {
                "id": "ACCOUNT_READ",
                "description": "Read accounts data from the IAM system"
            },
            {
                "id": "ACCOUNT_DELETE",
                "description": "Delete accounts from the IAM system"
            },
            {
                "id": "ACCOUNT_MODIFY",
                "description": "Edit accounts details, roles, and scopes"
            },
            {
                "id": "ACCOUNT_PWDDCHANGE",
                "description": "Change account passwords"
            },
            {
                "id": "ACCOUNT_DISABLE",
                "description": "Disable/lock accounts"
            },
            {
                "id": "ACCOUNT_ENABLE",
                "description": "Enable/unlock accounts"
            },
            {
                "id": "APP_CREATE",
                "description": "Create applications on the IAM"
            },
            {
                "id": "APP_DELETE",
                "description": "Delete application's from the IAM"
            },
            {
                "id": "APP_MODIFY",
                "description": "Modify application data on the IAM"
            },
            {
                "id": "APP_READ",
                "description": "Read application data from the IAM"
            },
            {
                "id": "AUTH_CREATE",
                "description": "Create authentication schemes and slots on the IAM"
            },
            {
                "id": "AUTH_DELETE",
                "description": "Delete authentication schemes and slots on the IAM"
            },
            {
                "id": "AUTH_MODIFY",
                "description": "Modify authentication schemes and slots on the IAM"
            },
            {
                "id": "AUTH_READ",
                "description": "Read authentication schemes and slots on the IAM"
            },
            {
                "id": "CONFIG_READ",
                "description": "Read the configuration of the IAM"
            },
            {
                "id": "CONFIG_WRITE",
                "description": "Write the configuration of the IAM"
            },
            {
                "id": "AUDIT_LOG_VIEW",
                "description": "Access, export and view IAM audit logs"
            },
            {
                "id": "AUDIT_LOG_CLEAN",
                "description": "Clean/remove audit logs"
            }
        ]
    )"));
/*
    Sessions::ClientDetails clientDetails;
    std::string performedBy = "00000000-0000-4000-8000-000000000000";

    if (!identityManager->applications->validateApplicationAccount(IAM_ADMPORTAL_APPNAME, adminUserUUID))
    {
        LOG_APP->log0(__func__, Logs::LogLevel::WARN, "Setting up '%s' user as application '%s' user.", adminUserUUID.c_str(), IAM_ADMPORTAL_APPNAME);

        if (!identityManager->applications->addAccountToApplication(clientDetails, performedBy, IAM_ADMPORTAL_APPNAME, adminUserUUID))
        {
            LOG_APP->log0(__func__, Logs::LogLevel::CRITICAL, "Failed to set the '%s' account as application '%s' user.", adminUserUUID.c_str(), IAM_ADMPORTAL_APPNAME);
            return false;
        }
    }

    if (!identityManager->applications->isApplicationAdmin(IAM_ADMPORTAL_APPNAME, adminUserUUID))
    {
        LOG_APP->log0(__func__, Logs::LogLevel::WARN, "Setting up '%s' user as application '%s' admin.", adminUserUUID.c_str(), IAM_ADMPORTAL_APPNAME);

        if (!identityManager->applications->changeApplicationAdmin(clientDetails, performedBy, IAM_ADMPORTAL_APPNAME, adminUserUUID, true))
        {
            LOG_APP->log0(__func__, Logs::LogLevel::CRITICAL, "Failed to set the '%s' account as application '%s' admin.", adminUserUUID.c_str(), IAM_ADMPORTAL_APPNAME);
            return false;
        }
    }*/

    return true;
}

bool AuthStorageImpl::configureUserPortalApplication(IdentityManager_DB *identityManager)
{
    if (!identityManager->applications->doesApplicationExist(IAM_USRPORTAL_APPNAME))
    {
        LOG_APP->log0(__func__, Logs::LogLevel::CRITICAL, "Application '%s' does not exist, aborting.", IAM_USRPORTAL_APPNAME);
        return false;
    }

    AppSync_Endpoints::updateAppScopes(IAM_USRPORTAL_APPNAME, "127.0.0.1", parseJSON(R"(
    [
      {
        "id": "LOGIN",
        "description": "Access the self-service user portal"
      },
      {
        "id": "CHANGEPWD",
        "description": "Change my account password"
      },
      {
        "id": "SELF_PROFILE_VIEW",
        "description": "View my profile information and attributes"
      },
      {
        "id": "SELF_PROFILE_EDIT",
        "description": "Update my profile information and preferences"
      },
      {
        "id": "SELF_MFA_MANAGE",
        "description": "Manage my multi-factor authenticators"
      },
      {
        "id": "SELF_SESSIONS_VIEW",
        "description": "Review my active sessions, devices, and remembered browsers"
      },
      {
        "id": "SELF_SESSIONS_TERMINATE",
        "description": "Sign out or revoke specific sessions and devices"
      },
      {
        "id": "VIEWLOGS",
        "description": "View my personal audit and activity logs"
      },
      {
        "id": "VIEWIP",
        "description": "Inspect IP addresses recorded for my activity"
      }
    ]
    )"));

    AppSync_Endpoints::updateAppRoles(IAM_USRPORTAL_APPNAME, "127.0.0.1", parseJSON(R"(
    [
      {
        "id": "GENERIC_USER",
        "description": "Standard user with access to all self-mgmt functionality",
        "scopes": [
          "LOGIN",
          "CHANGEPWD",
          "SELF_PROFILE_VIEW",
          "SELF_PROFILE_EDIT",
          "SELF_MFA_MANAGE",
          "SELF_SESSIONS_VIEW",
          "SELF_SESSIONS_TERMINATE",
          "VIEWLOGS",
          "VIEWIP"
        ]
      }
    ]
    )"));

    /*
    Sessions::ClientDetails clientDetails;
    std::string performedBy = "00000000-0000-4000-8000-000000000000";

    if (!identityManager->applications->validateApplicationAccount(IAM_USRPORTAL_APPNAME, adminUserUUID))
    {
        LOG_APP->log0(__func__, Logs::LogLevel::WARN, "Setting up '%s' user as application '%s' user.", adminUserUUID.c_str(), IAM_USRPORTAL_APPNAME);

        if (!identityManager->applications->addAccountToApplication(clientDetails, performedBy, IAM_USRPORTAL_APPNAME, adminUserUUID))
        {
            LOG_APP->log0(__func__, Logs::LogLevel::CRITICAL, "Failed to set the '%s' account as application '%s' user.", adminUserUUID.c_str(), IAM_USRPORTAL_APPNAME);
            return false;
        }
    }

    std::set<std::string> accounts = identityManager->applicationRoles->getApplicationRoleAccounts(IAM_USRPORTAL_APPNAME, "GENERIC_USER");
    if (accounts.find(adminUserUUID) == accounts.end())
    {
        LOG_APP->log0(__func__, Logs::LogLevel::WARN, "Setting up '%s' user with role 'GENERIC_USER' in application '%s'.", adminUserUUID.c_str(), IAM_USRPORTAL_APPNAME);

        if (!identityManager->applicationRoles->addAccountToRole(clientDetails, performedBy, IAM_USRPORTAL_APPNAME, "GENERIC_USER", adminUserUUID))
        {
            LOG_APP->log0(__func__, Logs::LogLevel::CRITICAL, "Failed to set up '%s' user with role 'GENERIC_USER' in application '%s'.", adminUserUUID.c_str(), IAM_USRPORTAL_APPNAME);
            return false;
        }
    }*/

    return true;
}
