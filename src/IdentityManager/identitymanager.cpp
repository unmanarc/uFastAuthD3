#include "identitymanager.h"
#include "IdentityManager/ds_account.h"
#include "IdentityManager/ds_application.h"
#include "globals.h"
#include <memory>
#include <optional>
#include <string>
#include <sys/stat.h>

#ifdef WIN32
#include <windows.h>
#endif

using namespace Mantids30;
using namespace Mantids30::DataFormat;
using namespace Mantids30::Program::Logs;

IdentityManager::~IdentityManager()
{
    delete accounts;
    delete applicationRoles;
    delete applications;
    delete authController;
    delete applicationActivities;
}

bool IdentityManager::isAccountActiveAndValidForApp(const std::string &accountUUID, const std::string &appName, AuthenticationResult &reason, bool checkValidAppAccount) const
{
    // First, check if the account is disabled, unconfirmed, or expired.
    AccountFlags accountFlags = accounts->getAccountFlags(accountUUID);

    if (!accountFlags.enabled)
    {
        reason = AuthenticationResult::DISABLED_ACCOUNT;
        return false;
    }
    else if (!accountFlags.confirmed)
    {
        reason = AuthenticationResult::UNCONFIRMED_ACCOUNT;
        return false;
    }
    else if (accounts->isAccountExpired(accountUUID))
    {
        reason = AuthenticationResult::EXPIRED_ACCOUNT;
        return false;
    }

    // If checkValidAppAccount is true, check if the account is valid for the specified application.
    if (checkValidAppAccount && !applications->validateApplicationAccount(appName, accountUUID))
    {
        reason = AuthenticationResult::ACCOUNT_NOT_IN_APP;
        return false;
    }

    // If all checks pass, the account is valid for refreshing the token.
    return true;
}

bool createPassFile(const std::string &sInitPW)
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
        LOG_APP->log0(__func__, LogLevel::CRITICAL, "Failed to save the password account.");
        return false;
    }
#ifndef WIN32
    if (chmod(initPassOutFile.c_str(), 0600) != 0)
    {
        LOG_APP->log0(__func__, LogLevel::WARN, "Failed to chmod the password file (be careful with this file and content).");
    }
#else
    LOG_APP->log0(__func__, LogLevel::WARN, "Initial password was saved without special owner read-only privileges (be careful).");
#endif
    ofstr << sInitPW;
    ofstr.close();
    LOG_APP->log0(__func__, LogLevel::INFO, "File '%s' created with the super-user password. Login and change it immediately", initPassOutFile.c_str());
    return true;
}

bool IdentityManager::initializeAdminAccountWithPasswordIfNotExist(const uint32_t &schemeId, bool forceIfExist) const
{
    ClientDetails clientDetails;
    std::string performedByUUID = "00000000-0000-4000-8000-000000000000"; // nobody (initialization)
    std::string accountUUID;
    std::string adminPW;

    if (!forceIfExist && accounts->hasValidAdminAccount())
    {
        // Already exist.
        LOG_APP->log0(__func__, LogLevel::DEBUG, "Admin account already exists. Not creating a new one");
        return true;
    }

    std::optional<std::string> _accountUUID = accounts->createAdminAccount();

    if (_accountUUID.has_value())
    {
        LOG_APP->log0(__func__, LogLevel::CRITICAL, "Error creating admin account (DB).");
        return false;
    }

    if (!authController->setAccountPasswordOnScheme(clientDetails, performedByUUID, accountUUID, &adminPW, schemeId))
    {
        LOG_APP->log0(__func__, LogLevel::CRITICAL, "Error creating admin account (SCHEME).");
        return false;
    }

    // si no hay username... crear campo username.

    std::map<std::string, AccountDetailField> detailFields = accounts->listAccountDetailFields();
    if (!detailFields.count("USERNAME"))
    {
        AccountDetailField field;
        field.description = "Login Username";
        field.fieldType = "TEXTLINE";
        field.isLoginIdentifier = true;
        field.isOptionalField = false;
        field.isUnique = true;
        field.extendedAttributes["security"]["canUserEdit"] = true;
        field.extendedAttributes["security"]["canUserView"] = true;
        field.extendedAttributes["behavior"]["regexpValidator"] = "^[a-zA-Z0-9_]+$";
        if (!accounts->createAccountDetailField(clientDetails, performedByUUID, "USERNAME", field))
        {
            LOG_APP->log0(__func__, LogLevel::CRITICAL, "Error creating admin account (CREATE_USERNAME_DETAIL_FIELD).");
            return false;
        }
    }


    const std::string adminBaseName = "admin";
    int i=0;

    for (size_t i=0;i<100;i++)
    {
        std::string adminUsername = adminBaseName;
        if (i!=0)
        {
            adminUsername+=std::to_string(i);
        }

        AccountDetailFieldValue fieldValue;
        fieldValue.name = "USERNAME";
        fieldValue.value = adminUsername;
        accounts->updateAccountDetailFieldValues(clientDetails,performedByUUID, accountUUID, { fieldValue }, true);
    }

    LOG_APP->log0(__func__, LogLevel::INFO, "New admin account '%s' successfully created.", accountUUID.c_str());

    createPassFile(adminPW);
    return true;
}

bool IdentityManager::initializeApplicationWithScheme(const std::string &appName, const std::string &appDescription, const std::string &appURL, const uint32_t &schemeId, bool *alreadyExist) const
{
    bool r = true;
    ClientDetails clientDetails;
    std::string performedByUUID = "00000000-0000-4000-8000-000000000000"; // nobody (initialization)

    if (!applications->doesApplicationExist(appName))
    {
        r = r
            && applications->createApplication(clientDetails, performedByUUID, appName, appDescription, appURL, Mantids30::Helpers::Random::createRandomString(32), performedByUUID,
                                               Applications::ApplicationAttributes(), true);
        *alreadyExist = false;
    }
    else
    {
        *alreadyExist = true;
    }

    return r;
}

std::optional<std::string> IdentityManager::Accounts::createAdminAccount()
{
    AccountFlags accountFlags;
    accountFlags.confirmed = true;
    accountFlags.enabled = true;
    accountFlags.admin = true;
    accountFlags.blocked = false;

    return createAccount(0, accountFlags);
}

std::shared_ptr<JWT> IdentityManager::Applications::getAppJWTValidator(const std::string &appName)
{
    // Obtain data from the DB:
    ApplicationTokenProperties tokenProperties = getWebLoginJWTConfigFromApplication(appName);
    std::string validationKey = getWebLoginJWTValidationKeyForApplication(appName);

    if (tokenProperties.appName != appName)
    {
        // Failed to load token properties.
        return nullptr;
    }

    if (validationKey.empty())
    {
        // Failed to load validation Key.
        return nullptr;
    }

    // Validate the JWT Algorithm....
    if (!JWT::isAlgorithmSupported(tokenProperties.signAlgorithm))
    {
        // Failed to validate the algorithm type.
        return nullptr;
    }

    // Setup the JWT validator:
    JWT::AlgorithmDetails algorithmDetails = JWT::AlgorithmDetails(tokenProperties.signAlgorithm.c_str());
    std::shared_ptr<JWT> jwtValidator = std::make_shared<JWT>(algorithmDetails.algorithm);

    if (algorithmDetails.isUsingHMAC)
    {
        jwtValidator->setSharedSecret(validationKey);
    }
    else
    {
        jwtValidator->setPublicSecret(validationKey);
    }

    return jwtValidator;
}

std::shared_ptr<JWT> IdentityManager::Applications::getAppJWTSigner(const std::string &appName)
{
    // Obtain data from the DB:
    ApplicationTokenProperties tokenProperties = getWebLoginJWTConfigFromApplication(appName);
    std::string validationKey = getWebLoginJWTValidationKeyForApplication(appName);
    std::string signingKey = getWebLoginJWTSigningKeyForApplication(appName);

    if (tokenProperties.appName == appName && !validationKey.empty() && !signingKey.empty())
    {
        // Validate the JWT....
        JWT::AlgorithmDetails algorithmDetails = JWT::AlgorithmDetails(tokenProperties.signAlgorithm.c_str());
        std::shared_ptr<JWT> jwtSigner = std::make_shared<JWT>(algorithmDetails.algorithm);

        if (algorithmDetails.isUsingHMAC)
        {
            jwtSigner->setSharedSecret(signingKey);
        }
        else
        {
            jwtSigner->setPrivateSecret(signingKey);
            jwtSigner->setPublicSecret(validationKey);
        }

        return jwtSigner;
    }

    return nullptr;
}

IdentityManager::AuthController::AuthController(IdentityManager *parent)
{
    m_authLogGC.setGarbageCollectorInterval(60000); // Check every 60 seconds
    m_authLogGC.startGarbageCollector(markExpiredAuthLogSessions, this, "GC:AuthLogSessions");
    m_parent = parent;
}
