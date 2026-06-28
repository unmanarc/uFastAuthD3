#include "loginportal_endpoints.h"

#include "globals.h"
#include <optional>

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocol;

/*
 * TODO:
 *
    mmmm , the registration should be at the application or at the IAM? in this case, seems to be at the IAM, and then, the app should be linked to the account.
    and...    captchas or something? how do we do?

    When self-registering, you must come with the sponsored app right? and immediately link the app with the user I think...
    anything else?

    ANSWER: it should be at the IAM and the user portal itself, then, when you log into your user portal, you will be able to self-register into some specific app.
*/

API::APIReturn LoginPortal_Endpoints::registerAccount(void *context, const RequestContext &request, ClientDetails &clientDetails)
{
    API::APIReturn response;
    /*
    IdentityManager *identityManager = Globals::getIdentityManager();

    auto config = Globals::pConfig;
    bool bAllowSelfRegistration = config.get<bool>("LoginPortal.Registration.AllowSelfRegistration", false);
    bool bAutoConfirmAccount = config.get<bool>("LoginPortal.Registration.AutoConfirm", false);

    AccountFlags accountFlags;
    accountFlags.confirmed = bAutoConfirmAccount;
    accountFlags.enabled = false;
    accountFlags.admin = false;
    accountFlags.blocked = false;

    // TODO: what application? by now is a non-application enabled account
    // maybe "a button to request access to the application?"

    bool success = false;
    bool create = false;

    if (bAllowSelfRegistration)
    {
        create = true;
    }
    else
    {
        // TODO: in the future, the app admin can create users for the app?
        // Only admins can create.
        if (request.jwtToken->isAdmin())
        {
            create = true;
        }
        else
        {
            return {HTTP::Status::Code::S_401_UNAUTHORIZED, "unauthorized", "Insufficient permissions"};
        }
    }

    std::string accountToCreate = Helpers::JSON::ASSTRING((*request.inputJSON)["accountDetails"], "accountUUID", "");

    if (create)
    {
        success = identityManager->accounts->addAccount(accountToCreate, Helpers::JSON::ASUINT64(*request.inputJSON, "expiration", 0), accountFlags, request.jwtToken->getSubject());
    }

    if (!success)
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to create the account"};
    }

    LOG_APP->log2(__func__, request.jwtToken->getSubject(), clientDetails.ipAddress, success ? Logs::LogLevel::SECURITY_ALERT : Logs::LogLevel::INFO,
                  !success ? "Failed to create account '%s'" : "Account '%s' created.", accountToCreate.c_str());

    // Set the credential:
    std::string newPass = Helpers::JSON::ASSTRING(*request.inputJSON, "newPass", "");

    // TODO: mejorar el nivel de log...

    if (!newPass.empty() && success)
    {
        bool r = false;
        std::optional<uint32_t> applicationRoleDefaultSSOLogin = identityManager->applicationActivities->getApplicationActivityDefaultScheme(IAM_USRPORTAL_APPNAME, "LOGIN");

        // Not any scheme to the default
        if (applicationRoleDefaultSSOLogin.has_value())
        {
            auto authSlots = identityManager->authController->listAuthenticationSlotsUsedByScheme(*applicationRoleDefaultSSOLogin);
            if (!authSlots.empty())
            {
                // not a password...
                if (authSlots.begin()->details.isTextPasswordFunction())
                {
                    auto credentialData = identityManager->authController->createNewCredential(authSlots.begin()->slotId, newPass, true);
                    r = identityManager->authController->changeAccountCredential(accountToCreate, credentialData, authSlots.begin()->slotId);
                }
            }
        }

        LOG_APP->log2(__func__, request.jwtToken->getSubject(), clientDetails.ipAddress, r ? Logs::LogLevel::SECURITY_ALERT : Logs::LogLevel::INFO,
                      !r ? "Failed to change initial password on account '%s'" : "Initial password for account '%s' changed.", accountToCreate.c_str());
    }
    */
    return response;
}

// TODO: llenar los details del user.

/*AccountCreationDetails getAccountDetails;
        getAccountDetails.description = Helpers::JSON::ASSTRING((*request.inputJSON)["getAccountDetails"], "description", "");
        getAccountDetails.email = Helpers::JSON::ASSTRING((*request.inputJSON)["getAccountDetails"], "email", "");
        getAccountDetails.extraData = Helpers::JSON::ASSTRING((*request.inputJSON)["getAccountDetails"], "extraData", "");
        getAccountDetails.givenName = Helpers::JSON::ASSTRING((*request.inputJSON)["getAccountDetails"], "givenName", "");
        getAccountDetails.lastName = Helpers::JSON::ASSTRING((*request.inputJSON)["getAccountDetails"], "lastName", "");*/
