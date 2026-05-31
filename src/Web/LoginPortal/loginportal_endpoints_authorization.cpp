#include "IdentityManager/ds_authentication.h"
#include "Mantids30/Program_Logs/loglevels.h"
#include "Mantids30/Protocol_HTTP/api_return.h"
#include "loginportal_endpoints.h"
#include "json/value.h"
#include <Mantids30/Helpers/json.h>

#include "globals.h"

#include <cstdint>
#include <inttypes.h>
#include <json/config.h>
#include <memory>
#include <optional>
#include <string>

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols;
using namespace Mantids30::DataFormat;

// Validate user and get authorization flow:
API::APIReturn LoginPortal_Endpoints::preAuthorize(void *context, const API::RESTful::RequestParameters &request, ClientDetails &authClientDetails)
{
    json r;
    API::APIReturn response;
    // Environment:
    IdentityManager *identityManager = Globals::getIdentityManager();
    std::shared_ptr<TransientAuthenticationContext> authContext = std::make_shared<TransientAuthenticationContext>();

    //  Configuration parameters:
    auto config = Globals::pConfig;
    uint32_t loginAuthenticationTimeout = config.get<uint32_t>("LoginPortal.AuthenticationTimeout", 300);

    // Input parameters:
    authContext->accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");    // ACCOUNT ID.
    std::string appName = JSON_ASSTRING(*request.inputJSON, "app", "");                // APPNAME.
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activity", "");           // APP ACTIVITY NAME.

    if (!identityManager->applications->doesApplicationExist(appName))
    {
        response.setError(HTTP::Status::S_404_NOT_FOUND, "not_found", "Invalid Application");
        return response;
    }

    if (!authContext->validateAndMerge_AccessTokenIfExist(request.clientRequest->getCookie("AccessToken"), response, request.jwtValidator))
    {
        // Invalid Access Token. (Relogin)
        return response;
    }

    if ( activityName == "LOGIN" )
        r = identityManager->authController->getApplicableAuthenticationSchemesForAccount(IAM_LOGINPORTAL_APPNAME, activityName, authContext->accountName, authContext->authenticatedSlots);
    else // Activity from the application.
        r = identityManager->authController->getApplicableAuthenticationSchemesForAccount(appName, activityName, authContext->accountName, authContext->authenticatedSlots);

    if (r["defaultScheme"] == Json::nullValue)
    {
        // Member not found.
        response.setError(HTTP::Status::S_404_NOT_FOUND, "not_found", "There is no Authentication Scheme Available.");
        return response;
    }

    r["loginAuthenticationTimeout"] = loginAuthenticationTimeout;
    return r;
}

// Validate credential:
API::APIReturn LoginPortal_Endpoints::authorize(void *context, const RequestParameters &request, ClientDetails &clientDetails)
{
    API::APIReturn response;

    // Get the identity manager from global settings to handle authentication.
    IdentityManager *identityManager = Globals::getIdentityManager();
    std::shared_ptr<TransientAuthenticationContext> authContext = std::make_shared<TransientAuthenticationContext>();

    // Decode the bearer transient token... (and get the Account Name)
    // If the token does not exist, it will get the data from the USER INPUT JSON
    if (!authContext->validateAndMerge_TransientAuthTokenIfExist(request.clientRequest->getAuthorizationBearer(), request.inputJSON, request.jwtValidator))
    {
        response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                          authResultToString(AuthenticationResult::UNAUTHENTICATED));
        return response;
    }

    if (authContext->currentSlotId == std::nullopt)
    {
        // You don´t need to authorize anything else! it's already authenticated.
        // code warning: this nullopt check prevent usage of .value() after.
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::AUTHENTICATION_FAILED)),
                          authResultToString(AuthenticationResult::AUTHENTICATION_FAILED));
        return response;
    }

    AuthenticationResult authRetCode = identityManager->authController->authenticateCredential(clientDetails, authContext->accountName, JSON_ASSTRING(*request.inputJSON, "password", ""),
                                                                                               authContext->currentSlotId.value(),
                                                                                               getAuthModeFromString(JSON_ASSTRING(*request.inputJSON, "authMode", "MODE_PLAIN")),
                                                                                               JSON_ASSTRING(*request.inputJSON, "challengeSalt", ""), authContext);

    LOG_APP->log2(__func__, authContext->accountName, clientDetails.ipAddress, authRetCode != AuthenticationResult::AUTHENTICATED ? Logs::LEVEL_SECURITY_ALERT : Logs::LEVEL_INFO,
                  "Account Authorization Result: %" PRIu32 " - %s, scheme '%" PRIu32 "' and slotId = %'" PRIu32 "'", authRetCode, authResultToString(authRetCode),
                  authContext->schemeId, authContext->currentSlotId.value());

    if (IS_CREDENTIAL_AUTHENTICATED(authRetCode))
    {
        std::vector<AuthenticationSchemeUsedSlot> requiredAuthSlots;

        if (!authContext->validateAndMerge_AccessTokenIfExist(request.clientRequest->getCookie("AccessToken"), response, request.jwtValidator))
        {
            // Invalid Access Token. (Relogin)
            return response;
        }

        requiredAuthSlots = calculateRequiredAuthSlotsLeftForTheNewTransientAuthToken(authContext, &response);

        if (requiredAuthSlots.empty())
        {
            // Why...? at least should exist 1 left.
            response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::INTERNAL_ERROR)),
                               authResultToString(AuthenticationResult::INTERNAL_ERROR));
            return response;
        }

        // The current slot should be the first to avoid order change (eg. trying to try the OTP before the pass)...
        if (requiredAuthSlots.begin()->slotId != authContext->currentSlotId.value())
        {
            response.setError(HTTP::Status::S_400_BAD_REQUEST, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::BAD_PARAMETERS)),
                               authResultToString(AuthenticationResult::BAD_PARAMETERS));
            return response;
        }

        // Remove the first element from requiredAuthSlots (which is the authenticated credential)
        requiredAuthSlots.erase(requiredAuthSlots.begin());

        issueTransientAuthTokenResponse(request, response, authContext, requiredAuthSlots, authRetCode == AuthenticationResult::MUST_CHANGE_CREDENTIAL);
    }
    else
    {
        // Use the same auth... don't go to the next.
        (*response.responseJSON())["nextSlot"] = authContext->currentSlotId.value();

        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(authRetCode)), authResultToString(authRetCode));
    }

    LOG_APP->log2(__func__, authContext->accountName, clientDetails.ipAddress, response.getHTTPResponseCode() != HTTP::Status::S_200_OK ? Logs::LEVEL_SECURITY_ALERT : Logs::LEVEL_INFO, "R/%03" PRIu16 ": %s",
                  static_cast<uint16_t>(response.getHTTPResponseCode()), request.clientRequest->getURI().c_str());

    return response;
}
