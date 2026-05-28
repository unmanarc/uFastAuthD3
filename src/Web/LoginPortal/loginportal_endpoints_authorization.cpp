#include "IdentityManager/ds_authentication.h"
#include "Mantids30/Program_Logs/loglevels.h"
#include "Mantids30/Protocol_HTTP/api_return.h"
#include "Tokens/tokensmanager.h"
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

bool LoginPortal_Endpoints::decodeAndValidateAccessTokenIfExist(const RequestParameters &request, LoginPortal_Endpoints::APIReturn &response, JWT::Token *token, const std::string &currentAccountName,std::shared_ptr<TransientAuthenticationContext> authContext)
{
    std::string cookieAccessTokenStr = request.clientRequest->getCookie("AccessToken");

    if (!cookieAccessTokenStr.empty())
    {
        if (!request.jwtValidator->verify(cookieAccessTokenStr, token))
        {
            // Failed to load the intermediary...
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                              authResultToString(AuthenticationResult::UNAUTHENTICATED));
            return false;
        }
        if (token->getClaim("app") != IAM_LOGINPORTAL_APPNAME || token->getClaim("type") != "access")
        {
            // This Token is not for this cookie...
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                              authResultToString(AuthenticationResult::UNAUTHENTICATED));
            return false;
        }
        if (token->getSubject() != currentAccountName)
        {
            // This Token is not for this cookie... (other username... logout first please!)
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                              authResultToString(AuthenticationResult::UNAUTHENTICATED));
            return false;
        }

        // We have an access token!
        std::set<uint32_t> authenticatedSlotsOnAccessToken = Mantids30::Helpers::jsonToUInt32Set( token->getClaim("slotIds") );
        // Merge.
        for (const auto & i  : authenticatedSlotsOnAccessToken)
        {
            authContext->authenticatedSlots.insert(i);
        }
    }

    return true;
}


void LoginPortal_Endpoints::setupNewTransientAuthToken(const RequestParameters &request, Mantids30::API::APIReturn &response, IdentityManager *identityManager, std::shared_ptr<TransientAuthenticationContext> authContext,
                                   const std::vector<AuthenticationSchemeUsedSlot> &requiredAuthSlots, const time_t &oldTransientTokenExpirationTime, const std::string &accountName,
                                   bool mustChange)
{
    // Retrieve configuration parameters from global settings.
    auto config = Globals::pConfig;
    uint32_t loginAuthenticationTimeout = config.get<uint32_t>("LoginPortal.AuthenticationTimeout", 300);
    JWT::Token newTransientAuthToken;

    if (authContext->firstAuth)
    {
        newTransientAuthToken.setJwtId(Mantids30::Helpers::Random::createRandomString(16));
        newTransientAuthToken.setExpirationTime(time(nullptr) + loginAuthenticationTimeout);
    }
    else
    {
        newTransientAuthToken.setExpirationTime(oldTransientTokenExpirationTime);
    }

    newTransientAuthToken.setIssuedAt(time(nullptr));
    newTransientAuthToken.setNotBefore(time(nullptr) - 30);
    newTransientAuthToken.addClaim("app", authContext->appName);
    newTransientAuthToken.addClaim("preAuthUser", accountName);
    newTransientAuthToken.addClaim("slotSchemeHash", authContext->slotSchemeHash);
    newTransientAuthToken.addClaim("schemeId", authContext->schemeId);
    newTransientAuthToken.addClaim("keepAuthenticated", authContext->keepAuthenticated);
    newTransientAuthToken.addClaim("type", "transient");

    std::set<uint32_t> authSlots = authContext->authenticatedSlots;
    if (authContext->currentSlotId.has_value())
        authSlots.insert(authContext->currentSlotId.value());
    newTransientAuthToken.addClaim("authenticatedSlots", Mantids30::Helpers::setToJSON(authSlots));

    std::set<uint32_t> currentMustChangeSlots = authContext->mustChangeSlots;
    if (mustChange)
        currentMustChangeSlots.insert(authContext->currentSlotId.value());
    else
        currentMustChangeSlots.erase(authContext->currentSlotId.value());

    newTransientAuthToken.addClaim("mustChangeSlots", Mantids30::Helpers::setToJSON(currentMustChangeSlots));

    (*response.responseJSON())["changeCredential"] = mustChange;

    if (requiredAuthSlots.empty())
    {
        if (currentMustChangeSlots.empty())
        {
            // Set the IAM Access Token into the Cookie ONLY if mustchangeslots is empty...
            TokensManager::setIAMAccessTokenCookie(response, request, newTransientAuthToken,
                                                   authContext->keepAuthenticated,              // Keep authenticated will use the current authentication proccess
                                                   newTransientAuthToken.getExpirationTime() // Get current JWT expiration time (if keep autneticated is false)
                                                   );
        }

        // DONE!
        (*response.responseJSON())["nextSlot"] = Json::nullValue;
        (*response.responseJSON())["transientToken"] = request.jwtSigner->signFromToken(newTransientAuthToken, false);
    }
    else
    {
        auto nextSlotId = requiredAuthSlots.begin()->slotId;
        newTransientAuthToken.addClaim("currentSlotId", nextSlotId); // Enforce this with authentication.

        // We can give the credential public data for the next credential:
        Credential credentialPublicData = identityManager->authController->getAccountCredentialPublicData(accountName, nextSlotId);

        json nextSlot;
        nextSlot["slotId"] = nextSlotId;
        nextSlot["details"] = credentialPublicData.slotDetails.toJSON();
        (*response.responseJSON())["nextSlot"] = nextSlot;
        (*response.responseJSON())["publicData"] = credentialPublicData.toJSON(identityManager->authController->getAuthenticationPolicy());
        (*response.responseJSON())["publicData"].removeMember("slotDetails");
        (*response.responseJSON())["transientToken"] = request.jwtSigner->signFromToken(newTransientAuthToken, false);
    }
}

// Validate user and get authorization flow:
API::APIReturn LoginPortal_Endpoints::preAuthorize(void *context, const API::RESTful::RequestParameters &request, ClientDetails &authClientDetails)
{
    json r;
    API::APIReturn response;
    // Environment:
    JWT::Token authenticatedAccessToken;
    IdentityManager *identityManager = Globals::getIdentityManager();
    std::shared_ptr<TransientAuthenticationContext> authContext = std::make_shared<TransientAuthenticationContext>();

    //  Configuration parameters:
    auto config = Globals::pConfig;
    uint32_t loginAuthenticationTimeout = config.get<uint32_t>("LoginPortal.AuthenticationTimeout", 300);

    // Input parameters:
    std::string appName = JSON_ASSTRING(*request.inputJSON, "app", "");                      // APPNAME.
    std::string inputAccountName = JSON_ASSTRING(*request.inputJSON, "accountName", ""); // ACCOUNT ID.
    std::string activity = JSON_ASSTRING(*request.inputJSON, "activity", "");            // APP ACTIVITY NAME.

    if (!identityManager->applications->doesApplicationExist(appName))
    {
        response.setError(HTTP::Status::S_404_NOT_FOUND, "not_found", "Invalid Application");
        return response;
    }

    if (!decodeAndValidateAccessTokenIfExist(request, response, &authenticatedAccessToken, inputAccountName, authContext))
    {
        // Should logout first.
        return response;
    }

    r = identityManager->authController->getApplicableAuthenticationSchemesForAccount(appName, activity, inputAccountName, authContext->authenticatedSlots);

    if (r["defaultScheme"] == Json::nullValue)
    {
        // Member not found.
        response.setError(HTTP::Status::S_404_NOT_FOUND, "not_found", "There is no Authentication Scheme Available For This User/Application.");
        return response;
    }

    r["loginAuthenticationTimeout"] = loginAuthenticationTimeout;
    return r;
}


bool LoginPortal_Endpoints::calculateRequiredAuthSlotsLeftForTheNewTransientAuthToken(std::shared_ptr<TransientAuthenticationContext> authContext,
                                                                                           std::string accountName,
                                                                                            API::APIReturn *response,
                                                                                            std::vector<AuthenticationSchemeUsedSlot> *requiredAuthSlotsOnScheme,
                                                                                            const JWT::Token & accessToken
                                                                                            )
{
    // Get the identity manager from global settings to handle authentication.
    IdentityManager *identityManager = Globals::getIdentityManager();

    *requiredAuthSlotsOnScheme = identityManager->authController->listAuthenticationSlotsUsedByScheme(authContext->schemeId);
    std::set<uint32_t> usedAuthSlotsOnAccount = identityManager->authController->listUsedAuthenticationSlotsOnAccount(accountName);

    // Remove unused requiredAuthSlots if they are optional (eg. requiredAuthSlots[0].optional) and don't exist in usedAuthSlotsOnAccount
    std::vector<AuthenticationSchemeUsedSlot> filteredAuthSlots;
    for (const auto &slot : *requiredAuthSlotsOnScheme)
    {
        // Skip slots that are optional and not used by the account
        if (!slot.optional || usedAuthSlotsOnAccount.find(slot.slotId) != usedAuthSlotsOnAccount.end())
        {
            // Skip slots that are already authenticated (present in authContext->authSlots)
            if (authContext->authenticatedSlots.find(slot.slotId) == authContext->authenticatedSlots.end())
            {
                filteredAuthSlots.push_back(slot);
            }
        }
    }

    *requiredAuthSlotsOnScheme = filteredAuthSlots;


    return true;
}

// Validate credential:
API::APIReturn LoginPortal_Endpoints::authorize(void *context, const RequestParameters &request, ClientDetails &clientDetails)
{
    API::APIReturn response;

    // Get the identity manager from global settings to handle authentication.
    IdentityManager *identityManager = Globals::getIdentityManager();
    // Vector to store the authentication slots used by a particular scheme.

    std::shared_ptr<TransientAuthenticationContext> authContext = std::make_shared<TransientAuthenticationContext>();
    JWT::Token oldTransientAuthToken;
    std::string accountName;

    // Decode the bearer transient token... (and get the Account Name)
    // If the token does not exist, it will get the data from the USER INPUT JSON
    if (!authContext->validateAndDecodeBearerAccessTokenProperties(request.clientRequest->getAuthorizationBearer(), request.inputJSON, &oldTransientAuthToken, request.jwtValidator, &accountName))
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



    AuthenticationResult authRetCode = identityManager->authController->authenticateCredential(clientDetails, accountName, JSON_ASSTRING(*request.inputJSON, "password", ""),
                                                                                               authContext->currentSlotId.value(),
                                                                                               getAuthModeFromString(JSON_ASSTRING(*request.inputJSON, "authMode", "MODE_PLAIN")),
                                                                                               JSON_ASSTRING(*request.inputJSON, "challengeSalt", ""), authContext);

    LOG_APP->log2(__func__, accountName, clientDetails.ipAddress, authRetCode != AuthenticationResult::AUTHENTICATED ? Logs::LEVEL_SECURITY_ALERT : Logs::LEVEL_INFO,
                  "Account Authorization Result: %" PRIu32 " - %s, for application '%s', scheme '%" PRIu32 "' and slotId = %'" PRIu32 "'", authRetCode, authResultToString(authRetCode),
                  authContext->appName.c_str(), authContext->schemeId, authContext->currentSlotId.value());

    if (IS_CREDENTIAL_AUTHENTICATED(authRetCode))
    {
        std::vector<AuthenticationSchemeUsedSlot> requiredAuthSlots;
        JWT::Token accessToken;
        if (!decodeAndValidateAccessTokenIfExist(request,response,&accessToken, accountName,authContext))
        {
            // Invalid Access Token. (Relogin)
            return response;
        }
        if (!calculateRequiredAuthSlotsLeftForTheNewTransientAuthToken(authContext, accountName, &response, &requiredAuthSlots, accessToken))
        {
            return response;
        }

        if (requiredAuthSlots.empty())
        {
            // Why...? at least should exist 1 left.
            response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::INTERNAL_ERROR)),
                               authResultToString(AuthenticationResult::INTERNAL_ERROR));
            return response;
        }

        // The current slot should be the first to avoid order change...
        if (requiredAuthSlots.begin()->slotId != authContext->currentSlotId.value())
        {
            response.setError(HTTP::Status::S_400_BAD_REQUEST, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::BAD_PARAMETERS)),
                               authResultToString(AuthenticationResult::BAD_PARAMETERS));
            return response;
        }

        // Remove the first element from requiredAuthSlots (which is the authenticated credential)
        requiredAuthSlots.erase(requiredAuthSlots.begin());

        setupNewTransientAuthToken(request, response, identityManager, authContext, requiredAuthSlots, oldTransientAuthToken.getExpirationTime(), accountName,
                                      authRetCode == AuthenticationResult::MUST_CHANGE_CREDENTIAL);
    }
    else
    {
        if (authRetCode == AuthenticationResult::ACCOUNT_NOT_IN_APP)
        {
            // Prevent user/app enumeration:
            authRetCode = AuthenticationResult::AUTHENTICATION_FAILED;
        }

        // Use the same auth... don't go to the next.
        (*response.responseJSON())["nextSlot"] = authContext->currentSlotId.value();

        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(authRetCode)), authResultToString(authRetCode));
    }

    LOG_APP->log2(__func__, accountName, clientDetails.ipAddress, response.getHTTPResponseCode() != HTTP::Status::S_200_OK ? Logs::LEVEL_SECURITY_ALERT : Logs::LEVEL_INFO, "R/%03" PRIu16 ": %s",
                  static_cast<uint16_t>(response.getHTTPResponseCode()), request.clientRequest->getURI().c_str());

    return response;
}
