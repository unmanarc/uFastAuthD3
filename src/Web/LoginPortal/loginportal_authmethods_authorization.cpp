#include "IdentityManager/ds_authentication.h"
#include "Mantids30/Program_Logs/loglevels.h"
#include "Mantids30/Protocol_HTTP/api_return.h"
#include "Tokens/tokensmanager.h"
#include "loginportal_add_endpoints.h"
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
API::APIReturn LoginPortal_AuthMethods::preAuthorize(void *context, const API::RESTful::RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    // Environment:
    JWT::Token token;
    IdentityManager *identityManager = Globals::getIdentityManager();

    //  Configuration parameters:
    auto config = Globals::pConfig;
    uint32_t loginAuthenticationTimeout = config.get<uint32_t>("LoginPortal.AuthenticationTimeout", 300);

    // Input parameters:
    std::string app = JSON_ASSTRING(*request.inputJSON, "app", "");                 // APPNAME.
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", ""); // ACCOUNT ID.
    std::string activity = JSON_ASSTRING(*request.inputJSON, "activity", "");       // APP ACTIVITY NAME.

    if (!identityManager->applications->doesApplicationExist(app))
    {
        response.setError(HTTP::Status::S_404_NOT_FOUND, "not_found", "Invalid Application");
        return response;
    }

    (*response.responseJSON()) = identityManager->authController->getApplicableAuthenticationSchemesForAccount(app, activity, accountName);
    (*response.responseJSON())["loginAuthenticationTimeout"] = loginAuthenticationTimeout;
    return response;
}

bool validateIAMAccessTokenCookieProperties(const RequestParameters &request, LoginPortal_AuthMethods::APIReturn &response, JWT::Token *token, const std::string &accountName,
                                            const std::string &appName)
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
        if (token->getSubject() != accountName)
        {
            // This Token is not for this cookie... (other username... logout first please!)
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                              authResultToString(AuthenticationResult::UNAUTHENTICATED));
            return false;
        }

        if (token->getClaim("apps").isMember(appName))
        {
            // Already authenticated within this APP...
            response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::INTERNAL_ERROR)),
                              authResultToString(AuthenticationResult::INTERNAL_ERROR));
            return false;
        }
    }
    return true;
}

bool validateAndDecodeBearerAccessTokenProperties(const RequestParameters &request, LoginPortal_AuthMethods::APIReturn &response, JWT::Token *oldIntermediateAuthToken, std::string *accountName,
                                                  std::shared_ptr<AppAuthExtras> authContext)
{
    std::string oldIntermediateAuthTokenStr = request.clientRequest->getAuthorizationBearer();

    // Validate the token
    if (!oldIntermediateAuthTokenStr.empty() && oldIntermediateAuthTokenStr != "null")
    {
        if (!request.jwtValidator->verify(oldIntermediateAuthTokenStr, oldIntermediateAuthToken))
        {
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                              authResultToString(AuthenticationResult::UNAUTHENTICATED));
            return false;
        }
    }

    // Extract JWT Signed Parameters:
    *accountName = JSON_ASSTRING_D(oldIntermediateAuthToken->getClaim("preAuthUser"), "");
    authContext->fillFromTokenClaims(oldIntermediateAuthToken->getAllClaimsAsJSON());

    // Using the first slot where the intermediate token does not exist:
    if (oldIntermediateAuthToken->getJwtId().empty())
    {
        // When there is no token, override initial token parameters with the input parameters...
        *accountName = JSON_ASSTRING((*request.inputJSON), "preAuthUser", "");
        authContext->fillFromInitialJSONPOST(*request.inputJSON);
    }

    return true;
}

bool setupNewIntermediateAuthToken(const RequestParameters &request, Mantids30::API::APIReturn &response, IdentityManager *identityManager, std::shared_ptr<AppAuthExtras> authContext,
                                   const std::vector<AuthenticationSchemeUsedSlot> &requiredAuthSlots, const time_t &oldIntermediateTokenExpirationTime, const std::string &accountName)
{
    // Retrieve configuration parameters from global settings.
    auto config = Globals::pConfig;
    uint32_t loginAuthenticationTimeout = config.get<uint32_t>("LoginPortal.AuthenticationTimeout", 300);
    JWT::Token newIntermediateAuthToken;

    if (authContext->firstAuth)
    {
        newIntermediateAuthToken.setJwtId(Mantids30::Helpers::Random::createRandomString(16));
        newIntermediateAuthToken.setExpirationTime(time(nullptr) + loginAuthenticationTimeout);
    }
    else
    {
        newIntermediateAuthToken.setExpirationTime(oldIntermediateTokenExpirationTime);
    }

    newIntermediateAuthToken.setIssuedAt(time(nullptr));
    newIntermediateAuthToken.setNotBefore(time(nullptr) - 30);
    newIntermediateAuthToken.addClaim("app", authContext->appName);
    newIntermediateAuthToken.addClaim("preAuthUser", accountName);
    newIntermediateAuthToken.addClaim("slotSchemeHash", authContext->slotSchemeHash);
    newIntermediateAuthToken.addClaim("schemeId", authContext->schemeId);
    newIntermediateAuthToken.addClaim("keepAuthenticated", authContext->keepAuthenticated);
    newIntermediateAuthToken.addClaim("type", "intermediate");

    std::set<uint32_t> authSlots = authContext->authenticatedSlots;
    authSlots.insert(authContext->currentSlotId.value());
    newIntermediateAuthToken.addClaim("authenticatedSlots", Mantids30::Helpers::setToJSON(authSlots));

    if (requiredAuthSlots.empty())
    {
        JWT::Token cookieAccessToken;

        // Obtained accountName and appName in the POST Token (if exist) should match the decoded bearer token:
        if (!validateIAMAccessTokenCookieProperties(request, response, &cookieAccessToken, accountName, authContext->appName))
        {
            // Use the same auth... don't go to the next.
            (*response.responseJSON())["nextSlot"] = authContext->currentSlotId.value();

            return false;
        }

        // Set the IAM Access Token into the Cookie...
        TokensManager::setIAMAccessTokenCookie(response, request, newIntermediateAuthToken, cookieAccessToken,
                                               authContext->keepAuthenticated,              // Keep authenticated will use the current authentication proccess
                                               newIntermediateAuthToken.getExpirationTime() // Get current JWT expiration time (if keep autneticated is false)
        );

        // DONE!
        (*response.responseJSON())["nextSlot"] = Json::nullValue;
    }
    else
    {
        auto nextSlotId = requiredAuthSlots[0].slotId;
        newIntermediateAuthToken.addClaim("currentSlotId", nextSlotId); // Enforce this with authentication.

        // We can give the credential public data for the next credential:
        Credential credentialPublicData = identityManager->authController->getAccountCredentialPublicData(accountName, nextSlotId);

        json nextSlot;
        nextSlot["slotId"] = nextSlotId;
        nextSlot["details"] = credentialPublicData.slotDetails.toJSON();
        (*response.responseJSON())["nextSlot"] = nextSlot;
        (*response.responseJSON())["publicData"] = credentialPublicData.toJSON(identityManager->authController->getAuthenticationPolicy());
        (*response.responseJSON())["publicData"].removeMember("slotDetails");
        (*response.responseJSON())["intermediateToken"] = request.jwtSigner->signFromToken(newIntermediateAuthToken, false);
    }
    return true;
}

// Validate credential:
API::APIReturn LoginPortal_AuthMethods::authorize(void *context, const RequestParameters &request, ClientDetails &clientDetails)
{
    API::APIReturn response;

    // Get the identity manager from global settings to handle authentication.
    IdentityManager *identityManager = Globals::getIdentityManager();
    // Vector to store the authentication slots used by a particular scheme.
    std::vector<AuthenticationSchemeUsedSlot> requiredAuthSlots;

    std::shared_ptr<AppAuthExtras> authContext = std::make_shared<AppAuthExtras>();

    JWT::Token oldIntermediateAuthToken;
    std::string accountName;

    // Decode the bearer intermediate token... (and get the Account Name)
    if (!validateAndDecodeBearerAccessTokenProperties(request, response, &oldIntermediateAuthToken, &accountName, authContext))
    {
        return response;
    }

    if (authContext->currentSlotId == std::nullopt || request.clientRequest->getCookie("AccessToken") != "")
    {
        // You don´t need to authorize anything else! it's already authenticated.
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::AUTHENTICATION_FAILED)),
                          authResultToString(AuthenticationResult::AUTHENTICATION_FAILED));
        return response;
    }

    requiredAuthSlots = identityManager->authController->listAuthenticationSlotsUsedByScheme(authContext->schemeId);
    std::set<uint32_t> usedAuthSlotsOnAccount = identityManager->authController->listUsedAuthenticationSlotsOnAccount(accountName);

    // Remove unused requiredAuthSlots if they are optional (eg. requiredAuthSlots[0].optional) and don't exist in usedAuthSlotsOnAccount
    std::vector<AuthenticationSchemeUsedSlot> filteredAuthSlots;
    for (const auto &slot : requiredAuthSlots)
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
    requiredAuthSlots = filteredAuthSlots;

    if (requiredAuthSlots.empty())
    {
        // Why...? at least should exist 1 left.
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::INTERNAL_ERROR)),
                          authResultToString(AuthenticationResult::INTERNAL_ERROR));
        return response;
    }

    // The current slot should be the first.
    if ( requiredAuthSlots[0].slotId != authContext->currentSlotId )
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::BAD_PARAMETERS)),
                          authResultToString(AuthenticationResult::BAD_PARAMETERS));
        return response;
    }

    // Remove the first element from requiredAuthSlots
    requiredAuthSlots.erase(requiredAuthSlots.begin());

    AuthenticationResult authRetCode = identityManager->authController->authenticateCredential(clientDetails, accountName, JSON_ASSTRING(*request.inputJSON, "password", ""),
                                                                                               authContext->currentSlotId.value(),
                                                                                               getAuthModeFromString(JSON_ASSTRING(*request.inputJSON, "authMode", "MODE_PLAIN")),
                                                                                               JSON_ASSTRING(*request.inputJSON, "challengeSalt", ""), authContext);

    LOG_APP->log2(__func__, accountName, clientDetails.ipAddress, authRetCode != AuthenticationResult::AUTHENTICATED ? Logs::LEVEL_SECURITY_ALERT : Logs::LEVEL_INFO,
                  "Account Authorization Result: %" PRIu32 " - %s, for application '%s', scheme '%" PRIu32 "' and slotId = %'" PRIu32 "'", authRetCode, authResultToString(authRetCode),
                  authContext->appName.c_str(), authContext->schemeId, authContext->currentSlotId.value());

    if (IS_LOGIN_AUTHORIZED(authRetCode))
    {
        if (!setupNewIntermediateAuthToken(request, response, identityManager, authContext, requiredAuthSlots, oldIntermediateAuthToken.getExpirationTime(), accountName))
        {
            // Invalid Cookie...
            authRetCode = AuthenticationResult::BAD_PARAMETERS;
            response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(authRetCode)), authResultToString(authRetCode));
        }
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
