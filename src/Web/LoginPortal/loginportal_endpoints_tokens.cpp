#include "Mantids30/Program_Logs/loglevels.h"
#include "loginportal_endpoints.h"
#include <Mantids30/Helpers/json.h>
#include <json/value.h>

#include <algorithm> // std::find
#include <boost/algorithm/string/join.hpp>
#include <json/config.h>
#include <optional>

#include "globals.h"

#include "Tokens/tokensmanager.h"

using namespace Mantids30;
using namespace Mantids30::DataFormat;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols;

bool LoginPortal_Endpoints::token_validateRedirectURI(IdentityManager *identityManager, const std::string &app, const std::string &redirectURI, const std::string &user, const std::string &ipAddress)
{
    std::list<std::string> redirectURIs = identityManager->applications->listWebLoginAllowedRedirectURIsFromApplication(app);
    std::string callbackURI = identityManager->applications->getApplicationCallbackURI(app);

    // Validate if the redirect URI is acceptable by the application.
    if (!redirectURI.empty() && std::find(redirectURIs.begin(), redirectURIs.end(), redirectURI) == redirectURIs.end())
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, user, ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid return URL '%s': The provided URI does not match any recognized redirect URIs for application '%s'.",
                      redirectURI.c_str(), app.c_str());
        return false;
    }

    if (callbackURI.empty())
    {
        LOG_APP->log2(__func__, user, ipAddress, Logs::LEVEL_CRITICAL, "Configuration error: The application '%s' has not configured a callback URI yet.", app.c_str());
        return false;
    }

    return true;
}

std::optional<std::string> LoginPortal_Endpoints::token_signApplicationJWT(JWT::Token &accessToken, const ApplicationTokenProperties &tokenProperties)
{
    std::string appName = JSON_ASSTRING_D(accessToken.getClaim("app"), "");
    std::shared_ptr<JWT> signingJWT = Globals::getIdentityManager()->applications->getAppJWTSigner(appName);
    if (!signingJWT)
    {
        return std::nullopt;
    }
    return signingJWT->signFromToken(accessToken, false);
}

bool LoginPortal_Endpoints::token_createAndSignApplicationsJWTs(IdentityManager *identityManager, const JWT::Token *jwtToken, const std::string &app, const std::string &user,
                                                                  const uint32_t &schemeId, const std::string &redirectURI, APIReturn &response, ClientDetails &authClientDetails)
{
    ApplicationTokenProperties tokenProperties = identityManager->applications->getWebLoginJWTConfigFromApplication(app);

    if (tokenProperties.appName != app)
    {
        LOG_APP->log1(__func__, user, Logs::LEVEL_CRITICAL, "Configuration error: The application '%s' is configured with an unsupported or invalid signing algorithm.", app.c_str());
        return false;
    }

    std::set<uint32_t> authenticatedSlotIdsSet = Mantids30::Helpers::jsonToUInt32Set(jwtToken->getClaim("slotIds"));
    std::string refreshTokenId = Mantids30::Helpers::Random::createRandomString(16);

    JWT::Token accessToken, refreshToken;
    TokensManager::configureRefreshToken(refreshToken, refreshTokenId, user, app, tokenProperties, authenticatedSlotIdsSet);
    TokensManager::configureAccessToken(accessToken, refreshTokenId, user, app, tokenProperties, authenticatedSlotIdsSet);

    // Sign access token
    std::optional<std::string> accessTokenStr = token_signApplicationJWT(accessToken, tokenProperties);
    if (!accessTokenStr.has_value())
    {
        LOG_APP->log1(__func__, user, Logs::LEVEL_CRITICAL, "Failed to sign access token for application '%s'.", app.c_str());
        return false;
    }

    // Sign refresh token
    std::optional<std::string> refreshTokenStr = token_signApplicationJWT(refreshToken, tokenProperties);
    if (!refreshTokenStr.has_value())
    {
        LOG_APP->log1(__func__, user, Logs::LEVEL_CRITICAL, "Failed to sign refresh token for application '%s'.", app.c_str());
        return false;
    }

    identityManager->authController->insertApplicationAccountAccessAuthLog(user, app, schemeId, authClientDetails, refreshTokenId, accessToken.getJwtId(), accessToken.getExpirationTime(),
                                                                           refreshToken.getExpirationTime());

    // Here is the effective logging in the app.
    (*response.responseJSON())["accessToken"] = accessTokenStr.value();
    (*response.responseJSON())["refreshToken"] = refreshTokenStr.value();
    (*response.responseJSON())["redirectURI"] = redirectURI;
    (*response.responseJSON())["callbackURI"] = identityManager->applications->getApplicationCallbackURI(app);

    return true;
}

bool LoginPortal_Endpoints::token_validateJwtClaims(const JWT::Token *jwtToken, const std::string &user, const std::string &ipAddress)
{
    if (jwtToken->getClaim("app") != IAM_LOGINPORTAL_APPNAME || jwtToken->getClaim("type") != "access")
    {
        LOG_APP->log2(__func__, user, ipAddress, Logs::LEVEL_SECURITY_ALERT, "Token request denied: Invalid or unauthorized token.");
        return false;
    }
    return true;
}

bool token_validateAuthenticationScheme(IdentityManager *identityManager,
                                         const JWT::Token *jwtToken,
                                         const std::string &requestedApp,
                                         const std::string &requestedActivity,
                                         uint32_t requestedSchemeId,
                                         const std::string &authenticatedUser,
                                         const std::string &ipAddress)
{
    std::set<uint32_t> authenticatedSlotIdsSet = Mantids30::Helpers::jsonToUInt32Set(jwtToken->getClaim("slotIds"));
    std::set<std::string> authenticatedAppsSet = Mantids30::Helpers::jsonToStringSet(jwtToken->getClaim("apps"));

    if (authenticatedAppsSet.find(requestedApp)==authenticatedAppsSet.end())
    {
        LOG_APP->log2(__func__, authenticatedUser, ipAddress, Logs::LEVEL_SECURITY_ALERT, "Token request denied: The user is requesting an APP that is not authenticated.");
        return false;
    }

    std::set<uint32_t> schemesInActivity = identityManager->applicationActivities->listAuthenticationSchemesForApplicationActivity(requestedApp, requestedActivity);
    if (schemesInActivity.find(requestedSchemeId) == schemesInActivity.end())
    {
        LOG_APP->log2(__func__, authenticatedUser, ipAddress, Logs::LEVEL_SECURITY_ALERT, "Token request denied: The user is requesting an scheme that is not in that activity.");
        return false;
    }

    std::set<uint32_t> authenticationSlotsActivatedOnAccount = identityManager->authController->listUsedAuthenticationSlotsOnAccount( authenticatedUser );

    std::vector<AuthenticationSchemeUsedSlot> slotsUsedByScheme = identityManager->authController->listAuthenticationSlotsUsedByScheme(requestedSchemeId);
    bool atLeastOneSlot = false;
    for (const auto &slot : slotsUsedByScheme)
    {
        if (slot.optional && authenticationSlotsActivatedOnAccount.find(slot.slotId) == authenticationSlotsActivatedOnAccount.end())
        {
            // Don't require this slot...
            continue;
        }

        if (authenticatedSlotIdsSet.find(slot.slotId) == authenticatedSlotIdsSet.end())
        {
            LOG_APP->log2(__func__, authenticatedUser, ipAddress, Logs::LEVEL_SECURITY_ALERT, "Token request denied: Missing required credential slot id='%d'.", slot.slotId);
            return false;
        }

        atLeastOneSlot = true;
    }

    if (!atLeastOneSlot)
    {
        LOG_APP->log2(__func__, authenticatedUser, ipAddress, Logs::LEVEL_SECURITY_ALERT, "The account does not have any authentication activated yet.");
        return false;
    }

    return true;
}


bool LoginPortal_Endpoints::token_validateAppAuthorization(IdentityManager *identityManager, const JWT::Token *jwtToken, const std::string &app, const std::string &user, const std::string &ipAddress)
{
    std::set<std::string> authenticatedAppsSet = Mantids30::Helpers::jsonToStringSet(jwtToken->getClaim("apps"));
    if (authenticatedAppsSet.find(app) == authenticatedAppsSet.end())
    {
        LOG_APP->log2(__func__, user, ipAddress, Logs::LEVEL_SECURITY_ALERT, "Token request denied: Unauthorized application '%s' access.", app.c_str());
        return false;
    }
    return true;
}

/*
    This will tranform the current authentication into an APP access...
*/
API::APIReturn LoginPortal_Endpoints::token(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    IdentityManager *identityManager = Globals::getIdentityManager();

    std::string authenticatedUser = request.jwtToken->getSubject();

    std::string activity = JSON_ASSTRING(*request.inputJSON, "activity", "");       // APP ACTIVITY NAME.
    std::string redirectURI = JSON_ASSTRING(*request.inputJSON, "redirectURI", ""); // APP REDIRECT URI.
    std::string appName = JSON_ASSTRING(*request.inputJSON, "app", ""); // APP NAME.
    uint32_t schemeId = JSON_ASUINT(*request.inputJSON,"schemeId", 0);             // APP SCHEME ID.

    //////////////////////////////////////////////////////////////////////////////////////////
    //// -------------------------     TOKEN VALIDATION       --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    if (!token_validateJwtClaims(request.jwtToken, authenticatedUser, authClientDetails.ipAddress))
    {
        response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)), authResultToString(AuthenticationResult::UNAUTHENTICATED));
        return response;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// -------------------------        AUTHENTICATION      --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    // Validate authentication scheme
    if (!token_validateAuthenticationScheme(identityManager, request.jwtToken, appName, activity, schemeId, authenticatedUser, authClientDetails.ipAddress))
    {
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)), authResultToString(AuthenticationResult::UNAUTHENTICATED));
        return response;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// ---------------------------    ACCOUNT VALIDATIONS   --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    AuthenticationResult r;
    if (!identityManager->validateAccountForNewAccess(authenticatedUser, appName, r, true))
    {
        // This token is not available for retrieving app tokens because the user does not have a valid account with the specified application.
        const char *reasonText = authResultToString(r);
        LOG_APP->log2(__func__, authenticatedUser, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT,
                      "Token request denied: User '%s' attempted to obtain an access token for app '%s', but the account is not valid or authorized for this application. Reason: %s.",
                      authenticatedUser.c_str(), appName.c_str(), reasonText);
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_INVALID_ACCT", authResultToString(r));
        return response;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// ---------------------------   REDIRECT VALIDATIONS   --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////

    if (redirectURI.empty())
    {
        redirectURI = identityManager->applications->getWebLoginDefaultRedirectURIForApplication(appName);
    }

    if (!token_validateRedirectURI(identityManager, appName, redirectURI, authenticatedUser, authClientDetails.ipAddress))
    {
        response.setError(HTTP::Status::S_406_NOT_ACCEPTABLE, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::BAD_PARAMETERS)), "Invalid Redirect URI");
        return response;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// -------------------------       TOKEN CREATION       --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    // Create and sign tokens
    if (!token_createAndSignApplicationsJWTs(identityManager, request.jwtToken, appName, authenticatedUser, schemeId, redirectURI, response, authClientDetails))
    {
        // Failed to create the token...
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::INTERNAL_ERROR)), authResultToString(AuthenticationResult::INTERNAL_ERROR));
        return response;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// ----------------------       KEEP AUTHENTICATION       ------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    if (JSON_ASBOOL_D(request.jwtToken->getClaim("keepAuthenticated"), false) == false)
    {
        // Discard access cookies upon first use. (Access tokens are short-lived, but should be discarded after the first usage)
        doLogoutInResponse(context, request, authClientDetails, &response);
    }

    return response;
}
