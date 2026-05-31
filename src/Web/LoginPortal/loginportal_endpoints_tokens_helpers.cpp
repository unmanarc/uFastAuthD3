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

bool LoginPortal_Endpoints::token_validateRedirectURI(const std::string &app, const std::string &redirectURI, const std::string &user, const std::string &ipAddress)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

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

std::optional<std::string> LoginPortal_Endpoints::token_signApplicationJWT(JWT::Token &accessToken)
{
    std::string appName = JSON_ASSTRING_D(accessToken.getClaim("app"), "");
    std::shared_ptr<JWT> signingJWT = Globals::getIdentityManager()->applications->getAppJWTSigner(appName);
    if (!signingJWT)
    {
        return std::nullopt;
    }
    return signingJWT->signFromToken(accessToken, false);
}

bool LoginPortal_Endpoints::token_createAndSignApplicationAccessJWTs(const JWT::Token *jwtToken,
                                                                        const bool & keepAuthenticated,
                                                                        const std::string &app,
                                                                        const std::string &user,
                                                                        const uint32_t &schemeId,
                                                                        const std::string &redirectURI,
                                                                        APIReturn &response, ClientDetails &authClientDetails)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    ApplicationTokenProperties tokenProperties = identityManager->applications->getWebLoginJWTConfigFromApplication(app);

    if (tokenProperties.appName != app)
    {
        LOG_APP->log1(__func__, user, Logs::LEVEL_CRITICAL, "Configuration error: The application '%s' is configured with an unsupported or invalid signing algorithm.", app.c_str());
        return false;
    }

    std::set<uint32_t> authenticatedSlotIdsSet = Mantids30::Helpers::jsonToUInt32Set(jwtToken->getClaim("slotIds"));
    std::string refreshTokenId = Mantids30::Helpers::Random::createRandomString(16);

    JWT::Token accessToken, refreshToken;//, logoutToken;
    TokensManager::configureApplicationRefreshToken(refreshToken, refreshTokenId, user, app, tokenProperties, authenticatedSlotIdsSet, keepAuthenticated);
    TokensManager::configureApplicationAccessToken(accessToken, refreshTokenId, user, app, tokenProperties, authenticatedSlotIdsSet);

    // Sign access token
    std::optional<std::string> accessTokenStr = token_signApplicationJWT(accessToken);
    if (!accessTokenStr.has_value())
    {
        LOG_APP->log1(__func__, user, Logs::LEVEL_CRITICAL, "Failed to sign access token for application '%s'.", app.c_str());
        return false;
    }

    // Sign refresh token
    std::optional<std::string> refreshTokenStr = token_signApplicationJWT(refreshToken);
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
    //(*response.responseJSON())[""] = accessTokenStr.value();

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


bool LoginPortal_Endpoints::token_validateAuthenticationScheme(const JWT::Token *jwtToken, const std::string &requestedApp, const std::string &requestedActivity,
                                        uint32_t &requestedSchemeId, const std::string &authenticatedUser, const std::string &ipAddress)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    // 1. Extract authenticated slot IDs from the JWT token
    std::set<uint32_t> authenticatedSlotIdsSet = Mantids30::Helpers::jsonToUInt32Set(jwtToken->getClaim("slotIds"));

    // 2. Get schemes allowed for this activity
    std::set<uint32_t> schemesInActivity = identityManager->applicationActivities->listAuthenticationSchemesForApplicationActivity(requestedApp, requestedActivity);

    // Helper Lambda: Checks if a specific scheme ID is valid against the JWT and user account.
    // Returns true if valid, false otherwise.
    auto isSchemeValid = [&](uint32_t schemeId) -> bool
    {
        // Get slots required by this scheme
        std::vector<AuthenticationSchemeUsedSlot> slotsUsedByScheme = identityManager->authController->listAuthenticationSlotsUsedByScheme(schemeId);

        // Get slots activated on the user's account
        std::set<uint32_t> authenticationSlotsActivatedOnAccount = identityManager->authController->listUsedAuthenticationSlotsOnAccount(authenticatedUser);

        for (const auto &slot : slotsUsedByScheme)
        {
            bool isSlotRequiredToBeInJwt = false;

            if (slot.optional)
            {
                // Optional slot: Required only if activated on account
                if (authenticationSlotsActivatedOnAccount.find(slot.slotId) != authenticationSlotsActivatedOnAccount.end())
                {
                    isSlotRequiredToBeInJwt = true;
                }
            }
            else
            {
                // Mandatory slot: Always required
                isSlotRequiredToBeInJwt = true;
            }

            if (isSlotRequiredToBeInJwt)
            {
                if (authenticatedSlotIdsSet.find(slot.slotId) == authenticatedSlotIdsSet.end())
                {
                    return false; // Missing required slot
                }
            }
        }
        return true; // All required slots present
    };

    // Case 1: requestedSchemeId is 0 -> Try to find ANY valid scheme
    if (requestedSchemeId == 0)
    {
        for (uint32_t candidateSchemeId : schemesInActivity)
        {
            if (isSchemeValid(candidateSchemeId))
            {
                requestedSchemeId = candidateSchemeId; // Update the ID to the found valid one
                return true;
            }
        }

        LOG_APP->log2(__func__, authenticatedUser, ipAddress, Logs::LEVEL_SECURITY_ALERT, "Token request denied: No valid authentication scheme found for the provided JWT slots.");
        return false;
    }

    // Case 2: requestedSchemeId is NOT 0 -> Validate the specific requested scheme
    // First, check if the scheme is allowed in this activity
    if (schemesInActivity.find(requestedSchemeId) == schemesInActivity.end())
    {
        LOG_APP->log2(__func__, authenticatedUser, ipAddress, Logs::LEVEL_SECURITY_ALERT, "Token request denied: The user is requesting a scheme that is not in that activity.");
        return false;
    }

    // Then, validate the slots for the requested scheme
    if (!isSchemeValid(requestedSchemeId))
    {
        LOG_APP->log2(__func__, authenticatedUser, ipAddress, Logs::LEVEL_SECURITY_ALERT, "Token request denied: Missing required credential slots for requested scheme.");
        return false;
    }

    return true;
}

bool LoginPortal_Endpoints::token_validateAppAuthorization(const JWT::Token *jwtToken, const std::string &app, const std::string &user, const std::string &ipAddress)
{
    std::set<std::string> authenticatedAppsSet = Mantids30::Helpers::jsonToStringSet(jwtToken->getClaim("apps"));
    if (authenticatedAppsSet.find(app) == authenticatedAppsSet.end())
    {
        LOG_APP->log2(__func__, user, ipAddress, Logs::LEVEL_SECURITY_ALERT, "Token request denied: Unauthorized application '%s' access.", app.c_str());
        return false;
    }
    return true;
}
