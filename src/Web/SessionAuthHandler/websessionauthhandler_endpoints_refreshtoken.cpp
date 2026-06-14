#include "Mantids30/Program_Logs/loglevels.h"
#include "Mantids30/Protocol_HTTP/httpv1_base.h"
#include "Tokens/tokensmanager.h"
#include "websessionauthhandler_endpoints.h"
#include <json/value.h>
#include <Mantids30/Helpers/json.h>

#include <boost/algorithm/string/join.hpp>
#include <json/config.h>

#include "globals.h"
#include "Tokens/tokensmanager.h"

using namespace Mantids30;
using namespace Mantids30::DataFormat;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols;

API::APIReturn WebSessionAuthHandler_Endpoints::refreshAccessToken(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    IdentityManager *identityManager = Globals::getIdentityManager();

    std::string refreshTokenStr = request.clientRequest->getCookies()->getSubVar("RefreshToken");

    // ----------    decode no verify the Refresh Token and take the app name    -----------

    if (refreshTokenStr.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Refresh token cookie is missing or empty.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_refresher", "Invalid Refresh Token");
        return response;
    }

    // Validate the refresh token
    JWT::Token refreshTokenNoVerified;

    if (!JWT::decodeNoVerify(refreshTokenStr, &refreshTokenNoVerified))
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid JWT format detected in the provided access token.");
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_jwt", "The 'accessToken' must be a valid JWT string.");
        return response;
    }

    // Extract application from the refresh token
    const std::string &refreshTokenApp = JSON_ASSTRING_D(refreshTokenNoVerified.getClaim("app"), "");
    const std::string &tokenType = JSON_ASSTRING_D(refreshTokenNoVerified.getClaim("type"), "");
    ApplicationTokenProperties tokenProps = identityManager->applications->getWebLoginJWTConfigFromApplication(refreshTokenApp);

    if (tokenType!="refresher")
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "This is not a Refresher Token.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_token", "Invalid Refresher Token");
        return response;
    }

    if (refreshTokenApp.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Refresh token contains invalid or missing claims.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_token", "Invalid Refresher Token");
        return response;
    }

    if (tokenProps.appName != refreshTokenApp)
    {
        // This token is not available for retrieving app tokens...
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_CRITICAL, "Configuration error: The application '%s' is configured with an unsupported or invalid signing algorithm.",
                      refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::INTERNAL_ERROR)), authResultToString(AuthenticationResult::INTERNAL_ERROR));
        return response;
    }

    // ----------   validate the header API Key    -----------
    if (!validateAPIKey(refreshTokenApp, response, request, authClientDetails))
    {
        return response;
    }

    // --------- validate the refresh token itself (that is signed with the application keys) --------
    JWT::Token refreshTokenVerified;

    std::shared_ptr<JWT> validator = identityManager->applications->getAppJWTValidator(refreshTokenApp);

    if (!validator)
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "No JWT validator found for application '%s'.", refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_app", "Application not configured");
        return response;
    }

    if (!validator->verify(refreshTokenStr, &refreshTokenVerified))
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Failed to verify refresh token for application '%s'.", refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_token", "Invalid Refresh Token");
        return response;
    }

    const std::string &refreshTokenUser = refreshTokenVerified.getSubject();

    // --------- create a new access token (like in the token function) -----------
    std::set<uint32_t> currentAuthenticatedSlotIds;
    Json::Value jSlotIds = refreshTokenVerified.getClaim("slotIds");
    if (!jSlotIds.isNull() && jSlotIds.isArray())
    {
        for (const Json::Value &slotIdNode : jSlotIds)
        {
            const uint32_t slotId = JSON_ASUINT_D(slotIdNode, 0xFFFFFFFF);
            currentAuthenticatedSlotIds.insert(slotId);
        }
    }

    JWT::Token newAccessToken;
    TokensManager::configureApplicationAccessToken(newAccessToken, refreshTokenVerified.getJwtId(), refreshTokenUser, refreshTokenApp, tokenProps,
                         currentAuthenticatedSlotIds); // Assuming these variables are accessible here

    // --------- return as cookie, and create the max age cookie too, don't do anything else. ------------
    // Update cookies with new tokens
    setupAccessTokenCookies(response, newAccessToken, tokenProps);

    // Update the token in the database.
    identityManager->authController->updateApplicationAuthLogAccessTokenId( refreshTokenUser,refreshTokenApp,refreshTokenVerified.getJwtId(), newAccessToken.getJwtId(), newAccessToken.getExpirationTime() );

    (*response.responseJSON())["maxAge"] = (time_t)(newAccessToken.getExpirationTime() - time(nullptr));
    return response;
}



