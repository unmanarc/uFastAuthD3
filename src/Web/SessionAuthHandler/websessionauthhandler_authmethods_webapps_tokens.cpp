#include "Mantids30/Program_Logs/loglevels.h"
#include "Mantids30/Protocol_HTTP/httpv1_base.h"
#include "Tokens/tokensmanager.h"
#include "websessionauthhandler_authmethods.h"
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

void WebSessionAuthHandler_AuthMethods::setupAccessTokenCookies(APIReturn &response, JWT::Token accessToken, const ApplicationTokenProperties &tokenProps)
{
    CookieProperties props;
    props.sessionCookie = JSON_ASBOOL(tokenProps.tokensConfiguration["accessToken"],"useSessionCookies",true);
    props.expirationTime = accessToken.getExpirationTime(); // expire with the JWT token expiration.
    props.path = JSON_ASSTRING(tokenProps.tokensConfiguration["accessToken"],"path","/");
    setupCookie(response, "AccessToken", signApplicationToken(accessToken, tokenProps), props);
}

void WebSessionAuthHandler_AuthMethods::setupRefreshTokenCookies(APIReturn &response, JWT::Token refreshToken, const ApplicationTokenProperties &tokenProps)
{
    CookieProperties props;
    props.expirationTime = refreshToken.getExpirationTime(); // expire with the JWT token expiration.
    props.path = JSON_ASSTRING(tokenProps.tokensConfiguration["refreshToken"],"path","/auth");
    setupCookie(response, "RefreshToken", signApplicationToken(refreshToken, tokenProps), props);
}

void WebSessionAuthHandler_AuthMethods::setupCookie(APIReturn &response, const std::string &name, const std::string &value, const CookieProperties &props)
{
    response.cookiesMap[name] = HTTP::Headers::Cookie();
    response.cookiesMap[name].setExpiration(props.expirationTime);
    response.cookiesMap[name].secure = props.secure;
    response.cookiesMap[name].path = props.path;
    response.cookiesMap[name].httpOnly = props.httpOnly;
    response.cookiesMap[name].value = value;

    if (props.sessionCookie)
        response.cookiesMap[name].setAsSessionCookie();
}

API::APIReturn WebSessionAuthHandler_AuthMethods::refreshAccessToken(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
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
        for (const auto &slotIdNode : jSlotIds)
        {
            const uint32_t slotId = JSON_ASUINT_D(slotIdNode, 0xFFFFFFFF);
            currentAuthenticatedSlotIds.insert(slotId);
        }
    }

    JWT::Token newAccessToken;
    TokensManager::configureAccessToken(newAccessToken, refreshTokenVerified.getJwtId(), refreshTokenUser, refreshTokenApp, tokenProps,
                         currentAuthenticatedSlotIds); // Assuming these variables are accessible here

    // --------- return as cookie, and create the max age cookie too, don't do anything else. ------------
    // Update cookies with new tokens
    setupAccessTokenCookies(response, newAccessToken, tokenProps);

    // Update the token in the database.
    identityManager->authController->updateApplicationAuthLogAccessTokenId( refreshTokenUser,refreshTokenApp,refreshTokenVerified.getJwtId(), newAccessToken.getJwtId(), newAccessToken.getExpirationTime() );

    (*response.responseJSON())["maxAge"] = (time_t)(newAccessToken.getExpirationTime() - time(nullptr));
    return response;
}


API::APIReturn WebSessionAuthHandler_AuthMethods::appLogout(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    IdentityManager *identityManager = Globals::getIdentityManager();

    std::string xAPIKeyStr = request.clientRequest->getHeaderOption("x-api-key");
    std::string refreshTokenStr = request.clientRequest->getCookies()->getSubVar("RefreshToken");

    // Validate API key first
    std::string appNameStr = identityManager->applications->getApplicationNameByAPIKey(xAPIKeyStr);
    if (appNameStr.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid API key provided. Application not found.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_api_key", "The provided API key is invalid or unauthorized.");
        return response;
    }

    // Check if refresh token is present
    if (refreshTokenStr.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_WARN, "Refresh token cookie is missing or empty during logout. Maybe not logged in?");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_refresher", "Invalid Refresh Token");
        return response;
    }

    // Decode refresh token without verification initially
    JWT::Token refreshTokenNoVerified;
    if (!JWT::decodeNoVerify(refreshTokenStr, &refreshTokenNoVerified))
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid JWT format in refresh token.");
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_jwt", "Refresh token is not a valid JWT.");
        return response;
    }

    // Extract app from the refresh token
    const std::string &refreshTokenApp = JSON_ASSTRING_D(refreshTokenNoVerified.getClaim("app"), "");
    const std::string &refreshTokenType = JSON_ASSTRING_D(refreshTokenNoVerified.getClaim("type"), "");

    if (refreshTokenType!="refresher")
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "This is not a Refresher Token.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_token", "Invalid Refresher Token");
        return response;
    }

    if (refreshTokenApp.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Refresh token contains invalid or missing 'app' claim.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_token", "Invalid Refresh Token");
        return response;
    }

    // Verify the app name matches
    if (appNameStr != refreshTokenApp)
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Mismatched app name in token vs API key: expected '%s', got '%s'.", appNameStr.c_str(), refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_app", "Refresh token does not belong to this application.");
        return response;
    }

    // Now verify the signature of the refresh token
    std::shared_ptr<JWT> validator = identityManager->applications->getAppJWTValidator(refreshTokenApp);
    if (!validator)
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_CRITICAL, "No JWT validator found for application '%s'.", refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::INTERNAL_ERROR)), authResultToString(AuthenticationResult::INTERNAL_ERROR));
        return response;
    }

    JWT::Token refreshTokenVerified;
    if (!validator->verify(refreshTokenStr, &refreshTokenVerified))
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Failed to verify refresh token for app '%s'.", refreshTokenApp.c_str());
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_token", "Invalid Refresh Token");
        return response;
    }

    // At this point, we know the token is valid and belongs to the correct app.

    ApplicationTokenProperties tokenProps = identityManager->applications->getWebLoginJWTConfigFromApplication(appNameStr);

    // Clear cookies
    response.cookiesMap["AccessToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["AccessToken"].deleteCookie();
    response.cookiesMap["AccessToken"].path = JSON_ASSTRING(tokenProps.tokensConfiguration["accessToken"], "path", "/");

    response.cookiesMap["RefreshToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["RefreshToken"].deleteCookie();
    response.cookiesMap["RefreshToken"].path = JSON_ASSTRING(tokenProps.tokensConfiguration["refreshToken"], "path", "/auth");

    // Close the session in the database.
    identityManager->authController->logoutApplicationAuthLog( refreshTokenVerified.getSubject(),refreshTokenApp,refreshTokenVerified.getJwtId(), IdentityManager::LogoutReason::UserInitiated );

    // TODO: invalidate the token in the token manager... (put the id in the blacklist)

    return response;
}

// Receives the token from the Login Portal (Via proxy, this is why we receive the X-API-Key from the intermediate app), and then, we set the refresh/access token as cookies
API::APIReturn WebSessionAuthHandler_AuthMethods::callback(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    IdentityManager *identityManager = Globals::getIdentityManager();

    // HTTP CLIENT VARS:
    std::string accessTokenStr = request.clientRequest->getVars(HTTP::VARS_POST)->getStringValue("accessToken");
    std::string refreshTokenStr = request.clientRequest->getVars(HTTP::VARS_POST)->getStringValue("refreshToken");
    std::string redirectURIStr = request.clientRequest->getVars(HTTP::VARS_POST)->getStringValue("redirectURI");
    std::string xAPIKeyStr = request.clientRequest->getHeaderOption("x-api-key");

    // VARS:
    std::string appNameStr = identityManager->applications->getApplicationNameByAPIKey(xAPIKeyStr);

    // Now, search the application by the x-api-key:
    if (appNameStr.empty())
    {
        // app key not found...
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid API key provided. Application not found.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_api_key", "The provided API key is invalid or unauthorized.");
        return response;
    }

    ApplicationTokenProperties tokenProps = identityManager->applications->getWebLoginJWTConfigFromApplication(appNameStr);
    std::shared_ptr<JWT> validator = identityManager->applications->getAppJWTValidator(appNameStr);

    JWT::Token accessToken, refreshToken;

    // Verify that the tokens are valid, if not, don't return the tokens.
    bool accessTokenValid = validator->verify(accessTokenStr, &accessToken);
    bool refreshTokenValid = validator->verify(refreshTokenStr, &refreshToken);

    if (!accessTokenValid || !refreshTokenValid)
    {
        std::string logMessage = "Invalid JWT token(s) provided.";
        if (!accessTokenValid)
        {
            logMessage += " Access Token verification failed.";
        }
        if (!refreshTokenValid)
        {
            logMessage += " Refresh Token verification failed.";
        }
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, logMessage.c_str());
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_token", "The provided access or refresh token is invalid.");
        return response;
    }

    // Verify the redirection... (VERY IMPORTANT)
    std::list<std::string> redirectURLS = identityManager->applications->listWebLoginAllowedRedirectURIsFromApplication(appNameStr);

    if (std::find(redirectURLS.begin(), redirectURLS.end(), redirectURIStr) == redirectURLS.end())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Redirect URI '%s' is not allowed for application '%s'.", redirectURIStr.c_str(), appNameStr.c_str());
        response.setError(HTTP::Status::S_403_FORBIDDEN, "invalid_redirect_uri", "The requested redirect URI is not authorized.");
        return response;
    }

    setupAccessTokenCookies(response, accessToken, tokenProps);
    setupRefreshTokenCookies(response, refreshToken, tokenProps);

    // Redirect:
    response.redirectURL = redirectURIStr;
    return response;
}



