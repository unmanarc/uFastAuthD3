#include "Mantids30/Program_Logs/loglevels.h"
#include "Mantids30/Protocol_HTTP/httpv1_base.h"
#include "websessionauthhandler_endpoints.h"
#include <Mantids30/Helpers/json.h>
#include <json/value.h>

#include <boost/algorithm/string/join.hpp>
#include <json/config.h>

#include "globals.h"

using namespace Mantids30;
using namespace Mantids30::DataFormat;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocol;
using namespace Network::Protocol::HTTP;

// Receives the token from the Login Portal (Via proxy, this is why we receive the X-API-Key from the intermediate app), and then, we set the refresh/access token as cookies
API::APIReturn WebSessionAuthHandler_Endpoints::callback(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    IdentityManager *identityManager = Globals::getIdentityManager();

    // HTTP CLIENT VARS:
    std::string modeStr = request.clientRequest->getVarsBySource(Source::POST)->getStringValue("mode");
    std::string accessTokenStr = request.clientRequest->getVarsBySource(Source::POST)->getStringValue("accessToken");
    std::string refreshTokenStr = request.clientRequest->getVarsBySource(Source::POST)->getStringValue("refreshToken");
    std::string redirectURIStr = request.clientRequest->getVarsBySource(Source::POST)->getStringValue("redirectURI");
    std::string xAPIKeyStr = request.clientRequest->getHeaderOption("x-api-key");

    if (modeStr == "logout")
    {
        std::string allowedOrigin;
        // TODO: check on dynamic token validator?
        allowedOrigin = Globals::pConfig.get<std::string>("AppVars.LoginPortalURL", "");
        if (request.clientRequest->getOrigin() != allowedOrigin)
        {
            LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "Logout is not allowed from Origin='%s'.", request.clientRequest->getOrigin().c_str());
            return {HTTP::Status::Code::S_403_FORBIDDEN, "invalid_origin", "Invalid Origin."};
        }

        APIReturn r = appLogout(context, request, authClientDetails);
        API::OptionsHandlerConfig options;
        options.insertAllowedOrigin(allowedOrigin);
        options.setAllowCredentials(true);
        options.configureAPIReturnOptionsHeaders(r, request.clientRequest->getOrigin());
        return r;
    }

    // VARS:
    std::string appNameStr = identityManager->applications->getApplicationNameByAPIKey(xAPIKeyStr);

    // Now, search the application by the x-api-key:
    if (appNameStr.empty())
    {
        // app key not found...
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "Invalid API key provided. Application not found.");
        return {HTTP::Status::Code::S_401_UNAUTHORIZED, "invalid_api_key", "The provided API key is invalid or unauthorized."};
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

        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, logMessage.c_str());
        return {HTTP::Status::Code::S_401_UNAUTHORIZED, "invalid_token", "The provided access/refresh token is invalid."};
    }

    // Verify the redirection... (VERY IMPORTANT)
    std::set<std::string> redirectURLS = identityManager->applications->listWebLoginAllowedRedirectURIsFromApplication(appNameStr);

    if (redirectURLS.count(redirectURIStr) == 0)
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "Redirect URI '%s' is not allowed for application '%s'.", redirectURIStr.c_str(), appNameStr.c_str());
        return {HTTP::Status::Code::S_403_FORBIDDEN, "invalid_redirect_uri", "The requested redirect URI is not authorized."};
    }

    setupAccessTokenCookies(response, accessToken, tokenProps);
    setupRefreshTokenCookies(response, refreshToken, tokenProps);

    // Redirect:
    response.redirectURL = redirectURIStr;
    return response;
}
