#include "websessionauthhandler_endpoints.h"

#include "Mantids30/Program_Logs/loglevels.h"
#include "Mantids30/Protocol_HTTP/httpv1_base.h"
#include <Mantids30/Helpers/json.h>
#include <json/value.h>

#include <boost/algorithm/string/join.hpp>
#include <json/config.h>

#include "globals.h"

using namespace Mantids30;
using namespace Mantids30::DataFormat;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols;

// Helper to set delete cookies for logout
static void setLogoutCookies(API::APIReturn &response, const ApplicationTokenProperties &tokenProps)
{
    // Clear AccessToken
    response.cookiesMap["AccessToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["AccessToken"].deleteCookie();
    response.cookiesMap["AccessToken"].path = JSON_ASSTRING(tokenProps.tokensConfiguration["accessToken"], "path", "/");

    // Clear RefreshToken
    response.cookiesMap["RefreshToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["RefreshToken"].deleteCookie();
    response.cookiesMap["RefreshToken"].path = JSON_ASSTRING(tokenProps.tokensConfiguration["refreshToken"], "path", "/auth");

    // Clear RefreshTokenId
    response.cookiesMap["RefreshTokenId"] = HTTP::Headers::Cookie();
    response.cookiesMap["RefreshTokenId"].deleteCookie();
    response.cookiesMap["RefreshTokenId"].path = JSON_ASSTRING(tokenProps.tokensConfiguration["refreshToken"], "path", "/auth");

    // Clear RefreshTokenUser
    response.cookiesMap["RefreshTokenUser"] = HTTP::Headers::Cookie();
    response.cookiesMap["RefreshTokenUser"].deleteCookie();
    response.cookiesMap["RefreshTokenUser"].path = JSON_ASSTRING(tokenProps.tokensConfiguration["refreshToken"], "path", "/auth");

    response.cookiesMap["KeepAuthentication"] = HTTP::Headers::Cookie();
    response.cookiesMap["KeepAuthentication"].deleteCookie();
    response.cookiesMap["KeepAuthentication"].path = "/";
}


API::APIReturn WebSessionAuthHandler_Endpoints::appLogout(void *context, const RequestParameters &request, IdentityManager::ClientDetails &authClientDetails)
{
    // Helper to extract common request parameters safely
    API::APIReturn response;
    IdentityManager *identityManager = Globals::getIdentityManager();

    std::string apiKey = request.clientRequest->getHeaderOption("x-api-key");
    // Validate API key first to get app name
    std::string appName = identityManager->applications->getApplicationNameByAPIKey(apiKey);
    if (appName.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid API key provided. Application not found.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_api_key", "The provided API key is invalid or unauthorized.");
        return response;
    }

    // 4. Get Token Configuration for Cookie Paths
    ApplicationTokenProperties tokenProps = identityManager->applications->getWebLoginJWTConfigFromApplication(appName);

    // 5. Clear Cookies
    setLogoutCookies(response, tokenProps);

    std::string user = request.clientRequest->getCookie("RefreshTokenUser");
    std::string jwtId = request.clientRequest->getCookie("RefreshTokenId");

    // 6. Close Session in Database
    identityManager->authController->logoutApplicationAuthLog(user, appName, jwtId,
                                                              IdentityManager::LogoutReason::UserInitiated);

    // TODO: invalidate the token in the token manager... (put the id in the blacklist)
    // identityManager->tokenBlacklist->add(refreshTokenVerified.getJwtId());

    return response;
}

WebSessionAuthHandler_Endpoints::APIReturn WebSessionAuthHandler_Endpoints::getLogoutCallbackURL(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    IdentityManager *identityManager = Globals::getIdentityManager();

    // VARS:
    std::string xAPIKeyStr = request.clientRequest->getHeaderOption("x-api-key");
    std::string appName = identityManager->applications->getApplicationNameByAPIKey(xAPIKeyStr);

    // Now, search the application by the x-api-key:
    if (appName.empty())
    {
        // app key not found...
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid API key provided. Application not found.");
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_api_key", "The provided API key is invalid or unauthorized.");
        return response;
    }

    auto attribs = identityManager->applications->getApplicationAttributes(appName);

    json payloadOut;

    //  Configuration parameters:
    auto config = Globals::pConfig;

    std::string logoutURL = attribs->useEmbeddedAuthentication?  "/login/logout/" : config.get<std::string>("AppVars.LoginPortalURL", "about:blank") + "/logout/";
    payloadOut["url"] = logoutURL;
    payloadOut["appName"] = appName;

    return payloadOut;
}
