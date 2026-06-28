#include "websessionauthhandler_endpoints.h"

#include <Mantids30/Program_Logs/loglevels.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Helpers/encoders.h>
#include <json/value.h>

#include <boost/algorithm/string/join.hpp>
#include <json/config.h>

#include "globals.h"

using namespace Mantids30;
using namespace Mantids30::DataFormat;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocol;

// Helper to set delete cookies for logout
static void setLogoutCookies(API::APIReturn &response, const ApplicationTokenProperties &tokenProps)
{
    // Clear AccessToken
    response.cookiesMap["AccessToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["AccessToken"].deleteCookie();
    response.cookiesMap["AccessToken"].path = Helpers::JSON::ASSTRING(tokenProps.tokensConfiguration["accessToken"], "path", "/");

    // Clear RefreshToken
    response.cookiesMap["RefreshToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["RefreshToken"].deleteCookie();
    response.cookiesMap["RefreshToken"].path = Helpers::JSON::ASSTRING(tokenProps.tokensConfiguration["refreshToken"], "path", "/auth");

    // Clear RefreshTokenId
    response.cookiesMap["RefreshTokenId"] = HTTP::Headers::Cookie();
    response.cookiesMap["RefreshTokenId"].deleteCookie();
    response.cookiesMap["RefreshTokenId"].path = Helpers::JSON::ASSTRING(tokenProps.tokensConfiguration["refreshToken"], "path", "/auth");

    // Clear SessionPublicData
    response.cookiesMap["SessionPublicData"] = HTTP::Headers::Cookie();
    response.cookiesMap["SessionPublicData"].deleteCookie();
    response.cookiesMap["SessionPublicData"].path = "/";
}

API::APIReturn WebSessionAuthHandler_Endpoints::appLogout(void *context, const RequestContext &request, IdentityManager::ClientDetails &authClientDetails)
{
    // Helper to extract common request parameters safely
    API::APIReturn response;
    IdentityManager *identityManager = Globals::getIdentityManager();

    std::string apiKey = request.clientRequest->getHeaderOption("x-api-key");
    // Validate API key first to get app name
    std::string appName = identityManager->applications->getApplicationNameByAPIKey(apiKey);
    if (appName.empty())
    {
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "Invalid API key provided. Application not found.");
        return {HTTP::Status::Code::S_401_UNAUTHORIZED, "invalid_api_key", "The provided API key is invalid or unauthorized."};
    }

    // 4. Get Token Configuration for Cookie Paths
    ApplicationTokenProperties tokenProps = identityManager->applications->getWebLoginJWTConfigFromApplication(appName);

    // 5. Clear Cookies
    setLogoutCookies(response, tokenProps);

    std::string sessionPublicData = request.clientRequest->getCookie("SessionPublicData");
    std::string user;
    if (!sessionPublicData.empty())
    {
        std::string decoded = Mantids30::Helpers::Encoders::decodeFromBase64(sessionPublicData);
        Json::Value jSessionPublicData;
        Json::CharReaderBuilder builder;
        const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
        std::string errors;
        if (reader->parse(decoded.c_str(), decoded.c_str() + decoded.length(), &jSessionPublicData, &errors))
        {
            user = jSessionPublicData.get("user", "").asString();
        }
    }
    std::string jwtId = request.clientRequest->getCookie("RefreshTokenId");

    // 6. Close Session in Database
    identityManager->authController->logoutApplicationAuthLog(user, appName, jwtId, IdentityManager::LogoutReason::UserInitiated);

    // TODO: invalidate the token in the token manager... (put the id in the blacklist)
    // identityManager->tokenBlacklist->add(refreshTokenVerified.getJwtId());

    return response;
}

WebSessionAuthHandler_Endpoints::APIReturn WebSessionAuthHandler_Endpoints::getLogoutCallbackURL(void *context, const RequestContext &request, ClientDetails &authClientDetails)
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
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "Invalid API key provided. Application not found.");
        return {HTTP::Status::Code::S_401_UNAUTHORIZED, "invalid_api_key", "The provided API key is invalid or unauthorized."};
    }

    std::optional<IdentityManager::Applications::ApplicationAttributes> attribs = identityManager->applications->getApplicationAttributes(appName);
    if (!attribs.has_value())
    {
        // app key not found...
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "Internal Error While reading the APP '%s' Attributes.", appName.c_str());
        return {HTTP::Status::Code::S_401_UNAUTHORIZED, "invalid_app", "Internal Error While reading the APP Attributes."};
    }

    Json::Value payloadOut;

    //  Configuration parameters:
    boost::property_tree::ptree config = Globals::pConfig;

    std::string logoutURL = attribs->useEmbeddedAuthentication ? "/login/logout/" : config.get<std::string>("AppVars.LoginPortalURL", "about:blank") + "/logout/";
    payloadOut["url"] = logoutURL;
    payloadOut["appName"] = appName;

    return payloadOut;
}
