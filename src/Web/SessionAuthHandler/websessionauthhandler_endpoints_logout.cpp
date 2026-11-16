#include "websessionauthhandler_endpoints.h"

#include <Mantids30/Runtime/Logs/loglevels.h>
#include <Mantids30/Protocol/HTTP/httpv1_base.h>
#include <Mantids30/DataFormat/JSON/json.h>
#include <Mantids30/Core/Helpers/encoders.h>
#include <Mantids30/DataFormat/JSON/json.h>

#include <boost/algorithm/string/join.hpp>

#include "globals.h"

using namespace Mantids30;
using namespace Mantids30::Protocol::HTTP;
using namespace Mantids30::DataFormat;
using namespace Mantids30::Runtime;
using namespace Mantids30::Server::WebRESTFul::RESTful;
using namespace Mantids30::Protocol;

// Helper to set delete cookies for logout
static void setLogoutCookies(APIReturn &response, const ApplicationAuthSettings &tokenProps)
{
    // Clear AccessToken
    response.cookiesMap["AccessToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["AccessToken"].deleteCookie();
    response.cookiesMap["AccessToken"].path = DataFormat::JSON::ASSTRING(DataFormat::JSON::MEMBER_OR_NULL(tokenProps.tokensConfiguration, "accessToken"), "path", "/");

    // Clear RefreshToken
    response.cookiesMap["RefreshToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["RefreshToken"].deleteCookie();
    response.cookiesMap["RefreshToken"].path = DataFormat::JSON::ASSTRING(DataFormat::JSON::MEMBER_OR_NULL(tokenProps.tokensConfiguration, "refreshToken"), "path", "/auth");

    // Clear RefreshTokenId
    response.cookiesMap["RefreshTokenId"] = HTTP::Headers::Cookie();
    response.cookiesMap["RefreshTokenId"].deleteCookie();
    response.cookiesMap["RefreshTokenId"].path = DataFormat::JSON::ASSTRING(DataFormat::JSON::MEMBER_OR_NULL(tokenProps.tokensConfiguration, "refreshToken"), "path", "/auth");

    // Clear SessionPublicData
    response.cookiesMap["SessionPublicData"] = HTTP::Headers::Cookie();
    response.cookiesMap["SessionPublicData"].deleteCookie();
    response.cookiesMap["SessionPublicData"].path = "/";
}

APIReturn WebSessionAuthHandler_Endpoints::appLogout(void *context, const RequestContext &request, IdentityManager::ClientDetails &authClientDetails)
{
    // Helper to extract common request parameters safely
    APIReturn response;
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
    ApplicationAuthSettings tokenProps = identityManager->applications->getAuthSettingsFromApplication(appName);

    // 5. Clear Cookies
    setLogoutCookies(response, tokenProps);

    std::string sessionPublicData = request.clientRequest->getCookie("SessionPublicData");
    std::string user;
    if (!sessionPublicData.empty())
    {
        std::string decoded = Mantids30::Core::Helpers::Encoders::decodeFromBase64(sessionPublicData);
        boost::json::value jSessionPublicData;
        std::string errors;
        if (Mantids30::DataFormat::JSON::parse(decoded, jSessionPublicData, &errors))
        {
            user = Mantids30::DataFormat::JSON::ASSTRING(jSessionPublicData, "user", "");
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
    APIReturn response;
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

    //  Configuration parameters:
    boost::property_tree::ptree config = Globals::pConfig;
    std::string logoutURL = attribs->useEmbeddedInPortalAuthentication ? "/login/logout/" : config.get<std::string>("AppVars.LoginPortalURL", "about:blank") + "/logout/";

    return boost::json::value(boost::json::object{
        {"url",     logoutURL},
        {"appName", appName},
    });
}
