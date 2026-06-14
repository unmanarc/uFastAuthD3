#include "globals.h"
#include "loginportal_endpoints.h"
#include <Mantids30/Helpers/json.h>
#include <boost/algorithm/string/replace.hpp>

using namespace Mantids30;
using namespace API::RESTful;
using namespace Network::Protocols;

// Get the application token...

std::regex LoginPortal_Endpoints::originPattern = std::regex("^(https?://[^/]+)");
using namespace Mantids30;
using namespace Mantids30::Program;
using namespace Mantids30::API::RESTful;
using namespace Mantids30::Network::Protocols;
using namespace Mantids30::DataFormat;


bool LoginPortal_Endpoints::retrieveAndValidateAppOrigin(HTTPv1_Base::Request *request, const std::string &appName, const OriginSource &originSource)
{
    std::set<std::string> origins = Globals::getIdentityManager()->applications->listWebLoginOriginUrlsFromApplication(appName);

    std::string currentOrigin;
    if (originSource == USING_HEADER_ORIGIN)
    {
        currentOrigin = request->getHeaderOption("Origin");
    }
    else if (originSource == USING_HEADER_REFERER)
    {
        std::string referer = request->getHeaderOption("Referer");
        std::smatch matches;
        if (std::regex_search(referer, matches, originPattern) && matches.size() > 1)
        {
            currentOrigin = matches[1].str(); // Extrae solo la parte del dominio y el esquema.
        }
    }

    // Validate the origin...
    return origins.count(currentOrigin);
}

HTTP::Status::Codes LoginPortal_Endpoints::handleLogoutDynamicRequest(const std::string &urlPostfix, HTTPv1_Base::Request *request, HTTPv1_Base::Response *response, std::shared_ptr<void>)
{
    if (request->requestLine.getHTTPMethod() != "POST")
        return HTTP::Status::S_400_BAD_REQUEST;


    // Determine appName: prioritize x-api-key header, fallback to "app" POST field
    std::string apiKey = request->getHeaderOption("x-api-key");
    bool dontUseOriginValidation = false;
    std::string appName;
    if (!apiKey.empty())
    {
        appName = Globals::getIdentityManager()->applications->getApplicationNameByAPIKey(apiKey);
        if (appName.empty())
        {
            LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LEVEL_SECURITY_ALERT,
                          "Invalid API key provided. Application not found.");
            API::APIReturn response;
            return HTTP::Status::S_401_UNAUTHORIZED;
        }
        dontUseOriginValidation = true;
    }
    else
    {
        appName = request->getVars(HTTP::VARS_POST)->getStringValue("appName");
        dontUseOriginValidation = false;
    }


    std::string keepAuthentication = request->getVars(HTTP::VARS_POST)->getStringValue("keepAuthentication");

    // if the cookie does not exist, it's a non-persistent login session.
    std::string defaultAPPCallback = Globals::getIdentityManager()->applications->getApplicationCallbackURI(appName);

    Json::Value v;
    v["appName"] = appName;
    v["keepAuthentication"] = keepAuthentication;
    v["defaultCallbackURL"] = defaultAPPCallback;

    Json::StreamWriterBuilder builder;
    builder.settings_["indentation"] = "";
    std::string xstrValue = Json::writeString(builder, v);

    std::regex appRegex("^[a-zA-Z0-9\\_]+$");

    if (!std::regex_match(appName, appRegex))
    {
        LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LEVEL_SECURITY_ALERT,
                      "Invalid APP Name '%s' ", appName.c_str());

        return HTTP::Status::S_400_BAD_REQUEST;
    }

    std::string page;

    page = R"(
<HTML>
<head>
    <script src="../assets/js/jquery.min.js" type="text/javascript"></script>
    <script>
    let data=DEFAULTAPPCALLBACK_PLACEHOLDER;
    </script>
    <script src="../assets/js/logout.js" type="text/javascript"></script>
</head>
<body>
    <h1>Logging out...</h1>
</body>
</HTML>
)";

    // Replace placeholder with the actual default callback URL
    boost::replace_all(page, "DEFAULTAPPCALLBACK_PLACEHOLDER", xstrValue);

    bool originValidated = dontUseOriginValidation || retrieveAndValidateAppOrigin(request, appName, USING_HEADER_ORIGIN);
    std::string currentOrigin = request->getHeaderOption("Origin");

    if (!originValidated)
    {
        LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LEVEL_SECURITY_ALERT, "Not allowed origin '%s' for application '%s'", currentOrigin.c_str(), appName.c_str());
        return HTTP::Status::S_403_FORBIDDEN;
    }

    LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LEVEL_DEBUG, "Logout requested from application '%s' with origin '%s'", appName.c_str(), currentOrigin.c_str());
    response->content.writer()->writeString(page);
    response->setContentType("text/html");

    return HTTP::Status::S_200_OK;
}

API::APIReturn LoginPortal_Endpoints::logout(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    deleteLoginCookies(context,request,authClientDetails,&response);
    return response;
}

