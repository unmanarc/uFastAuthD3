#include "globals.h"
#include "loginportal_endpoints.h"
#include <Mantids30/Helpers/encoders.h>
#include <Mantids30/Helpers/json.h>
#include <boost/algorithm/string/replace.hpp>
#include <json/value.h>
#include <json/writer.h>

using namespace Mantids30;
using namespace API::RESTful;
using namespace Network::Protocol;

// Get the application token...

std::regex LoginPortal_Endpoints::originPattern = std::regex("^(https?://[^/]+)");
using namespace Mantids30;
using namespace Mantids30::Program;
using namespace Mantids30::API::RESTful;
using namespace Mantids30::Network::Protocol;
using namespace Mantids30::DataFormat;

bool LoginPortal_Endpoints::retrieveAndValidateAppOrigin(HTTPv1_Base::Request *request, const std::string &appName, const OriginSource &originSource)
{
    std::set<std::string> origins = Globals::getIdentityManager()->applications->listWebLoginOriginUrlsFromApplication(appName);

    std::string currentOrigin;
    if (originSource == OriginSource::HTTP_HEADER_ORIGIN)
    {
        currentOrigin = request->getHeaderOption("Origin");
    }
    else if (originSource == OriginSource::HTTP_HEADER_REFERER)
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

HTTP::Status::Code LoginPortal_Endpoints::handleLogoutDynamicRequest(const std::string &urlPostfix, HTTPv1_Base::Request *request, HTTPv1_Base::Response *response, const std::shared_ptr<void> &)
{
    if (request->requestLine.getHTTPMethod() != "POST")
    {
        return HTTP::Status::Code::S_400_BAD_REQUEST;
    }

    // Determine appName: prioritize x-api-key header, fallback to "app" POST field
    std::string apiKey = request->getHeaderOption("x-api-key");
    bool dontUseOriginValidation = false;
    std::string appName;
    if (!apiKey.empty())
    {
        appName = Globals::getIdentityManager()->applications->getApplicationNameByAPIKey(apiKey);
        if (appName.empty())
        {
            LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LogLevel::SECURITY_ALERT, "Invalid API key provided. Application not found.");
            API::APIReturn response;
            return HTTP::Status::Code::S_401_UNAUTHORIZED;
        }
        dontUseOriginValidation = true;
    }
    else
    {
        appName = request->getVarsBySource(HTTP::Source::POST)->getStringValue("appName");
        dontUseOriginValidation = false;
    }

    std::string sessionPublicData = request->getVarsBySource(HTTP::Source::POST)->getStringValue("sessionPublicData");

    Json::Value jSessionPublicData;
    if (!sessionPublicData.empty())
    {
        std::string decoded = Mantids30::Helpers::Encoders::decodeFromBase64(sessionPublicData);
        Json::CharReaderBuilder readerBuilder;
        std::string errors;

        // 3. Create the CharReader via CharReaderBuilder
        Json::CharReaderBuilder builder;
        const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());

        // 4. Parse the string
        bool parsingSuccessful = reader->parse(decoded.c_str(), decoded.c_str() + decoded.length(), &jSessionPublicData, &errors);

        // 5. Check for errors and extract data
        if (!parsingSuccessful)
        {
            LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LogLevel::SECURITY_ALERT, "Failed to parse sessionPublicData: %s", errors.c_str());
            return HTTP::Status::Code::S_400_BAD_REQUEST;
        }
    }

    // if the cookie does not exist, it's a non-persistent login session.
    std::string defaultAPPCallback = Globals::getIdentityManager()->applications->getApplicationCallbackURI(appName);

    Json::Value v;
    v["appName"] = appName;
    v["sessionPublicData"] = jSessionPublicData;
    v["defaultCallbackURL"] = defaultAPPCallback;

    Json::StreamWriterBuilder builder;
    builder.settings_["indentation"] = "";
    std::string xstrValue = Json::writeString(builder, v);

    std::regex appRegex("^[a-zA-Z0-9\\_]+$");

    if (!std::regex_match(appName, appRegex))
    {
        LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LogLevel::SECURITY_ALERT, "Invalid APP Name '%s' ", appName.c_str());

        return HTTP::Status::Code::S_400_BAD_REQUEST;
    }

    std::string page;

    page = R"(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logging Out</title>
    <style>
        *, *::before, *::after {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        html, body {
            height: 100%;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: #e8e8e8;
        }

        body {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .card {
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            padding: 48px 56px;
            text-align: center;
            max-width: 420px;
        }

        .spinner {
            width: 48px;
            height: 48px;
            margin: 0 auto 24px;
            border: 4px solid #e0e0e0;
            border-top-color: #757575;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        h1 {
            font-size: 1.5rem;
            font-weight: 400;
            color: #424242;
            margin-bottom: 8px;
        }

        p {
            font-size: 0.95rem;
            color: #757575;
        }
    </style>
    <script src="../assets/js/jquery.min.js" type="text/javascript"></script>
    <script>
    let data=DEFAULTAPPCALLBACK_PLACEHOLDER;
    </script>
    <script src="../assets/js/logout.js" type="text/javascript"></script>
</head>
<body>
    <main class="card">
        <div class="spinner"></div>
        <h1>Logging Out</h1>
        <p>Your session is being terminated securely. Please wait...</p>
    </main>
</body>
</html>
)";

    // Replace placeholder with the actual default callback URL
    boost::replace_all(page, "DEFAULTAPPCALLBACK_PLACEHOLDER", xstrValue);

    bool originValidated = dontUseOriginValidation || retrieveAndValidateAppOrigin(request, appName, OriginSource::HTTP_HEADER_ORIGIN);
    std::string currentOrigin = request->getHeaderOption("Origin");

    if (!originValidated)
    {
        LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LogLevel::SECURITY_ALERT, "Not allowed origin '%s' for application '%s'", currentOrigin.c_str(), appName.c_str());
        return HTTP::Status::Code::S_403_FORBIDDEN;
    }

    LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LogLevel::DEBUG, "Logout requested from application '%s' with origin '%s'", appName.c_str(), currentOrigin.c_str());
    response->content.writer()->writeString(page);
    response->setContentType("text/html");

    return HTTP::Status::Code::S_200_OK;
}

API::APIReturn LoginPortal_Endpoints::logout(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    deleteLoginCookies(context, request, authClientDetails, &response);
    return response;
}
