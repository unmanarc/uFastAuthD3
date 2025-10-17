#include "weblogin_add_endpoints.h"

#include <Mantids30/DataFormat_JWT/jwt.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Helpers/random.h>
#include <Mantids30/Program_Logs/applog.h>
#include <Mantids30/Program_Logs/loglevels.h>
#include <Mantids30/Protocol_HTTP/hdr_cookie.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>
#include <Mantids30/Protocol_HTTP/rsp_status.h>

#include <boost/algorithm/string.hpp>
#include <json/value.h>
#include <string>

#include "../globals.h"
#include "logindirectorymanager.h"

using namespace Mantids30;
using namespace Mantids30::Program;
using namespace Mantids30::API::RESTful;
using namespace Mantids30::Network::Protocols;
using namespace Mantids30::DataFormat;

std::regex WebLogin_AuthMethods::originPattern = std::regex("^(https?://[^/]+)");

void WebLogin_AuthMethods::addEndpoints(std::shared_ptr<Endpoints> endpoints)
{
    using SecurityOptions = Mantids30::API::RESTful::Endpoints::SecurityOptions;

    // AUTHENTICATION FUNCTIONS:

    // Web triggered events:
    // TODO: cuando requiere REQUIRE_JWT_COOKIE_AUTH implica que necesita validar que la aplicación sea la correcta (configurada)
    endpoints->addEndpoint(Endpoints::POST, "preAuthorize",  SecurityOptions::NO_AUTH, {}, nullptr, &preAuthorize);

    endpoints->addEndpoint(Endpoints::POST, "authorize",     SecurityOptions::NO_AUTH, {}, nullptr, &authorize);

    // Transform the current authentication to the app authentication...
    endpoints->addEndpoint(Endpoints::POST, "token",         SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &token);

    // Logout only clear the cookie... it just does need a CSRF control method...
    endpoints->addEndpoint(Endpoints::POST, "logout",        SecurityOptions::NO_AUTH, {}, nullptr, &logout);

    // Account registration:
    //endpoints->addEndpoint(Endpoints::POST, "registerAccount", nullptr, SecurityOptions::NO_AUTH, {}, nullptr, &registerAccount);

    // When requested by an external webste, no CSRF challenge could be sent by an external website... So your access token will be used to authenticate the refreshal...
    // In this premise, the refresher cookie is not know by your website (so if your website leaks the data),
    //   will not leak the master authentication cookie (refresher token) that can go to any application under your name.
    //   so... with this accessToken, you can renew, but what if the accessToken is compromised? well...
    //   the only thing you want to do is to limit the amount of time of that access...
    //   then... we should implement some kind of anti-CSRF, tokens are discarded because they are in the same domain of the access token (the browser)
    //   and... what you can do is: to validate the origin/referer.

    // Post-authenticated API:
    //endpoints->addEndpoint(Endpoints::POST, "retokenize", nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &retokenize);
    endpoints->addEndpoint(Endpoints::PUT, "changeCredential",             SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &changeCredential);
    endpoints->addEndpoint(Endpoints::GET, "listCredentials",              SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &listCredentials);
    endpoints->addEndpoint(Endpoints::GET, "accountCredentialPublicData",  SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &accountCredentialPublicData);
    endpoints->addEndpoint(Endpoints::GET, "getSessionInfo",               SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &getSessionInfo);

    // Temporal tokens are also given trough an intermediate window...
    //endpoints->addEndpoint(Endpoints::POST, "tempMFAToken", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr,&tempMFAToken);
    //    endpoints->addEndpoint("addAccount",{&addAccount,auth});
}

bool WebLogin_AuthMethods::retrieveAndValidateAppOrigin(HTTPv1_Base::Request *request, const std::string &appName, const OriginSource &originSource)
{
    auto origins = Globals::getIdentityManager()->applications->listWebLoginOriginUrlsFromApplication(appName);

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
    bool originValidated = false;
    for (const auto &origin : origins)
    {
        if (currentOrigin == origin)
        {
            originValidated = true;
            break;
        }
    }
    return originValidated;
}

// Handle personalized login forms:
HTTP::Status::Codes WebLogin_AuthMethods::handleLoginDynamicRequest(const std::string &appName, HTTPv1_Base::Request *request, HTTPv1_Base::Response *response, std::shared_ptr<void>)
{
    std::string page;
    LoginDirectoryManager::ErrorCode status = Globals::getLoginDirManager()->retrieveFile(appName, page);
    bool originValidated = retrieveAndValidateAppOrigin(request, appName, USING_HEADER_REFERER);
    auto currentOrigin = request->getHeaderOption("Origin");

    if (!originValidated)
    {
        LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LEVEL_SECURITY_ALERT, "Not allowed origin '%s' for application '%s'", currentOrigin.c_str(), appName.c_str());

        return HTTP::Status::S_403_FORBIDDEN;
    }

    if (status != LoginDirectoryManager::ErrorCode::SUCCESS)
    {
        LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LEVEL_WARN, "Failed to obtain the HTML for application '%s': %s", appName.c_str(),
                      LoginDirectoryManager::getErrorMessage(status).c_str());
        return HTTP::Status::S_404_NOT_FOUND;
    }

    LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LEVEL_INFO, "HTML Login for application '%s' requested from '%s'", appName.c_str(), currentOrigin.c_str());

    response->content.writer()->writeString(page);
    response->setContentType("text/html");

    return HTTP::Status::S_200_OK;
}

