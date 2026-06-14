#include "loginportal_endpoints.h"

#include "globals.h"
#include "json/value.h"

using namespace Mantids30;
using namespace Mantids30::Program;
using namespace Mantids30::API::RESTful;
using namespace Mantids30::Network::Protocols;
using namespace Mantids30::DataFormat;

void LoginPortal_Endpoints::addEndpoints(std::shared_ptr<Endpoints> endpoints)
{
    using SecurityOptions = Mantids30::API::RESTful::Endpoints::SecurityOptions;

    // AUTHENTICATION FUNCTIONS:

    // Web triggered events:
    // TODO: cuando requiere REQUIRE_JWT_COOKIE_AUTH implica que necesita validar que la aplicación sea la correcta (configurada)
    endpoints->addEndpoint(Endpoints::POST, "preAuthorize", SecurityOptions::NO_AUTH, {}, nullptr, &preAuthorize);

    endpoints->addEndpoint(Endpoints::POST, "authorize", SecurityOptions::NO_AUTH, {}, nullptr, &authorize);

    // Transform the current authentication to the app authentication...
    endpoints->addEndpoint(Endpoints::POST, "token", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &token);

    // Logout only clear the cookie... it just does need a CSRF control method...
    endpoints->addEndpoint(Endpoints::POST, "logout", SecurityOptions::NO_AUTH, {}, nullptr, &logout);

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
    endpoints->addEndpoint(Endpoints::PUT, "changeCredential", SecurityOptions::NO_AUTH, {}, nullptr, &changeCredential);

    endpoints->addEndpoint(Endpoints::GET, "getAppDescription", SecurityOptions::NO_AUTH, {}, nullptr, &getAppDescription);

    endpoints->addEndpoint(Endpoints::GET, "getLoginMode", SecurityOptions::NO_AUTH, {}, nullptr, &getLoginMode);

    // Temporal tokens are also given trough an intermediate window...
    //endpoints->addEndpoint(Endpoints::POST, "tempMFAToken", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr,&tempMFAToken);
}

LoginPortal_Endpoints::APIReturn LoginPortal_Endpoints::getLoginMode(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    Json::Value r;
    // Get the identity manager from global settings to handle authentication.
    IdentityManager *identityManager = Globals::getIdentityManager();

    // Determine appName: prioritize x-api-key header, fallback to inputJSON "app" field
    std::string apiKey = request.clientRequest->getHeaderOption("x-api-key");
    std::string appName;
    if (!apiKey.empty())
    {
        appName = identityManager->applications->getApplicationNameByAPIKey(apiKey);
        if (appName.empty())
        {
            LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid API key provided. Application not found.");
            API::APIReturn response;
            response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_api_key", "The provided API key is invalid or unauthorized.");
            return response;
        }
        r["mode"] = "EMBEDDED";
    }
    else
    {
        appName = request.clientRequest->getVars(HTTP::VARS_GET)->getTValue<std::string>("app");
        r["mode"] = "DOMAIN";
    }

    r["app"]["name"] = appName;
    r["app"]["description"] = identityManager->applications->getApplicationDescription(appName);
    return r;
}

LoginPortal_Endpoints::APIReturn LoginPortal_Endpoints::getAppDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    // Get the identity manager from global settings to handle authentication.
    IdentityManager *identityManager = Globals::getIdentityManager();

    // Determine appName: prioritize x-api-key header, fallback to inputJSON "app" field
    std::string apiKey = request.clientRequest->getHeaderOption("x-api-key");
    std::string appName;
    if (!apiKey.empty())
    {
        appName = identityManager->applications->getApplicationNameByAPIKey(apiKey);
        if (appName.empty())
        {
            LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT, "Invalid API key provided. Application not found.");
            API::APIReturn response;
            response.setError(HTTP::Status::S_401_UNAUTHORIZED, "invalid_api_key", "The provided API key is invalid or unauthorized.");
            return response;
        }
    }
    else
    {
        appName = JSON_ASSTRING(*request.inputJSON, "app", "");
    }

    json r;
    r["description"] = identityManager->applications->getApplicationDescription(appName);
    return r;
}
