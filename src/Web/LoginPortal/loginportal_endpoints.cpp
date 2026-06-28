#include "loginportal_endpoints.h"

#include <Mantids30/Protocol_HTTP/httpv1_base.h>
#include "globals.h"
#include "json/value.h"

using namespace Mantids30;
using namespace Mantids30::Program;
using namespace Mantids30::API::RESTful;
using namespace Mantids30::Network::Protocol;
using namespace Mantids30::DataFormat;

void LoginPortal_Endpoints::addEndpoints(const std::shared_ptr<Endpoints> &endpoints)
{
    using SecurityRequirements = API::Security::Requirements;

    // AUTHENTICATION FUNCTIONS:

    // Web triggered events:
    // TODO: cuando requiere JWT_COOKIE_AUTH implica que necesita validar que la aplicación sea la correcta (configurada)
    endpoints->addEndpoint(HTTP::Method::POST, "preAuthorize", SecurityRequirements::NONE, {}, nullptr, &preAuthorize);

    endpoints->addEndpoint(HTTP::Method::POST, "authorize", SecurityRequirements::NONE, {}, nullptr, &authorize);

    // Transform the current authentication to the app authentication...
    endpoints->addEndpoint(HTTP::Method::POST, "token", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &token);

    // Logout only clear the cookie... it just does need a CSRF control method...
    endpoints->addEndpoint(HTTP::Method::POST, "logout", SecurityRequirements::NONE, {}, nullptr, &logout);

    // Account registration:
    //endpoints->addEndpoint(HTTP::Method::POST, "registerAccount", nullptr, SecurityRequirements::NONE, {}, nullptr, &registerAccount);

    // When requested by an external webste, no CSRF challenge could be sent by an external website... So your access token will be used to authenticate the refreshal...
    // In this premise, the refresher cookie is not know by your website (so if your website leaks the data),
    //   will not leak the master authentication cookie (refresher token) that can go to any application under your name.
    //   so... with this accessToken, you can renew, but what if the accessToken is compromised? well...
    //   the only thing you want to do is to limit the amount of time of that access...
    //   then... we should implement some kind of anti-CSRF, tokens are discarded because they are in the same domain of the access token (the browser)
    //   and... what you can do is: to validate the origin/referer.

    // Post-authenticated API:
    //endpoints->addEndpoint(HTTP::Method::POST, "retokenize", nullptr, SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &retokenize);
    endpoints->addEndpoint(HTTP::Method::PUT, "changeCredential", SecurityRequirements::NONE, {}, nullptr, &changeCredential);
    endpoints->addEndpoint(HTTP::Method::GET, "getApplicationLoginPublicData", SecurityRequirements::NONE, {}, nullptr, &getApplicationLoginPublicData);

    // Temporal tokens are also given trough an intermediate window...
    //endpoints->addEndpoint(HTTP::Method::POST, "tempMFAToken", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr,&tempMFAToken);
}

LoginPortal_Endpoints::APIReturn LoginPortal_Endpoints::getApplicationLoginPublicData(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    Json::Value r;
    // Get the identity manager from global settings to handle authentication.

    // Determine appName: prioritize x-api-key header, fallback to inputJSON "app" field
    std::string apiKey = request.clientRequest->getHeaderOption("x-api-key");
    std::string appName;
    if (!apiKey.empty())
    {
        appName = Globals::getIdentityManager()->applications->getApplicationNameByAPIKey(apiKey);
        if (appName.empty())
        {
            LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "Invalid API key provided. Application not found.");
            return {HTTP::Status::Code::S_401_UNAUTHORIZED, "invalid_api_key", "The provided API key is invalid or unauthorized."};
        }
        r["mode"] = "EMBEDDED";
    }
    else
    {
        appName = request.clientRequest->getVarsBySource(HTTP::Source::GET)->getTValue<std::string>("app");
        r["mode"] = "DOMAIN";
    }


    ApplicationTokenProperties tokenProps = Globals::getIdentityManager()->applications->getWebLoginJWTConfigFromApplication(appName);
    //x.sessionInactivityTimeout

    r["app"]["name"] = appName;
    r["app"]["description"] = Globals::getIdentityManager()->applications->getApplicationDescription(appName);
    r["app"]["session"]["useSessionCookiesByDefault"] = JSON_ASBOOL(tokenProps.tokensConfiguration["accessToken"], "useSessionCookiesByDefault", true);

    return r;
}
