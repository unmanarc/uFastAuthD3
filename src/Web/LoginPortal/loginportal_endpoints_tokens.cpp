#include "Mantids30/Program_Logs/loglevels.h"
#include "defs.h"
#include "loginportal_endpoints.h"
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

/*
    This will tranform the current authentication into the login token for an APP first access...
*/
API::APIReturn LoginPortal_Endpoints::token(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    IdentityManager *identityManager = Globals::getIdentityManager();

    std::string authenticatedUser = request.jwtToken->getSubject();

    bool useEmbeddedAuthentication = false;
    bool keepAuthenticated = JSON_ASBOOL_D(request.jwtToken->getClaim("keepAuthenticated"), false);
    std::string activity = JSON_ASSTRING(*request.inputJSON, "activity", "");       // APP ACTIVITY NAME.
    std::string redirectURI = JSON_ASSTRING(*request.inputJSON, "redirectURI", ""); // APP REDIRECT URI.
    uint32_t schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", 0);             // APP SCHEME ID.
    bool mock = JSON_ASBOOL(*request.inputJSON, "mock", false);                     // MOCK

    // Determine appName: prioritize x-api-key header, fallback to inputJSON "app" field
    std::string apiKey = request.clientRequest->getHeaderOption("x-api-key");
    std::string appName;
    if (!apiKey.empty())
    {
        appName = identityManager->applications->getApplicationNameByAPIKey(apiKey);
        if (appName.empty())
        {
            LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "Invalid API key provided. Application not found.");
            return {HTTP::Status::Code::S_401_UNAUTHORIZED, "invalid_api_key", "The provided API key is invalid or unauthorized."};
        }

        // Check if the application has embedded authentication enabled
        std::optional<IdentityManager::Applications::ApplicationAttributes> appAttrs = identityManager->applications->getApplicationAttributes(appName);

        if (!appAttrs.has_value())
        {
            LOG_APP->log2(__func__, appName, authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "Application attributes not found for app: %s", appName.c_str());
            return {HTTP::Status::Code::S_404_NOT_FOUND, "not_found", "Application not found."};
        }
        if (!appAttrs.value().useEmbeddedAuthentication)
        {
            LOG_APP->log2(__func__, appName, authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "API key access attempted for non-embedded application. App: %s", appName.c_str());
            return {HTTP::Status::Code::S_403_FORBIDDEN, "security_error", "Application does not support embedded authentication via API key."};
        }
        useEmbeddedAuthentication = true;
    }
    else
    {
        useEmbeddedAuthentication = false;
        appName = JSON_ASSTRING(*request.inputJSON, "app", "");
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// -------------------------     TOKEN VALIDATION       --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    if (!token_validateJwtClaims(request.jwtToken, authenticatedUser, authClientDetails.ipAddress))
    {
        return {HTTP::Status::Code::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                authResultToString(AuthenticationResult::UNAUTHENTICATED)};
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// -------------------------        AUTHENTICATION      --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    // Validate authentication scheme

    if (activity == "LOGIN")
    {
        if (!token_validateAuthenticationScheme(request.jwtToken, IAM_LOGINPORTAL_APPNAME, "LOGIN", schemeId, authenticatedUser, authClientDetails.ipAddress))
        {
            return {HTTP::Status::Code::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                    authResultToString(AuthenticationResult::UNAUTHENTICATED)};
        }
    }
    else
    {
        if (!token_validateAuthenticationScheme(request.jwtToken, appName, activity, schemeId, authenticatedUser, authClientDetails.ipAddress))
        {
            return {HTTP::Status::Code::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                    authResultToString(AuthenticationResult::UNAUTHENTICATED)};
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// ---------------------------    ACCOUNT VALIDATIONS   --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    AuthenticationResult r;
    if (!identityManager->isAccountActiveAndValidForApp(authenticatedUser, appName, r, true))
    {
        // This token is not available for retrieving app tokens because the user does not have a valid account with the specified application.
        const char *reasonText = authResultToString(r);
        LOG_APP->log2(__func__, authenticatedUser, authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT,
                      "Token request denied: User '%s' attempted to obtain an access token for app '%s', but the account is not valid or authorized for this application. Reason: %s.",
                      authenticatedUser.c_str(), appName.c_str(), reasonText);
        return {HTTP::Status::Code::S_401_UNAUTHORIZED, "AUTH_ERR_INVALID_ACCT", authResultToString(r)};
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// ---------------------------   REDIRECT VALIDATIONS   --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////

    if (redirectURI.empty())
    {
        redirectURI = identityManager->applications->getWebLoginDefaultRedirectURIForApplication(appName);
    }

    if (!token_validateRedirectURI(appName, redirectURI, authenticatedUser, authClientDetails.ipAddress))
    {
        return {HTTP::Status::Code::S_406_NOT_ACCEPTABLE, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::BAD_PARAMETERS)), "Invalid Redirect URI"};
    }

    if (mock)
    {
        return response;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// -------------------------       TOKEN CREATION       --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    // Create and sign tokens
    if (!token_createAndSignApplicationRefreshAndAccessJWTs(request.jwtToken, useEmbeddedAuthentication, keepAuthenticated, appName, authenticatedUser, schemeId, redirectURI, response,
                                                            authClientDetails))
    {
        // Failed to create the token...
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::INTERNAL_ERROR)),
                authResultToString(AuthenticationResult::INTERNAL_ERROR)};
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// ----------------------       KEEP AUTHENTICATION       ------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    if (keepAuthenticated == false)
    {
        // Discard access cookies upon first use. (Access tokens are short-lived, but should be discarded after the first usage)
        deleteLoginCookies(context, request, authClientDetails, &response);
    }

    return response;
}
