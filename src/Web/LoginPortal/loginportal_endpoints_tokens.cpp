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
using namespace Network::Protocols;


/*
    This will tranform the current authentication into an APP access...
*/
API::APIReturn LoginPortal_Endpoints::token(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    IdentityManager *identityManager = Globals::getIdentityManager();

    std::string authenticatedUser = request.jwtToken->getSubject();
    bool keepAuthenticated = JSON_ASBOOL_D(request.jwtToken->getClaim("keepAuthenticated"), false);

    std::string activity = JSON_ASSTRING(*request.inputJSON, "activity", "");       // APP ACTIVITY NAME.
    std::string redirectURI = JSON_ASSTRING(*request.inputJSON, "redirectURI", ""); // APP REDIRECT URI.
    std::string appName = JSON_ASSTRING(*request.inputJSON, "app", "");             // APP NAME.
    uint32_t schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", 0);             // APP SCHEME ID.
    bool mock = JSON_ASBOOL(*request.inputJSON, "mock", false);             // MOCK

    //////////////////////////////////////////////////////////////////////////////////////////
    //// -------------------------     TOKEN VALIDATION       --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    if (!token_validateJwtClaims(request.jwtToken, authenticatedUser, authClientDetails.ipAddress))
    {
        response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                          authResultToString(AuthenticationResult::UNAUTHENTICATED));
        return response;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// -------------------------        AUTHENTICATION      --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    // Validate authentication scheme

    if (activity == "LOGIN")
    {
        if (!token_validateAuthenticationScheme( request.jwtToken, IAM_LOGINPORTAL_APPNAME, "LOGIN" , schemeId, authenticatedUser, authClientDetails.ipAddress))
        {
            response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                              authResultToString(AuthenticationResult::UNAUTHENTICATED));
            return response;
        }
    }
    else
    {
        if (!token_validateAuthenticationScheme( request.jwtToken, appName, activity, schemeId, authenticatedUser, authClientDetails.ipAddress))
        {
            response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                              authResultToString(AuthenticationResult::UNAUTHENTICATED));
            return response;
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
        LOG_APP->log2(__func__, authenticatedUser, authClientDetails.ipAddress, Logs::LEVEL_SECURITY_ALERT,
                      "Token request denied: User '%s' attempted to obtain an access token for app '%s', but the account is not valid or authorized for this application. Reason: %s.",
                      authenticatedUser.c_str(), appName.c_str(), reasonText);
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_INVALID_ACCT", authResultToString(r));
        return response;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //// ---------------------------   REDIRECT VALIDATIONS   --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////

    if (redirectURI.empty())
    {
        redirectURI = identityManager->applications->getWebLoginDefaultRedirectURIForApplication(appName);
    }

    if (!token_validateRedirectURI( appName, redirectURI, authenticatedUser, authClientDetails.ipAddress))
    {
        response.setError(HTTP::Status::S_406_NOT_ACCEPTABLE, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::BAD_PARAMETERS)), "Invalid Redirect URI");
        return response;
    }

    if (mock)
        return response;

    //////////////////////////////////////////////////////////////////////////////////////////
    //// -------------------------       TOKEN CREATION       --------------------------- ////
    //////////////////////////////////////////////////////////////////////////////////////////
    // Create and sign tokens
    if (!token_createAndSignApplicationAccessJWTs( request.jwtToken, keepAuthenticated, appName, authenticatedUser, schemeId, redirectURI, response, authClientDetails))
    {
        // Failed to create the token...
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::INTERNAL_ERROR)),
                          authResultToString(AuthenticationResult::INTERNAL_ERROR));
        return response;
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
