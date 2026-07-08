#include "websessionauthhandler_endpoints.h"

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

#include "IdentityManager/ds_authentication.h"
#include "globals.h"
#include <Mantids30/API_EndpointsAndSessions/api_options_handler.h>

using namespace Mantids30;
using namespace Mantids30::Program;
using namespace Mantids30::API::RESTful;
using namespace Mantids30::Network::Protocol;
using namespace Mantids30::DataFormat;

void WebSessionAuthHandler_Endpoints::addEndpoints(const std::shared_ptr<Endpoints> &endpoints)
{
    using SecurityRequirements = API::Security::Requirements;

    endpoints->addEndpoint(HTTP::Method::GET, "getLogoutCallbackURL", SecurityRequirements::NONE, {}, nullptr, &getLogoutCallbackURL);
    endpoints->addEndpoint(HTTP::Method::POST, "refreshAccessToken", SecurityRequirements::NONE, {}, nullptr, &refreshAccessToken);                      // Using refresh token auth.
    endpoints->addEndpoint(HTTP::Method::GET, "getApplicationPublicData", SecurityRequirements::NONE, {}, nullptr, &getApplicationPublicData); // Using refresh token auth.
    endpoints->addEndpoint(HTTP::Method::GET, "getUserPublicData", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &getUserPublicData);              // Using refresh token auth.
    endpoints->addEndpoint(HTTP::Method::POST, "logout", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &appLogout);
    endpoints->addEndpoint(HTTP::Method::POST, "callback", SecurityRequirements::NONE, {}, nullptr, &callback);
    endpoints->setEndpointOptions("callback", API::OptionsHandlerConfig().insertAllowedOrigin(Globals::pConfig.get<std::string>("AppVars.LoginPortalURL", "")).setAllowCredentials(true));
}

HTTP::Status::Code WebSessionAuthHandler_Endpoints::handleRetokenizeHTML(const std::string &urlPostfix, HTTPv1_Base::Request *request, HTTPv1_Base::Response *response, const std::shared_ptr<void> &)
{
    std::string page;
    page = R"(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Refreshing Session</title>
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
    <script src="../assets/js/auth.js" type="text/javascript"></script>
    <script>
        retokenizeAccessToken();
    </script>
</head>
<body>
    <main class="card">
        <div class="spinner"></div>
        <h1>Refreshing Session</h1>
        <p>A new access token is being generated. Please wait...</p>
    </main>
</body>
</html>
)";

    std::string currentOrigin = request->getHeaderOption("Origin");
    LOG_APP->log2(__func__, "", request->networkClientInfo.REMOTE_ADDR, Logs::LogLevel::DEBUG, "Retokenization requested from origin '%s'", currentOrigin.c_str());
    response->content.writer()->writeString(page);
    response->setContentType("text/html");
    return HTTP::Status::Code::S_200_OK;
}

/**
 * Valida y decodifica el Refresh Token.
 * @param refreshTokenStr El token en string.
 * @param outData Estructura donde se guardarán los datos validados.
 * @param outErrorMessage Mensaje de error si falla (vacío si éxito).
 * @param outErrorType Tipo de error (para mapear a HTTP status).
 * @return true si la validación fue exitosa, false en caso contrario.
 */
bool WebSessionAuthHandler_Endpoints::validateAndDecodeRefreshToken(const std::string &refreshTokenStr, RefreshTokenData &outData, std::string &outErrorMessage, std::string &outErrorType)
{
    // 0. Comprobación inicial de presencia
    if (refreshTokenStr.empty())
    {
        outErrorMessage = "Refresh token cookie is missing or empty.";
        outErrorType = "invalid_refresher";
        return false;
    }

    // 1. Decodificar sin verificar (para obtener claims básicos)
    JWT::Token refreshTokenNoVerified;
    if (!JWT::decodeNoVerify(refreshTokenStr, &refreshTokenNoVerified))
    {
        outErrorMessage = "Invalid JWT format detected in the provided refresh token.";
        outErrorType = "invalid_jwt";
        return false;
    }

    // 2. Extraer Claims básicos
    const std::string &refreshTokenApp = Helpers::JSON::ASSTRING_D(refreshTokenNoVerified.getClaim("app"), "");
    const std::string &tokenType = Helpers::JSON::ASSTRING_D(refreshTokenNoVerified.getClaim("type"), "");

    // Validar tipo de token
    if (tokenType != "refresher")
    {
        outErrorMessage = "This is not a Refresher Token.";
        outErrorType = "invalid_token";
        return false;
    }

    // Validar que la app no esté vacía
    if (refreshTokenApp.empty())
    {
        outErrorMessage = "Refresh token contains invalid or missing claims.";
        outErrorType = "invalid_token";
        return false;
    }

    // Obtener propiedades de la app
    ApplicationAuthSettings tokenProps = Globals::getIdentityManager()->applications->getAuthSettingsFromApplication(refreshTokenApp);

    // Validar que la configuración de la app coincida (seguridad)
    if (tokenProps.appName != refreshTokenApp)
    {
        // Nota: En la función original esto era 500, pero lógicamente es un error de configuración del token/app
        outErrorMessage = "Configuration error: Application mismatch.";
        outErrorType = "internal_error";
        return false;
    }

    // 3. Validar la firma del token
    std::shared_ptr<JWT> validator = Globals::getIdentityManager()->applications->getAppJWTValidator(refreshTokenApp);
    if (!validator)
    {
        outErrorMessage = "No JWT validator found for application.";
        outErrorType = "invalid_app";
        return false;
    }

    JWT::Token refreshTokenVerified;
    if (!validator->verify(refreshTokenStr, &refreshTokenVerified))
    {
        outErrorMessage = "Failed to verify refresh token.";
        outErrorType = "invalid_token";
        return false;
    }

    // 4. Extraer datos finales para el nuevo token
    const std::string &refreshTokenUser = refreshTokenVerified.getSubject();

    // 5. Llenar la estructura de salida
    outData.app = refreshTokenApp;
    outData.user = refreshTokenUser;
    outData.jwtId = refreshTokenVerified.getJwtId();
    outData.slotIds = Helpers::JSON::toUInt32Set(refreshTokenVerified.getClaim("slotIds"));
    outData.useEmbeddedAuthentication = Helpers::JSON::ASBOOL_D(refreshTokenVerified.getClaim("useEmbeddedAuthentication"), false);
    outData.tokenProps = tokenProps;

    return true;
}

WebSessionAuthHandler_Endpoints::APIReturn WebSessionAuthHandler_Endpoints::getUserPublicData(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    Json::Value r;

    std::string userUUID = request.jwtToken->getSubject();

    IdentityManager *identityManager = Globals::getIdentityManager();

    // 1. Get all login identifiers (account names) for this user
    std::set<std::string> accountNames = identityManager->accounts->getAccountNamesByAccountUUID(userUUID);
    Json::Value loginsArray(Json::arrayValue);
    for (const auto &name : accountNames)
    {
        loginsArray.append(name);
    }
    r["logins"] = loginsArray;

    // 2-4. Get the display name from the identity manager
    r["displayName"] = identityManager->accounts->getAccountDisplayName(userUUID);

    // 5. Account expiration information
    time_t expirationTime = identityManager->accounts->getAccountExpirationTime(userUUID);
    r["accountExpiration"] = expirationTime;

    // 6. Account creation time
    time_t creationTime = identityManager->accounts->getAccountCreationTime(userUUID);
    r["accountCreation"] = creationTime;

    return r;
}

WebSessionAuthHandler_Endpoints::APIReturn WebSessionAuthHandler_Endpoints::getApplicationPublicData(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::string refreshTokenStr = request.clientRequest->getCookies()->getSubVar("RefreshToken");
    RefreshTokenData tokenData;
    std::string errorMsg;
    std::string errorType;

    // 3. Delegar la validación y decodificación
    if (!validateAndDecodeRefreshToken(refreshTokenStr, tokenData, errorMsg, errorType))
    {
        // Determinar el código HTTP basado en el tipo de error
        HTTP::Status::Code status = HTTP::Status::Code::S_401_UNAUTHORIZED;
        if (errorType == "internal_error")
        {
            status = HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR;
            errorMsg = authResultToString(AuthenticationResult::INTERNAL_ERROR);
        }
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "%s", errorMsg.c_str());
        return {status, errorType, errorMsg};
    }

    // 4. Validar API Key usando la app extraída del token
    if (!validateAPIKey(tokenData.app, response, request, authClientDetails))
    {
        return response;
    }

    Json::Value r;
    r["loginMode"] = tokenData.useEmbeddedAuthentication ? "EMBEDDED" : "DOMAIN";
    r["app"]["name"] = tokenData.app;
    r["app"]["description"] = Globals::getIdentityManager()->applications->getApplicationDescription(tokenData.app);
    r["session"] = tokenData.tokenProps.sessionConfiguration;
    return r;
}

// TODO: manage errors?
bool WebSessionAuthHandler_Endpoints::validateAPIKey(const std::string &app, APIReturn &response, const RequestContext &request, ClientDetails &authClientDetails)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    // Check if the token generation is called within the app context:
    std::string apiKey = request.clientRequest->headers.getOptionValueStringByName("x-api-key");

    // Check if the token generation is called within the app context:
    std::string dbApiKey = identityManager->applications->getApplicationAPIKey(app);

    if (dbApiKey.empty())
    {
        LOG_APP->log2(__func__, request.jwtToken->getSubject(), authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT,
                      "Application '%s' does not exist. Pre-Auth JWT Token signature may be compromised!! Change immediately!", app.c_str());
        response = {HTTP::Status::Code::S_400_BAD_REQUEST, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::BAD_PARAMETERS)),
                    authResultToString(AuthenticationResult::BAD_PARAMETERS)};
        return false;
    }

    if (dbApiKey != apiKey)
    {
        LOG_APP->log2(__func__, request.jwtToken->getSubject(), authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT,
                      "Application '%s' does not match the web application API Key. Attack or misconfiguration?", app.c_str());
        response = {HTTP::Status::Code::S_404_NOT_FOUND, "not_found", "Not Found."};
        return false;
    }

    return true;
}

std::string WebSessionAuthHandler_Endpoints::signApplicationToken(JWT::Token &accessToken, const ApplicationAuthSettings &appAuthSettings)
{
    std::string appName = Helpers::JSON::ASSTRING_D(accessToken.getClaim("app"), "");
    std::shared_ptr<JWT> signingJWT = Globals::getIdentityManager()->applications->getAppJWTSigner(appName);
    if (!signingJWT)
    {
        return {};
    }
    return signingJWT->signFromToken(accessToken, false);
}
