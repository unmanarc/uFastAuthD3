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
#include "Mantids30/API_EndpointsAndSessions/api_options_handler.h"
#include "globals.h"

using namespace Mantids30;
using namespace Mantids30::Program;
using namespace Mantids30::API::RESTful;
using namespace Mantids30::Network::Protocol;
using namespace Mantids30::DataFormat;

void WebSessionAuthHandler_Endpoints::addEndpoints(std::shared_ptr<Endpoints> endpoints)
{
    using SecurityRequirements = API::Security::Requirements;

    endpoints->addEndpoint(HTTP::Method::GET, "getLogoutCallbackURL", SecurityRequirements::NONE, {}, nullptr, &getLogoutCallbackURL);
    endpoints->addEndpoint(HTTP::Method::POST, "refreshAccessToken", SecurityRequirements::NONE, {}, nullptr, &refreshAccessToken); // Using refresh token auth.
    endpoints->addEndpoint(HTTP::Method::GET, "getLoginMode", SecurityRequirements::NONE, {}, nullptr, &getLoginMode);              // Using refresh token auth.
    endpoints->addEndpoint(HTTP::Method::POST, "logout", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &appLogout);
    endpoints->addEndpoint(HTTP::Method::POST, "callback", SecurityRequirements::NONE, {}, nullptr, &callback);
    endpoints->setEndpointOptions("callback", API::OptionsHandlerConfig().insertAllowedOrigin(Globals::pConfig.get<std::string>("AppVars.LoginPortalURL", "")).setAllowCredentials(true));
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
    const std::string &refreshTokenApp = JSON_ASSTRING_D(refreshTokenNoVerified.getClaim("app"), "");
    const std::string &tokenType = JSON_ASSTRING_D(refreshTokenNoVerified.getClaim("type"), "");

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
    ApplicationTokenProperties tokenProps = Globals::getIdentityManager()->applications->getWebLoginJWTConfigFromApplication(refreshTokenApp);

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
    outData.slotIds = Mantids30::Helpers::jsonToUInt32Set(refreshTokenVerified.getClaim("slotIds"));
    outData.useEmbeddedAuthentication = JSON_ASBOOL_D(refreshTokenVerified.getClaim("useEmbeddedAuthentication"), false);
    outData.tokenProps = tokenProps;

    return true;
}

WebSessionAuthHandler_Endpoints::APIReturn WebSessionAuthHandler_Endpoints::getLoginMode(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
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
        response.setError(status, errorType, errorMsg);
        return response;
    }

    // 4. Validar API Key usando la app extraída del token
    if (!validateAPIKey(tokenData.app, response, request, authClientDetails))
    {
        return response;
    }

    Json::Value r;
    r["mode"] = tokenData.useEmbeddedAuthentication ? "EMBEDDED" : "DOMAIN";
    r["app"]["name"] = tokenData.app;
    r["app"]["description"] = Globals::getIdentityManager()->applications->getApplicationDescription(tokenData.app);
    return r;
}

// TODO: manage errors?
bool WebSessionAuthHandler_Endpoints::validateAPIKey(const std::string &app, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
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
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::BAD_PARAMETERS)),
                          authResultToString(AuthenticationResult::BAD_PARAMETERS));
        return false;
    }

    if (dbApiKey != apiKey)
    {
        LOG_APP->log2(__func__, request.jwtToken->getSubject(), authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT,
                      "Application '%s' does not match the web application API Key. Attack or misconfiguration?", app.c_str());
        response.setError(HTTP::Status::Code::S_404_NOT_FOUND, "not_found", "Not Found.");
        return false;
    }

    return true;
}

std::string WebSessionAuthHandler_Endpoints::signApplicationToken(JWT::Token &accessToken, const ApplicationTokenProperties &tokenProperties)
{
    std::string appName = JSON_ASSTRING_D(accessToken.getClaim("app"), "");
    std::shared_ptr<JWT> signingJWT = Globals::getIdentityManager()->applications->getAppJWTSigner(appName);
    if (!signingJWT)
    {
        return std::string();
    }
    return signingJWT->signFromToken(accessToken, false);
}
