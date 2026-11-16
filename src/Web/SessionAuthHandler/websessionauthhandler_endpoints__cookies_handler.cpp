#include "websessionauthhandler_endpoints.h"
#include <Mantids30/DataFormat/JSON/json.h>
#include <Mantids30/DataFormat/JSON/json.h>
#include <boost/algorithm/string/join.hpp>

using namespace Mantids30;
using namespace Mantids30::DataFormat;
using namespace Mantids30::Runtime;
using namespace Mantids30::Server::WebRESTFul::RESTful;
using namespace Mantids30::Protocol;

void WebSessionAuthHandler_Endpoints::setupAccessTokenCookies(APIReturn &response, JWT::Token accessToken, const ApplicationAuthSettings &tokenProps)
{
    CookieProperties props;
    props.sessionCookie = true; // The access Token it's always a session cookie.
    props.expirationTime = accessToken.getExpirationTime(); // expire with the JWT token expiration.
    props.path = DataFormat::JSON::ASSTRING(DataFormat::JSON::MEMBER_OR_NULL(tokenProps.tokensConfiguration, "accessToken"), "path", "/");
    setupCookie(response, "AccessToken", signApplicationToken(accessToken, tokenProps), props);
}

void WebSessionAuthHandler_Endpoints::setupRefreshTokenCookies(APIReturn &response, JWT::Token refreshToken, const ApplicationAuthSettings &tokenProps)
{
    bool keepAuthenticated = DataFormat::JSON::ASBOOL_D(refreshToken.getClaim("keepAuthenticated"), false);

    CookieProperties props;

    // Si recibi mantenerme autenticado, entonces el refresh token no es de sesión.
    props.sessionCookie = !keepAuthenticated;
    props.expirationTime = refreshToken.getExpirationTime(); // expire with the JWT token expiration.
    props.path = DataFormat::JSON::ASSTRING(DataFormat::JSON::MEMBER_OR_NULL(tokenProps.tokensConfiguration, "refreshToken"), "path", "/auth");
    setupCookie(response, "RefreshToken", signApplicationToken(refreshToken, tokenProps), props);

    CookieProperties propsForCORSPublicData;
    propsForCORSPublicData.sessionCookie = !keepAuthenticated;
    propsForCORSPublicData.expirationTime = refreshToken.getExpirationTime(); // expire with the JWT token expiration.
    propsForCORSPublicData.path = DataFormat::JSON::ASSTRING(DataFormat::JSON::MEMBER_OR_NULL(tokenProps.tokensConfiguration, "refreshToken"), "path", "/auth");
    propsForCORSPublicData.sameSitePolicy = Mantids30::Protocol::HTTP::Headers::Cookie::SameSitePolicy::NONE;

    setupCookie(response, "RefreshTokenId", refreshToken.getJwtId(), propsForCORSPublicData);

    // Everyone can see if you are logged in and with what user (plus session metadata).
    boost::json::object sessionPublicData{
        {"user",             refreshToken.getSubject()},
        {"loginTime",        refreshToken.getIssuedAt()},
        {"expirationTime",   refreshToken.getExpirationTime()},
        {"keepAuthenticated", keepAuthenticated},
        {"app",              refreshToken.getClaim("app")},
    };

    CookieProperties propsForLocalModeRead;
    propsForLocalModeRead.httpOnly = false;
    propsForLocalModeRead.path = "/";
    propsForLocalModeRead.expirationTime = refreshToken.getExpirationTime(); // expire with the JWT token expiration.
    propsForLocalModeRead.sessionCookie = !keepAuthenticated;
    propsForLocalModeRead.sameSitePolicy = Mantids30::Protocol::HTTP::Headers::Cookie::SameSitePolicy::NONE;
    setupCookie(response, "SessionPublicData",
        Mantids30::Core::Helpers::Encoders::encodeToBase64(DataFormat::JSON::toString(sessionPublicData)),
        propsForLocalModeRead);
}

void WebSessionAuthHandler_Endpoints::setupCookie(APIReturn &response, const std::string_view &_name, const std::string_view &value, const CookieProperties &props)
{
    std::string name(_name);
    response.cookiesMap[name] = HTTP::Headers::Cookie();
    response.cookiesMap[name].setExpiration(props.expirationTime);
    response.cookiesMap[name].secure = props.secure;
    response.cookiesMap[name].path = props.path;
    response.cookiesMap[name].httpOnly = props.httpOnly;
    response.cookiesMap[name].value = value;
    response.cookiesMap[name].sameSitePolicy = props.sameSitePolicy;

    if (props.sessionCookie)
    {
        response.cookiesMap[name].setAsSessionCookie();
    }
}
