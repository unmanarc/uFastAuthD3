#include <Mantids30/Helpers/json.h>
#include <Mantids30/Program_Logs/loglevels.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>
#include <boost/algorithm/string/join.hpp>
#include <json/config.h>
#include <json/value.h>

#include "Tokens/tokensmanager.h"
#include "globals.h"
#include "websessionauthhandler_endpoints.h"

using namespace Mantids30;
using namespace Mantids30::DataFormat;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocol;

API::APIReturn WebSessionAuthHandler_Endpoints::refreshAccessToken(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::string refreshTokenStr = request.clientRequest->getCookies()->getSubVar("RefreshToken");
    RefreshTokenData tokenData;
    std::string errorMsg;
    std::string errorType;

    if (!validateAndDecodeRefreshToken(refreshTokenStr, tokenData, errorMsg, errorType))
    {
        HTTP::Status::Code status = HTTP::Status::Code::S_401_UNAUTHORIZED;
        if (errorType == "internal_error")
        {
            status = HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR;
            errorMsg = authResultToString(AuthenticationResult::INTERNAL_ERROR);
        }
        LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "%s", errorMsg.c_str());
        return {status, errorType, errorMsg};
    }

    if (!validateAPIKey(tokenData.app, response, request, authClientDetails))
    {
        return response;
    }

    JWT::Token newAccessToken;
    TokensManager::ApplicationTokenCommonParams params;
    params.refreshTokenId = tokenData.jwtId;
    params.tokenProperties = tokenData.tokenProps;
    params.appName = tokenData.app;
    params.jwtAccountName = tokenData.user;
    params.slotIds = tokenData.slotIds;

    TokensManager::configureApplicationAccessToken(newAccessToken, params);
    setupAccessTokenCookies(response, newAccessToken, tokenData.tokenProps);

    Globals::getIdentityManager()->authController->updateApplicationAuthLogAccessTokenId(tokenData.user, tokenData.app, tokenData.jwtId, newAccessToken.getJwtId(), newAccessToken.getExpirationTime());

    (*response.responseJSON())["maxAge"] = (time_t) (newAccessToken.getExpirationTime() - time(nullptr));

    return response;
}
