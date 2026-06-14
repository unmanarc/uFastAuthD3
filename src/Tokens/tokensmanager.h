#ifndef TOKENSMANAGER_H
#define TOKENSMANAGER_H

#include "IdentityManager/credentialvalidator.h"
#include "IdentityManager/ds_application.h"

#include <Mantids30/API_EndpointsAndSessions/api_restful_endpoints.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/api_return.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class TokensManager
{
public:
    TokensManager() = default;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;
    using HTTPv1_Base = Mantids30::Network::Protocols::HTTP::HTTPv1_Base;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

    struct ApplicationTokenCommonParams
    {
        std::string refreshTokenId;
        std::string jwtAccountName;
        std::string appName;
        ApplicationTokenProperties tokenProperties;
        std::set<uint32_t> slotIds;
    };

    struct RefreshTokenParams
    {
        bool keepAuthenticated = false;
        bool useEmbeddedAuthentication = false;
    };

    static void configureApplicationAccessToken(Mantids30::DataFormat::JWT::Token &accessToken, const ApplicationTokenCommonParams &commonParams);

    static void configureApplicationRefreshToken(Mantids30::DataFormat::JWT::Token &refreshToken, const ApplicationTokenCommonParams &commonParams, const RefreshTokenParams &refreshParams);

    //static void configureLogoutToken(const Mantids30::DataFormat::JWT::Token &refreshToken, Mantids30::DataFormat::JWT::Token &logoutToken);

    static void issueLPTokenCookie(APIReturn &response, const RequestParameters &request, std::shared_ptr<TransientAuthenticationContext> authContext);
};

#endif // TOKENSMANAGER_H
