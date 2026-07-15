#pragma once

#include "IdentityManager/ds_application.h"
#include "IdentityManager/identitymanager.h"

#include <Mantids30/API_EndpointsAndSessions/api_restful_endpoints.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/api_return.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class TokensManager
{
public:
    TokensManager() = default;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestContext = Mantids30::API::RESTful::RequestContext;
    using HTTPv1_Base = Mantids30::Network::Protocol::HTTP::HTTPv1_Base;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

    struct ApplicationTokenCommonParams
    {
        std::string refreshTokenId;
        std::string jwtAccountName;
        std::string appName;
        ApplicationAuthSettings appAuthSettings;
        std::set<uint32_t> slotIds;
    };

    struct RefreshTokenParams
    {
        std::string activity;
        bool keepAuthenticated = false;
        bool useEmbeddedAuthentication = false;
    };

    static void configureApplicationAccessToken(Mantids30::DataFormat::JWT::Token &accessToken, const ApplicationTokenCommonParams &commonParams);

    static void configureApplicationRefreshToken(Mantids30::DataFormat::JWT::Token &refreshToken, const ApplicationTokenCommonParams &commonParams, const RefreshTokenParams &refreshParams);

    static void configureLPToken(Mantids30::DataFormat::JWT::Token &lpToken, const std::shared_ptr<TransientAuthenticationContext> &authContext);

    //static void configureLogoutToken(const Mantids30::DataFormat::JWT::Token &refreshToken, Mantids30::DataFormat::JWT::Token &logoutToken);

    static void issueLPTokenCookie(APIReturn &response, const RequestContext &request, const std::shared_ptr<TransientAuthenticationContext> &authContext);

private:
    static time_t getExpirationTime(const ApplicationTokenCommonParams &commonParams, IdentityManager *identityManager, const std::string &tokenType, time_t defaultTimeout);
};

