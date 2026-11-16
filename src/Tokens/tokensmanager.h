#pragma once

#include "IdentityManager/ds_application.h"
#include "IdentityManager/identitymanager.h"

#include <Mantids30/Server/WebRESTFul/api_restful_endpoints.h>
#include <Mantids30/DataFormat/JSON/json.h>
#include <Mantids30/Protocol/HTTP/api_return.h>
#include <Mantids30/Protocol/HTTP/httpv1_base.h>

class TokensManager
{
public:
    TokensManager() = default;
    using APIReturn = Mantids30::Protocol::HTTP::APIReturn;
    using RequestContext = Mantids30::Server::WebRESTFul::RESTful::RequestContext;
    using HTTPv1_Base = Mantids30::Protocol::HTTP::HTTPv1_Base;
    using ClientDetails = Mantids30::Server::WebRESTFul::Sessions::ClientDetails;

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
        bool useEmbeddedInPortalAuthentication = false;
    };

    static void configureApplicationAccessToken(Mantids30::DataFormat::JWT::Token &accessToken, const ApplicationTokenCommonParams &commonParams);

    static void configureApplicationRefreshToken(Mantids30::DataFormat::JWT::Token &refreshToken, const ApplicationTokenCommonParams &commonParams, const RefreshTokenParams &refreshParams);

    static void configureLPToken(Mantids30::DataFormat::JWT::Token &lpToken, const std::shared_ptr<TransientAuthenticationContext> &authContext);

    //static void configureLogoutToken(const Mantids30::DataFormat::JWT::Token &refreshToken, Mantids30::DataFormat::JWT::Token &logoutToken);

    static void issueLPTokenCookie(APIReturn &response, const RequestContext &request, const std::shared_ptr<TransientAuthenticationContext> &authContext);

private:
    static time_t getExpirationTime(const ApplicationTokenCommonParams &commonParams, IdentityManager *identityManager, const std::string &tokenType, time_t defaultTimeout);
};

