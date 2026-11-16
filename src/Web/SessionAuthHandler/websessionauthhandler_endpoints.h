#pragma once

#include "IdentityManager/identitymanager.h"
#include <Mantids30/Server/WebRESTFul/api_restful_endpoints.h>
#include <Mantids30/DataFormat/JSON/json.h>
#include <Mantids30/Protocol/HTTP/hdr_cookie.h>
#include <Mantids30/Protocol/HTTP/httpv1_base.h>

// This template is for FastRPC
class WebSessionAuthHandler_Endpoints
{
public:
    using Endpoints = Mantids30::Server::WebRESTFul::RESTful::Endpoints;
    using APIReturn = Mantids30::Protocol::HTTP::APIReturn;
    using RequestContext = Mantids30::Server::WebRESTFul::RESTful::RequestContext;
    using HTTPv1_Base = Mantids30::Protocol::HTTP::HTTPv1_Base;
    using ClientDetails = Mantids30::Server::WebRESTFul::Sessions::ClientDetails;
    using SessionInfo = Mantids30::Server::WebRESTFul::Sessions::SessionInfo;
    using JWT = ::Mantids30::DataFormat::JWT;

    /**
    * @brief Adds the available login authentication methods as server functions.
    * @param methods The Endpoints to which the authentication methods will be added.
    */
    static void addEndpoints(const std::shared_ptr<Endpoints> &endpoints);

    // Remote triggered:
    static APIReturn refreshAccessToken(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn getUserPublicData(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationPublicData(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn appLogout(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn callback(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn getLogoutCallbackURL(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static Mantids30::Protocol::HTTP::Status::Code handleRetokenizeHTML(const std::string &urlPostfix, HTTPv1_Base::Request *request, HTTPv1_Base::Response *response,
                                                                                 const std::shared_ptr<void> &, const SessionInfo *sessionInfo);

private:
    static bool validateAPIKey(const std::string &app, APIReturn &response, const RequestContext &request, ClientDetails &authClientDetails);
    static void setupAccessTokenCookies(APIReturn &response, JWT::Token accessToken, const ApplicationAuthSettings &tokenProps);
    static void setupRefreshTokenCookies(APIReturn &response, JWT::Token refreshToken, const ApplicationAuthSettings &tokenProps);
    //static void setupLogoutTokenCookies(APIReturn &response, JWT::Token refreshToken, const ApplicationAuthSettings &tokenProps);

    struct CookieProperties
    {
        Mantids30::Protocol::HTTP::Headers::Cookie::SameSitePolicy sameSitePolicy = Mantids30::Protocol::HTTP::Headers::Cookie::SameSitePolicy::STRICT;
        bool sessionCookie = false;
        bool secure = true;
        bool httpOnly = true;
        time_t expirationTime = 0; // don't expire?
        std::string path;
    };
    struct RefreshTokenData
    {
        bool useEmbeddedInPortalAuthentication = false;
        std::string app;
        std::string user;
        std::string jwtId;
        std::set<uint32_t> slotIds;
        ApplicationAuthSettings tokenProps;
    };

    static bool validateAndDecodeRefreshToken(const std::string &refreshTokenStr, RefreshTokenData &outData, std::string &outErrorMessage, std::string &outErrorType);
    static void setupCookie(APIReturn &response, const std::string_view &name, const std::string_view &value, const CookieProperties &props);
    static void setupMaxAgeCookie(APIReturn &response, const std::string &name, time_t expirationTime);
    static std::string signApplicationToken(JWT::Token &accessToken, const ApplicationAuthSettings &appAuthSettings);
};
