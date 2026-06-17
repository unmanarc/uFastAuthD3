#pragma once

#include "IdentityManager/identitymanager.h"
#include <Mantids30/API_EndpointsAndSessions/api_restful_endpoints.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/hdr_cookie.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

// This template is for FastRPC
class WebSessionAuthHandler_Endpoints
{
public:
    using Endpoints = Mantids30::API::RESTful::Endpoints;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;
    using HTTPv1_Base = Mantids30::Network::Protocol::HTTP::HTTPv1_Base;
    using ClientDetails = Mantids30::Sessions::ClientDetails;
    using JWT = Mantids30::DataFormat::JWT;

    /**
    * @brief Adds the available login authentication methods as server functions.
    * @param methods The Endpoints to which the authentication methods will be added.
    */
    static void addEndpoints(const std::shared_ptr<Endpoints> &endpoints);

    // Remote triggered:
    static APIReturn refreshAccessToken(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationLoginPublicData(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn appLogout(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn callback(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getLogoutCallbackURL(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

    static Mantids30::Network::Protocol::HTTP::Status::Code handleRetokenizeHTML(const std::string &appName, HTTPv1_Base::Request *request, HTTPv1_Base::Response *response,
                                                                                       const std::shared_ptr<void> &);


private:
    static bool validateAPIKey(const std::string &app, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void setupAccessTokenCookies(APIReturn &response, JWT::Token accessToken, const ApplicationTokenProperties &tokenProps);
    static void setupRefreshTokenCookies(APIReturn &response, JWT::Token refreshToken, const ApplicationTokenProperties &tokenProps);
    //static void setupLogoutTokenCookies(APIReturn &response, JWT::Token refreshToken, const ApplicationTokenProperties &tokenProps);

    struct CookieProperties
    {
        Mantids30::Network::Protocol::HTTP::Headers::Cookie::SameSitePolicy sameSitePolicy = Mantids30::Network::Protocol::HTTP::Headers::Cookie::SameSitePolicy::STRICT;
        bool sessionCookie = false;
        bool secure = true;
        bool httpOnly = true;
        time_t expirationTime = 0; // don't expire?
        std::string path;
    };
    struct RefreshTokenData
    {
        bool useEmbeddedAuthentication = false;
        std::string app;
        std::string user;
        std::string jwtId;
        std::set<uint32_t> slotIds;
        ApplicationTokenProperties tokenProps;
    };

    static bool validateAndDecodeRefreshToken(const std::string &refreshTokenStr, RefreshTokenData &outData, std::string &outErrorMessage, std::string &outErrorType);
    static void setupCookie(APIReturn &response, const std::string &name, const std::string &value, const CookieProperties &props);
    static void setupMaxAgeCookie(APIReturn &response, const std::string &name, time_t expirationTime);
    static std::string signApplicationToken(JWT::Token &accessToken, const ApplicationTokenProperties &tokenProperties);
};
