#pragma once

#include "IdentityManager/identitymanager.h"
#include <Mantids30/API_EndpointsAndSessions/api_restful_endpoints.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

#include <regex>

// This template is for FastRPC
class LoginPortal_Endpoints
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
    static void addEndpoints(std::shared_ptr<Endpoints> endpoints);

    /*static Mantids30::Network::Protocol::HTTP::Status::Code handleLoginDynamicRequest(const std::string &appName, HTTPv1_Base::Request *request, HTTPv1_Base::Response *response,
                                                                                        std::shared_ptr<void>);*/

    static Mantids30::Network::Protocol::HTTP::Status::Code handleLogoutDynamicRequest(const std::string &appName, HTTPv1_Base::Request *request, HTTPv1_Base::Response *response,
                                                                                       std::shared_ptr<void>);

private:
    ////////////////
    // EXPOSED FUNCTIONS:

    static APIReturn preAuthorize(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn authorize(void *context, const RequestParameters &request, ClientDetails &clientDetails);
    static APIReturn token(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn logout(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn changeCredential(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getAppDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getLoginMode(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn registerAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn callback(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

private:
    ////////////////

    enum class OriginSource : uint8_t
    {
        HTTP_HEADER_ORIGIN,
        HTTP_HEADER_REFERER
    };
    static bool retrieveAndValidateAppOrigin(HTTPv1_Base::Request *request, const std::string &appName, const OriginSource &originSource);
    static std::regex originPattern;

    static void deleteLoginCookies(void *context, const RequestParameters &, ClientDetails &, APIReturn *response);

    // TOKEN HELPERS:
    static bool token_validateRedirectURI(const std::string &app, const std::string &user, const std::string &redirectURI, const std::string &ipAddress);
    static bool token_createAndSignApplicationRefreshAndAccessJWTs(const JWT::Token *jwtToken, const bool &useEmbeddedAuthentication, const bool &keepAuthenticated, const std::string &app,
                                                                   const std::string &user, const uint32_t &schemeId, const std::string &redirectURI, APIReturn &response,
                                                                   ClientDetails &authClientDetails);
    static bool token_validateJwtClaims(const JWT::Token *jwtToken, const std::string &user, const std::string &ipAddress);

    static bool token_validateAuthenticationScheme(const JWT::Token *jwtToken, const std::string &requestedApp, const std::string &requestedActivity, uint32_t &requestedSchemeId,
                                                   const std::string &authenticatedUser, const std::string &ipAddress);
    static std::optional<std::string> token_signApplicationJWT(JWT::Token &accessToken);
    static bool token_validateAppAuthorization(const JWT::Token *jwtToken, const std::string &app, const std::string &user, const std::string &ipAddress);

    static std::vector<AuthenticationSchemeUsedSlot> calculateRequiredAuthSlotsLeftForTheNewTransientAuthToken(std::shared_ptr<TransientAuthenticationContext> authContext,
                                                                                                               Mantids30::API::APIReturn *response);

    //static bool validateAndMerge_AccessTokenIfExist(const RequestParameters &request, LoginPortal_Endpoints::APIReturn &response, std::shared_ptr<TransientAuthenticationContext> authContext);

    static void issueTransientAuthTokenResponse(const RequestParameters &request, Mantids30::API::APIReturn &response, std::shared_ptr<TransientAuthenticationContext> authContext,
                                                const std::vector<AuthenticationSchemeUsedSlot> &requiredAuthSlots, bool mustChange, bool canSkipPasswordChange);
};
