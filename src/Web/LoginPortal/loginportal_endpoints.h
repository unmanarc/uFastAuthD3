#pragma once

#include "IdentityManager/identitymanager.h"
#include <Mantids30/Server/WebRESTFul/api_restful_endpoints.h>
#include <Mantids30/DataFormat/JSON/json.h>
#include <Mantids30/Protocol/HTTP/httpv1_base.h>

#include <regex>

// This template is for FastRPC
class LoginPortal_Endpoints
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

    static Mantids30::Protocol::HTTP::Status::Code handleLogoutDynamicRequest(const std::string &urlPostfix, HTTPv1_Base::Request *request, HTTPv1_Base::Response *response,
                                                                                       const std::shared_ptr<void> &, const SessionInfo *sessionInfo);

private:
    ////////////////
    // EXPOSED FUNCTIONS:

    static APIReturn preAuthorize(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn authorize(void *context, const RequestContext &request, ClientDetails &clientDetails);
    static APIReturn embedToken(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn token(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn logout(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn changeCredential(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationLoginPublicData(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn registerAccount(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn callback(void *context, const RequestContext &request, ClientDetails &authClientDetails);

private:
    ////////////////

    enum class OriginSource : uint8_t
    {
        HTTP_HEADER_ORIGIN,
        HTTP_HEADER_REFERER
    };
    static bool retrieveAndValidateAppOrigin(HTTPv1_Base::Request *request, const std::string &appName, const OriginSource &originSource);
    static std::regex originPattern;

    static void deleteLoginCookies(void *context, const RequestContext &, ClientDetails &, APIReturn *response);

    // TOKEN HELPERS:
    static bool token_validateRedirectURI(const std::string &app, const std::string &user, const std::string &redirectURI, const std::string &ipAddress);
    static bool token_createAndSignApplicationRefreshAndAccessJWTs(const JWT::Token *jwtToken, const bool &useEmbeddedInPortalAuthentication, const bool &keepAuthenticated, const std::string &app, const std::string &activity,
                                                                   const std::string &user, const uint32_t &schemeId, const std::string &redirectURI, APIReturn &response,
                                                                   ClientDetails &authClientDetails);
    static bool token_validateJwtClaims(const JWT::Token *jwtToken, std::string_view user, std::string_view ipAddress);

    static bool token_validateAuthenticationScheme(const JWT::Token *jwtToken, const std::string &requestedApp, const std::string &requestedActivity, uint32_t &requestedSchemeId,
                                                   std::string_view authenticatedUser, std::string_view ipAddress);
    static std::optional<std::string> token_signApplicationJWT(JWT::Token &accessToken);
    static bool token_validateAppAuthorization(const JWT::Token *jwtToken, const std::string_view &app, const std::string_view &user, const std::string_view &ipAddress);

    static std::vector<AuthenticationSchemeUsedSlot> calculateRequiredAuthSlotsLeftForTheNewTransientAuthToken(const std::shared_ptr<TransientAuthenticationContext> &authContext,
                                                                                                               Mantids30::Protocol::HTTP::APIReturn *response);

    //static bool validateAndMerge_AccessTokenIfExist(const RequestContext &request, LoginPortal_Endpoints::APIReturn &response, std::shared_ptr<TransientAuthenticationContext> authContext);

    static void issueTransientAuthTokenResponse(const RequestContext &request, Mantids30::Protocol::HTTP::APIReturn &response, const std::shared_ptr<TransientAuthenticationContext> &authContext,
                                                const std::vector<AuthenticationSchemeUsedSlot> &requiredAuthSlots, bool mustChange, bool canSkipPasswordChange);
};
