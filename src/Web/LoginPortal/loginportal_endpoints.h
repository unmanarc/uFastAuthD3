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
    using HTTPv1_Base = Mantids30::Network::Protocols::HTTP::HTTPv1_Base;
    using ClientDetails = Mantids30::Sessions::ClientDetails;
    using JWT = Mantids30::DataFormat::JWT;

    /**
    * @brief Adds the available login authentication methods as server functions.
    * @param methods The Endpoints to which the authentication methods will be added.
    */
    static void addEndpoints(std::shared_ptr<Endpoints> endpoints);

    static Mantids30::Network::Protocols::HTTP::Status::Codes handleLoginDynamicRequest(const std::string &appName, HTTPv1_Base::Request *request, HTTPv1_Base::Response *response,
                                                                                        std::shared_ptr<void>);

private:
    ////////////////
    // EXPOSED FUNCTIONS:

    static APIReturn preAuthorize(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn authorize(void *context, const RequestParameters &request, ClientDetails &clientDetails);
    static APIReturn token(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn logout(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn changeCredential(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn registerAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

private:
    ////////////////

    enum OriginSource
    {
        USING_HEADER_ORIGIN,
        USING_HEADER_REFERER
    };
    static bool retrieveAndValidateAppOrigin(HTTPv1_Base::Request *request, const std::string &appName, const OriginSource &originSource);
    static std::regex originPattern;

    static void prepareLogoutResponse(void *context, const RequestParameters &, ClientDetails &, APIReturn *response);

    // TOKEN HELPERS:
    static bool token_validateRedirectURI(IdentityManager *identityManager, const std::string &app, const std::string &redirectURI, const std::string &user, const std::string &ipAddress);
    static bool token_createAndSignApplicationsJWTs(IdentityManager *identityManager, const JWT::Token *jwtToken, const std::string &app, const std::string &user, const uint32_t &schemeId,
                                                    const std::string &redirectURI, APIReturn &response, ClientDetails &authClientDetails);
    static bool token_validateJwtClaims(const JWT::Token *jwtToken, const std::string &user, const std::string &ipAddress);
    static std::optional<std::string> token_signApplicationJWT(JWT::Token &accessToken, const ApplicationTokenProperties &tokenProperties);
    static bool token_validateAppAuthorization(IdentityManager *identityManager, const JWT::Token *jwtToken, const std::string &app, const std::string &user, const std::string &ipAddress);

    static std::vector<AuthenticationSchemeUsedSlot> calculateRequiredAuthSlotsLeftForTheNewTransientAuthToken(std::shared_ptr<TransientAuthenticationContext> authContext, Mantids30::API::APIReturn *response);

    //static bool validateAndMerge_AccessTokenIfExist(const RequestParameters &request, LoginPortal_Endpoints::APIReturn &response, std::shared_ptr<TransientAuthenticationContext> authContext);


    static void issueTransientAuthTokenResponse(const RequestParameters &request, Mantids30::API::APIReturn &response, IdentityManager *identityManager,
                                           std::shared_ptr<TransientAuthenticationContext> authContext, const std::vector<AuthenticationSchemeUsedSlot> &requiredAuthSlots
                                          , bool mustChange);
};
