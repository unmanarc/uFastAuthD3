#pragma once

#include <Mantids30/API_EndpointsAndSessions/api_restful_endpoints.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

#include "IdentityManager/identitymanager.h"

// This template is for FastRPC
class AppSync_Endpoints
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
    static void addAPIEndpoints(std::shared_ptr<Endpoints> endpoints);

    // Remote triggered:
    static APIReturn getApplicationAccountsList(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationJWTConfig(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    //static APIReturn getApplicationJWTSigningKey(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationJWTValidationKey(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateAccessControlContext(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

    /////////////////////////////////
    static void updateAppScopes(const std::string &appName, const std::string &ipAddress, const json &proposedScopes);
    static void updateAppRoles(const std::string &appName, const std::string &ipAddress, const json &proposedRoles);
    static void updateAppActivities(const std::string &appName, const std::string &ipAddress, const json &proposedActivities);

private:
    static AppSync_Endpoints::APIReturn validateAndFetchApplicationAttributes(const RequestParameters &request, ClientDetails &authClientDetails, std::string &appName,
                                                                              std::optional<IdentityManager::Applications::ApplicationAttributes> &attribs);
};
