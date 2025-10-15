#pragma once

#include <Mantids30/API_RESTful/endpointshandler.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

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
    static APIReturn getApplicationJWTConfig(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationJWTSigningKey(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationJWTValidationKey(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateAccessControlContext(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

private:


};
