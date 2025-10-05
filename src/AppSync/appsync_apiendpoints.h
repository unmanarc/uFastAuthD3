#pragma once

#include <Mantids30/API_RESTful/methodshandler.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

// This template is for FastRPC
class AppSync_Endpoints
{
public:
    using MethodsHandler = Mantids30::API::RESTful::MethodsHandler;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;
    using HTTPv1_Base = Mantids30::Network::Protocols::HTTP::HTTPv1_Base;
    using ClientDetails = Mantids30::Sessions::ClientDetails;
    using JWT = Mantids30::DataFormat::JWT;

    /**
    * @brief Adds the available login authentication methods as server functions.
    * @param methods The MethodsHandler to which the authentication methods will be added.
    */
    static void addAPIEndpoints(std::shared_ptr<MethodsHandler> methods);

    // Remote triggered:
    static APIReturn getApplicationJWTConfig(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationJWTSigningKey(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationJWTValidationKey(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

private:


};
