#pragma once

#include <Mantids30/API_EndpointsAndSessions/api_restful_endpoints.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class AdminPortal_Endpoints_AuthController
{
public:
    using Endpoints = Mantids30::API::RESTful::Endpoints;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

protected:
    static void addEndpoints_AuthController(std::shared_ptr<Endpoints> endpoints);

    static APIReturn addNewAuthenticationScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn listAuthenticationSchemes(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn deleteAuthenticationScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateAuthenticationScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

    static APIReturn listAuthenticationSlotsUsedByScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateAuthenticationSlotsUsedByScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails);


    static APIReturn getDefaultAuthScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateDefaultAuthScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

    static APIReturn listAuthenticationSlots(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn addNewAuthenticationSlot(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn deleteAuthenticationSlot(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateAuthenticationSlot(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
};
