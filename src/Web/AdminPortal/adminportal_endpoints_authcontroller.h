#pragma once

#include <Mantids30/Server/WebRESTFul/api_restful_endpoints.h>
#include <Mantids30/DataFormat/JSON/json.h>
#include <Mantids30/Protocol/HTTP/httpv1_base.h>

class AdminPortal_Endpoints_AuthController
{
public:
    using Endpoints = Mantids30::Server::WebRESTFul::RESTful::Endpoints;
    using APIReturn = Mantids30::Protocol::HTTP::APIReturn;
    using RequestContext = Mantids30::Server::WebRESTFul::RESTful::RequestContext;
    using ClientDetails = Mantids30::Server::WebRESTFul::Sessions::ClientDetails;

protected:
    static void addEndpoints_AuthController(const std::shared_ptr<Endpoints> &endpoints);

    static APIReturn createAuthenticationScheme(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn listAuthenticationSchemes(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn deleteAuthenticationScheme(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn updateAuthenticationScheme(void *context, const RequestContext &request, ClientDetails &authClientDetails);

    static APIReturn listAuthenticationSlotsUsedByScheme(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn updateAuthenticationSlotsUsedByScheme(void *context, const RequestContext &request, ClientDetails &authClientDetails);

    static APIReturn getDefaultAuthScheme(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn updateDefaultAuthScheme(void *context, const RequestContext &request, ClientDetails &authClientDetails);

    static APIReturn listAuthenticationSlots(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn createAuthenticationSlot(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn deleteAuthenticationSlot(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn updateAuthenticationSlot(void *context, const RequestContext &request, ClientDetails &authClientDetails);
};
