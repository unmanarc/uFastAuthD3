#pragma once

#include <Mantids30/Server/WebRESTFul/api_restful_endpoints.h>
#include <Mantids30/DataFormat/JSON/json.h>
#include <Mantids30/Protocol/HTTP/httpv1_base.h>

class AdminPortal_Endpoints_ApplicationsScopes
{
public:
    using Endpoints = Mantids30::Server::WebRESTFul::RESTful::Endpoints;
    using APIReturn = Mantids30::Protocol::HTTP::APIReturn;
    using RequestContext = Mantids30::Server::WebRESTFul::RESTful::RequestContext;
    using ClientDetails = Mantids30::Server::WebRESTFul::Sessions::ClientDetails;

protected:
    static void addEndpoints_Scopes(const std::shared_ptr<Endpoints> &endpoints);

    static APIReturn addApplicationScopeToAccount(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn removeApplicationScopeFromAccount(void *context, const RequestContext &request, ClientDetails &authClientDetails);

    static APIReturn createApplicationScope(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn removeApplicationScope(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn addApplicationScopeToRole(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn removeApplicationScopeFromRole(void *context, const RequestContext &request, ClientDetails &authClientDetails);

    static APIReturn searchApplicationScopes(void *context, const RequestContext &request, ClientDetails &authClientDetails);

    /*
    static APIReturn updateApplicationScopeDescription(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn listApplicationScopes(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationRolesForScope(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn listAccountsOnApplicationScope(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn scopesLeftListForRole(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationScopeDescription(void *context, const RequestContext &request, ClientDetails &authClientDetails);*/
};
