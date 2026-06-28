#pragma once

#include <Mantids30/API_EndpointsAndSessions/api_restful_endpoints.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class AdminPortal_Endpoints_ApplicationRoles
{
public:
    using Endpoints = Mantids30::API::RESTful::Endpoints;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestContext = Mantids30::API::RESTful::RequestContext;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

protected:
    static void addEndpoints_Roles(const std::shared_ptr<Endpoints> &endpoints);
    static APIReturn searchApplicationRoles(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn createRole(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn getRoleInfo(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn updateRoleDescription(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn removeRole(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn addApplicationRoleToAccount(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn removeApplicationRoleFromAccount(void *context, const RequestContext &request, ClientDetails &authClientDetails);
};
