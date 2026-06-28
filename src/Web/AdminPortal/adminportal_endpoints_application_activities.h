#pragma once

#include <Mantids30/API_EndpointsAndSessions/api_restful_endpoints.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class AdminPortal_Endpoints_ApplicationActivities
{
public:
    using Endpoints = Mantids30::API::RESTful::Endpoints;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestContext = Mantids30::API::RESTful::RequestContext;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

protected:
    static void addEndpoints_Activities(const std::shared_ptr<Endpoints> &endpoints);

    static APIReturn getActivityInfo(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn listApplicationActivities(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn createApplicationActivity(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn removeApplicationActivity(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn updateActivityParentActivity(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn updateActivityDescription(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn addSchemeToApplicationActivity(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn removeSchemeFromApplicationActivity(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn updateDefaultSchemeOnApplicationActivity(void *context, const RequestContext &request, ClientDetails &authClientDetails);
};
