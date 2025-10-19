#pragma once

#include <Mantids30/API_RESTful/endpointshandler.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class WebAdminMethods_ApplicationActivities
{
public:
    using Endpoints = Mantids30::API::RESTful::Endpoints;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

protected:
    static void addEndpoints_Activities(std::shared_ptr<Endpoints> endpoints);

    static APIReturn getActivityInfo(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn listApplicationActivities(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn addApplicationActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn removeApplicationActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

    static APIReturn updateActivityParentActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateActivityDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

    static APIReturn addSchemeToApplicationActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn removeSchemeFromApplicationActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

    static APIReturn updateDefaultSchemeOnApplicationActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails);


};
