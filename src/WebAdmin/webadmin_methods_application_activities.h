#pragma once

#include <Mantids30/API_RESTful/methodshandler.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class WebAdminMethods_ApplicationActivities
{
public:
    using MethodsHandler = Mantids30::API::RESTful::MethodsHandler;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

protected:
    static void addMethods_Activities(std::shared_ptr<MethodsHandler> methods);

    static void getActivityInfo(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void listApplicationActivities(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void addApplicationActivity(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void removeApplicationActivity(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

    static void updateActivityParentActivity(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void updateActivityDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

    static void addSchemeToApplicationActivity(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void removeSchemeFromApplicationActivity(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

    static void updateDefaultSchemeOnApplicationActivity(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);


};
