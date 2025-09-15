#pragma once

#include <Mantids30/API_RESTful/methodshandler.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class WebAdmin_Methods_AuthController
{
public:
    using MethodsHandler = Mantids30::API::RESTful::MethodsHandler;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

protected:
    static void addMethods_AuthController(std::shared_ptr<MethodsHandler> methods);

    static void addNewAuthenticationScheme(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void listAuthenticationSchemes(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void deleteAuthenticationScheme(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void updateAuthenticationScheme(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

    static void listAuthenticationSlotsUsedByScheme(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void updateAuthenticationSlotsUsedByScheme(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);


    static void listAuthenticationSlots(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void addNewAuthenticationSlot(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void deleteAuthenticationSlot(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void updateAuthenticationSlot(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
};
