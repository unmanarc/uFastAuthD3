#pragma once

#include <Mantids30/API_RESTful/methodshandler.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class WebAdminMethods_ApplicationsScopes
{
public:
    using MethodsHandler = Mantids30::API::RESTful::MethodsHandler;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

protected:
    static void addMethods_Scopes(std::shared_ptr<MethodsHandler> methods);

    static void addApplicationScopeToAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void removeApplicationScopeFromAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

    static void addApplicationScope(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void removeApplicationScope(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);


/*
    static void addApplicationScopeToRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void removeApplicationScopeFromRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void updateApplicationScopeDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void listApplicationScopes(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void getApplicationScopesForRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void listAccountsOnApplicationScope(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void searchApplicationScopes(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void scopesLeftListForRole(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void getApplicationScopeDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);*/
};
