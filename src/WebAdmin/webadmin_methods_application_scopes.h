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

    static APIReturn addApplicationScopeToAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn removeApplicationScopeFromAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

    static APIReturn addApplicationScope(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn removeApplicationScope(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn addApplicationScopeToRole(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn removeApplicationScopeFromRole(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

    static APIReturn searchApplicationScopes(void *context, const RequestParameters &request, ClientDetails &authClientDetails);


/*
    static APIReturn updateApplicationScopeDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn listApplicationScopes(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationRolesForScope(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn listAccountsOnApplicationScope(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn scopesLeftListForRole(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationScopeDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails);*/
};
