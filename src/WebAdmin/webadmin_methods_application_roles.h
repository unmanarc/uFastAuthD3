#pragma once

#include <Mantids30/API_RESTful/methodshandler.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class WebAdminMethods_ApplicationRoles
{
public:
    using MethodsHandler = Mantids30::API::RESTful::MethodsHandler;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

protected:
    static void addMethods_Roles(std::shared_ptr<MethodsHandler> methods);
    static APIReturn searchRoles(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn addRole(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getRoleInfo(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateRoleDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn removeRole(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn addApplicationRoleToAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn removeApplicationRoleFromAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

/*
    static APIReturn doesRoleExist(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn validateApplicationScopeOnRole(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getRoleDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getRolesList(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getRoleApplicationScopes(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getRoleAccounts(void *context, const RequestParameters &request, ClientDetails &authClientDetails);*/
};
