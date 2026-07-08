#pragma once

#include <Mantids30/API_EndpointsAndSessions/api_restful_endpoints.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class AdminPortal_Endpoints_Applications
{
public:
    using Endpoints = Mantids30::API::RESTful::Endpoints;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestContext = Mantids30::API::RESTful::RequestContext;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

protected:
    static void addEndpoints_Applications(const std::shared_ptr<Endpoints> &endpoints);

    static APIReturn searchApplications(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn removeApplication(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn addApplication(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn doesApplicationExist(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationInfo(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn updateApplicationDetails(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn updateApplicationAPIKey(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn updateAuthSettingsForApplication(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn updateApplicationLoginCallbackURI(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn addApplicationLoginOrigin(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn removeApplicationLoginOrigin(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn addApplicationLoginRedirectURI(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn removeApplicationLoginRedirectURI(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn updateWebLoginDefaultRedirectURIForApplication(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn setAccountAsApplicationAdmin(void *context, const RequestContext &request, ClientDetails &authClientDetails);

private:
    static Json::Value getLoginFlowDetails(const std::string &appName);
    static Json::Value getApplicationAccountDetails(const std::string &appName);
};
