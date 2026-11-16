#pragma once

#include <Mantids30/Server/WebRESTFul/api_restful_endpoints.h>
#include <Mantids30/DataFormat/JSON/json.h>
#include <Mantids30/Protocol/HTTP/httpv1_base.h>

class AdminPortal_Endpoints_Applications
{
public:
    using Endpoints = Mantids30::Server::WebRESTFul::RESTful::Endpoints;
    using APIReturn = Mantids30::Protocol::HTTP::APIReturn;
    using RequestContext = Mantids30::Server::WebRESTFul::RESTful::RequestContext;
    using ClientDetails = Mantids30::Server::WebRESTFul::Sessions::ClientDetails;

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
    static boost::json::value getLoginFlowDetails(const std::string &appName);
    static boost::json::value getApplicationAccountDetails(const std::string &appName);
};
