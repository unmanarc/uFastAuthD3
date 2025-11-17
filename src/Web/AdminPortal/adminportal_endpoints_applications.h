#pragma once

#include <Mantids30/API_EndpointsAndSessions/api_restful_endpoints.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class AdminPortalMethods_Applications
{
public:
    using Endpoints = Mantids30::API::RESTful::Endpoints;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

protected:
    static void addEndpoints_Applications(std::shared_ptr<Endpoints> endpoints);

    static APIReturn searchApplications(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn removeApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn addApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn doesApplicationExist(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationInfo(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateApplicationDetails(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateApplicationAPIKey(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateWebLoginJWTConfigForApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateApplicationLoginCallbackURI(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

    static APIReturn addApplicationLoginOrigin(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn removeApplicationLoginOrigin(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

    static APIReturn addApplicationLoginRedirectURI(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn removeApplicationLoginRedirectURI(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

    static APIReturn updateWebLoginDefaultRedirectURIForApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

    static APIReturn changeApplicationAdmin(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

private:
    static json getLoginFlowDetails(const std::string & appName);
    static json getApplicationAccountDetails(const std::string & appName);
/*
    static APIReturn removeApplicationAdmin(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationAPIKey(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateApplicationDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateApplicationAPIKey(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn listApplications(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn isApplicationAdmin(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn validateApplicationAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn listApplicationAdmins(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn listApplicationAccounts(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn listAccountApplications(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn addApplicationAdmin(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn listWebLoginAllowedRedirectURIsFromApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn listWebLoginOriginUrlsFromApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getWebLoginJWTConfigFromApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn setWebLoginJWTSigningKeyForApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getWebLoginJWTSigningKeyForApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails);*/
};

