#pragma once

#include <Mantids30/API_RESTful/endpointshandler.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class WebAdminMethods_Applications
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

private:
    static json getLoginFlowDetails(const std::string & appName);
/*
    static APIReturn removeApplicationOwner(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getApplicationAPIKey(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateApplicationDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateApplicationAPIKey(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn listApplications(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn validateApplicationOwner(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn validateApplicationAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn listApplicationOwners(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn listApplicationAccounts(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn listAccountApplications(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn addApplicationOwner(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn listWebLoginRedirectURIsFromApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn listWebLoginOriginUrlsFromApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getWebLoginJWTConfigFromApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn setWebLoginJWTSigningKeyForApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getWebLoginJWTSigningKeyForApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails);*/
};

