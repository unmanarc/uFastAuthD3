#pragma once

#include <Mantids30/API_EndpointsAndSessions/api_restful_endpoints.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class AdminPortal_Endpoints_AccountCredentials
{
public:
    using Endpoints = Mantids30::API::RESTful::Endpoints;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

protected:
    static void addEndpoints_AccountCredentials(const std::shared_ptr<Endpoints> &endpoints);

    // Account Credential Slots:
    static APIReturn getAccountCredentialSlots(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn removeAccountCredentialSlot(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn setAccountCredentialLockedStatus(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn setMustChangeCredential(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn cancelMustChangeCredential(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn generateMasterPassword(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
};
