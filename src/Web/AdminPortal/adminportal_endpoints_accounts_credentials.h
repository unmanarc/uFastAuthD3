#pragma once

#include <Mantids30/API_EndpointsAndSessions/api_restful_endpoints.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class AdminPortal_Endpoints_AccountsCredentials
{
public:
    using Endpoints = Mantids30::API::RESTful::Endpoints;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestContext = Mantids30::API::RESTful::RequestContext;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

protected:
    static void addEndpoints_AccountsCredentials(std::shared_ptr<Endpoints> endpoints);

    // Account Credential Slots:
    static APIReturn getAccountCredentialSlots(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn removeAccountCredentialSlot(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn setAccountCredentialLockedStatus(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn unsetAccountCredentialLockedStatus(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn setMustChangeCredential(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn cancelMustChangeCredential(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn generateMasterPassword(void *context, const RequestContext &request, ClientDetails &authClientDetails);
};