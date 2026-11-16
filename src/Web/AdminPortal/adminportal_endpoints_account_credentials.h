#pragma once

#include <Mantids30/Server/WebRESTFul/api_restful_endpoints.h>
#include <Mantids30/DataFormat/JSON/json.h>
#include <Mantids30/Protocol/HTTP/httpv1_base.h>

class AdminPortal_Endpoints_AccountCredentials
{
public:
    using Endpoints = Mantids30::Server::WebRESTFul::RESTful::Endpoints;
    using APIReturn = Mantids30::Protocol::HTTP::APIReturn;
    using RequestContext = Mantids30::Server::WebRESTFul::RESTful::RequestContext;
    using ClientDetails = Mantids30::Server::WebRESTFul::Sessions::ClientDetails;

protected:
    static void addEndpoints_AccountCredentials(const std::shared_ptr<Endpoints> &endpoints);

    // Account Credential Slots:
    static APIReturn getAccountCredentialSlots(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn removeAccountCredentialSlot(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn setAccountCredentialLockedStatus(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn setMustChangeCredential(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn cancelMustChangeCredential(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn generateMasterPassword(void *context, const RequestContext &request, ClientDetails &authClientDetails);
};
