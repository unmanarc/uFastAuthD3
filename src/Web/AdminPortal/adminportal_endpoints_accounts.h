#pragma once

#include <Mantids30/Server/WebRESTFul/api_restful_endpoints.h>
#include <Mantids30/DataFormat/JSON/json.h>
#include <Mantids30/Protocol/HTTP/httpv1_base.h>

class AdminPortal_Endpoints_Accounts
{
public:
    using Endpoints = Mantids30::Server::WebRESTFul::RESTful::Endpoints;
    using APIReturn = Mantids30::Protocol::HTTP::APIReturn;
    using RequestContext = Mantids30::Server::WebRESTFul::RESTful::RequestContext;
    using ClientDetails = Mantids30::Server::WebRESTFul::Sessions::ClientDetails;

protected:
    static void addEndpoints_Accounts(const std::shared_ptr<Endpoints> &endpoints);

    static APIReturn extendInactivity(void *context, const RequestContext &request, ClientDetails &authClientDetails);

    // Accounts:
    static APIReturn createAccount(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn getAccountDisplayName(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn searchAccounts(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn removeAccount(void *context, const RequestContext &request, ClientDetails &authClientDetails);

    // Fields:
    static APIReturn listDetailFields(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn searchFields(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn createAccountDetailField(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn updateAccountDetailField(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn removeAccountDetailField(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn getAccountDetailField(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn moveAccountDetailFieldUp(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn moveAccountDetailFieldDown(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn getAccountDetailFieldsValues(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn updateAccountDetailFieldsValues(void *context, const RequestContext &request, ClientDetails &authClientDetails);

    // Flags:
    static APIReturn getAccountFlags(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn changeAccountFlags(void *context, const RequestContext &request, ClientDetails &authClientDetails);

    // Accounts-Applications
    static APIReturn getAccountApplications(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn addAccountToApplication(void *context, const RequestContext &request, ClientDetails &authClientDetails);
    static APIReturn removeAccountFromApplication(void *context, const RequestContext &request, ClientDetails &authClientDetails);

};
