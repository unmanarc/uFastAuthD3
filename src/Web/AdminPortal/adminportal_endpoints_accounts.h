#pragma once

#include <Mantids30/API_EndpointsAndSessions/api_restful_endpoints.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class AdminPortal_Endpoints_Accounts
{
public:
    using Endpoints = Mantids30::API::RESTful::Endpoints;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestContext = Mantids30::API::RESTful::RequestContext;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

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
