#pragma once

#include <json/json.h>

#include <Mantids30/API_EndpointsAndSessions/api_restful_endpoints.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class UserPortal_Endpoints
{
public:
    using Endpoints = Mantids30::API::RESTful::Endpoints;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestContext = Mantids30::API::RESTful::RequestContext;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

    /**
    * @brief Adds the available login authentication methods as server functions.
    * @param methods The Endpoints to which the authentication methods will be added.
    */
    static void addEndpoints(const std::shared_ptr<Endpoints> &endpoints);

    static APIReturn getDashboardData(void *context, const RequestContext &request, ClientDetails &clientDetails);
    static APIReturn searchAccountSessions(void *context, const RequestContext &request, ClientDetails &clientDetails);
    static APIReturn searchAccountCredentialsActivity(void *context, const RequestContext &request, ClientDetails &clientDetails);
    static APIReturn getAccountDetailFieldsValues(void *context, const RequestContext &request, ClientDetails &clientDetails);
    static APIReturn updateAccountDetailFieldsValues(void *context, const RequestContext &request, ClientDetails &clientDetails);
    static APIReturn listAccountApplicationsFullInfo(void *context, const RequestContext &request, ClientDetails &clientDetails);
    static APIReturn listAllAuthCredentialSlotsPublicData(void *context, const RequestContext &request, ClientDetails &clientDetails);
    static APIReturn activateCredential(void *context, const RequestContext &request, ClientDetails &clientDetails);
    static APIReturn activateOTP(void *context, const RequestContext &request, ClientDetails &clientDetails);
    static APIReturn removeCredential(void *context, const RequestContext &request, ClientDetails &clientDetails);
    static APIReturn createChallengeToken(void *context, const RequestContext &request, ClientDetails &clientDetails);
    static APIReturn changeCredential(void *context, const RequestContext &request, ClientDetails &clientDetails);

    /**
     * @brief Returns the last login time for the authenticated user.
     * @param context Unused context pointer.
     * @param request The request parameters (JWT token provides the account name).
     * @param clientDetails Client session details.
     * @return APIReturn with lastLogin timestamp and ISO string.
     */
    static APIReturn getLastLogin(void *context, const RequestContext &request, ClientDetails &clientDetails);
};
