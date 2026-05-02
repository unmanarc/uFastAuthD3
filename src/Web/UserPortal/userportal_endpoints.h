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
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

    /**
    * @brief Adds the available login authentication methods as server functions.
    * @param methods The Endpoints to which the authentication methods will be added.
    */
    static void addEndpoints(std::shared_ptr<Endpoints> endpoints);

    /**
     * @brief Returns the last login time for the authenticated user.
     * @param context Unused context pointer.
     * @param request The request parameters (JWT token provides the account name).
     * @param clientDetails Client session details.
     * @return APIReturn with lastLogin timestamp and ISO string.
     */
    static APIReturn getLastLogin(void *context, const RequestParameters &request, ClientDetails &clientDetails);

};
