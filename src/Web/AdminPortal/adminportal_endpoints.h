#pragma once

#include "IdentityManager/credentialvalidator.h"

#include "Web/AdminPortal/adminportal_endpoints_account_credentials.h"
#include "Web/AdminPortal/adminportal_endpoints_accounts.h"
#include "Web/AdminPortal/adminportal_endpoints_application_activities.h"
#include "Web/AdminPortal/adminportal_endpoints_application_roles.h"
#include "Web/AdminPortal/adminportal_endpoints_application_scopes.h"
#include "Web/AdminPortal/adminportal_endpoints_applications.h"
#include "Web/AdminPortal/adminportal_endpoints_authcontroller.h"

#include <Mantids30/DataFormat/JSON/json.h>

#include <Mantids30/Server/WebRESTFul/api_restful_endpoints.h>
#include <Mantids30/DataFormat/JSON/json.h>
#include <Mantids30/Protocol/HTTP/httpv1_base.h>

class AdminPortal_Endpoints : private AdminPortal_Endpoints_Accounts,
                              private AdminPortal_Endpoints_AccountCredentials,
                              private AdminPortal_Endpoints_Applications,
                              private AdminPortal_Endpoints_ApplicationsScopes,
                              private AdminPortal_Endpoints_ApplicationRoles,
                              private AdminPortal_Endpoints_AuthController,
                              private AdminPortal_Endpoints_ApplicationActivities
{
public:
    using Endpoints = Mantids30::Server::WebRESTFul::RESTful::Endpoints;
    using APIReturn = Mantids30::Protocol::HTTP::APIReturn;
    using RequestContext = Mantids30::Server::WebRESTFul::RESTful::RequestContext;

    /**
    * @brief Adds the available login authentication methods as server functions.
    * @param methods The Endpoints to which the authentication methods will be added.
    */
    static void addEndpoints(const std::shared_ptr<Endpoints> &endpoints);

    // Helpers:
    static boost::json::array scopeListtoJSON(const std::set<ApplicationScope> &scopes);
    static std::set<ApplicationScope> iScopesLeftListForRole(const std::string &appName, const std::string &roleName);
};
