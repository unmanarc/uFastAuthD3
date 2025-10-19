#pragma once

#include "IdentityManager/credentialvalidator.h"

#include "Web/AdminPortal/webadmin_endpoints_accounts.h"
#include "Web/AdminPortal/webadmin_endpoints_applications.h"
#include "Web/AdminPortal/webadmin_endpoints_application_scopes.h"
#include "Web/AdminPortal/webadmin_endpoints_application_roles.h"
#include "Web/AdminPortal/webadmin_endpoints_application_activities.h"
#include "Web/AdminPortal/webadmin_endpoints_authcontroller.h"

#include <json/json.h>

#include <Mantids30/API_RESTful/endpointshandler.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class WebAdmin_Endpoints : private WebAdminMethods_Accounts, private WebAdminMethods_Applications, private WebAdminMethods_ApplicationsScopes, private WebAdminMethods_ApplicationRoles, private WebAdmin_Endpoints_AuthController, private WebAdminMethods_ApplicationActivities
{
public:
    using Endpoints = Mantids30::API::RESTful::Endpoints;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;

    /**
    * @brief Adds the available login authentication methods as server functions.
    * @param methods The Endpoints to which the authentication methods will be added.
    */
    static void addEndpoints(std::shared_ptr<Endpoints> endpoints);

    // Helpers:
    static json scopeListToJSON(const std::set<ApplicationScope> &scopes);
    static std::set<ApplicationScope> iScopesLeftListForRole(const std::string &appName, const std::string &roleName);
};
