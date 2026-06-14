#include "adminportal_endpoints_applications.h"

#include "globals.h"
#include "Mantids30/Protocol_HTTP/api_return.h"
#include "defs.h"
#include <json/value.h>
#include <Mantids30/Program_Logs/applog.h>
#include <optional>
#include <string>

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocols;

using ClientDetails = Mantids30::Sessions::ClientDetails;

void AdminPortal_Endpoints_Applications::addEndpoints_Applications(std::shared_ptr<Endpoints> endpoints)
{
    using SecurityOptions = Mantids30::API::RESTful::Endpoints::SecurityOptions;

    endpoints->addEndpoint(Endpoints::GET,    "searchApplications",                             SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"},     nullptr, &searchApplications);
    endpoints->addEndpoint(Endpoints::DELETE, "removeApplication",                              SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_DELETE"},   nullptr, &removeApplication);
    endpoints->addEndpoint(Endpoints::POST,   "addApplication",                                 SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_CREATE"},   nullptr, &addApplication);
    endpoints->addEndpoint(Endpoints::GET,    "doesApplicationExist",                           SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"},     nullptr, &doesApplicationExist);
    endpoints->addEndpoint(Endpoints::GET,    "getApplicationInfo",                             SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"},     nullptr, &getApplicationInfo);
    endpoints->addEndpoint(Endpoints::PATCH,  "updateApplicationDetails",                       SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"},   nullptr, &updateApplicationDetails);
    endpoints->addEndpoint(Endpoints::PATCH,  "updateApplicationAPIKey",                        SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"},   nullptr, &updateApplicationAPIKey);
    endpoints->addEndpoint(Endpoints::PATCH,  "updateWebLoginJWTConfigForApplication",          SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"},   nullptr, &updateWebLoginJWTConfigForApplication);
    endpoints->addEndpoint(Endpoints::PATCH,  "updateApplicationLoginCallbackURI",              SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"},   nullptr, &updateApplicationLoginCallbackURI);
    endpoints->addEndpoint(Endpoints::PUT,    "addApplicationLoginOrigin",                      SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"},   nullptr, &addApplicationLoginOrigin);
    endpoints->addEndpoint(Endpoints::DELETE, "removeApplicationLoginOrigin",                   SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"},   nullptr, &removeApplicationLoginOrigin);
    endpoints->addEndpoint(Endpoints::PUT,    "addApplicationLoginRedirectURI",                 SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"},   nullptr, &addApplicationLoginRedirectURI);
    endpoints->addEndpoint(Endpoints::DELETE, "removeApplicationLoginRedirectURI",              SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"},   nullptr, &removeApplicationLoginRedirectURI);
    endpoints->addEndpoint(Endpoints::PATCH,  "updateWebLoginDefaultRedirectURIForApplication", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"},   nullptr, &updateWebLoginDefaultRedirectURIForApplication);
    endpoints->addEndpoint(Endpoints::PATCH,  "changeApplicationAdmin",                         SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"},   nullptr, &changeApplicationAdmin);
}

API::APIReturn AdminPortal_Endpoints_Applications::searchApplications(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    return Globals::getIdentityManager()->applications->searchApplications(*request.inputJSON);
}

API::APIReturn AdminPortal_Endpoints_Applications::removeApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName == IAM_ADMPORTAL_APPNAME)
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Can't remove the IAM application");
        return response;
    }

    // Validate input data
    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applications->removeApplication(authClientDetails, request.jwtToken->getSubject(),appName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
        return response;
    }
    return response;

}
API::APIReturn AdminPortal_Endpoints_Applications::addApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    // Extract application name and description from input JSON
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string appDescription = JSON_ASSTRING(*request.inputJSON, "appDescription", "");

    // Validate input data
    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (appName.length() > 255)
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name must be less than 255 characters");
        return response;
    }

    // Check for invalid characters in appName
    if (appName.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != std::string::npos)
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name contains invalid characters");
        return response;
    }

    // Validate that the application doesn't already exist
    if (Globals::getIdentityManager()->applications->doesApplicationExist(appName))
    {
        response.setError(HTTP::Status::S_409_CONFLICT, "conflict", "Application already exists");
        return response;
    }

    IdentityManager::Applications::ApplicationAttributes attribs;
    attribs.fromJSON((*request.inputJSON)["applicationAttributes"]);

    // Attempt to create the new application
    if (!Globals::getIdentityManager()->applications->addApplication(
                                                                        authClientDetails, request.jwtToken->getSubject(),

                                                                     JSON_ASSTRING(*request.inputJSON, "appName", ""),
                                                                     JSON_ASSTRING(*request.inputJSON, "description", ""),
                                                                     JSON_ASSTRING(*request.inputJSON, "appURL", ""),
                                                                     JSON_ASSTRING(*request.inputJSON, "appKey", ""),
                                                                     request.jwtToken->getSubject(),
                                                                     attribs,
                                                                     JSON_ASBOOL(*request.inputJSON, "initializeDefaults", true)
                                                                     ))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to create application");
        return response;
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_Applications::doesApplicationExist(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return response;
    }

    if (!Globals::getIdentityManager()->applications->doesApplicationExist(appName))
    {
        response.setError(HTTP::Status::S_404_NOT_FOUND, "not_found", "The Application does not exist in the system.");
        return response;
    }
    return response;

}

AdminPortal_Endpoints_Applications::APIReturn AdminPortal_Endpoints_Applications::changeApplicationAdmin(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return response;
    }

    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty");
        return response;
    }

    if (!Globals::getIdentityManager()->applications->changeApplicationAdmin(authClientDetails, request.jwtToken->getSubject(),appName,accountName, JSON_ASBOOL(*request.inputJSON, "isAppAdmin", false) ))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
        return getApplicationAccountDetails(appName);
    }
    return getApplicationAccountDetails(appName);
}


API::APIReturn AdminPortal_Endpoints_Applications::getApplicationInfo(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    json payloadOut;
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return response;
    }

    payloadOut["loginFlow"] = getLoginFlowDetails(appName);

    std::optional<IdentityManager::Applications::ApplicationAttributes> attribs = Globals::getIdentityManager()->applications->getApplicationAttributes(appName);

    if (!attribs.has_value())
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to retrieve the application attributes");
        return response;
    }

    ApplicationTokenProperties appWebLoginTokenConfig = Globals::getIdentityManager()->applications->getWebLoginJWTConfigFromApplication(appName);
    payloadOut["tokenConfig"] = appWebLoginTokenConfig.toJSON();
    payloadOut["details"]["description"] = Globals::getIdentityManager()->applications->getApplicationDescription(appName);
    payloadOut["applicationAttributes"] = attribs->toJSON();

    // Get associated scope...
    payloadOut["scopes"] = Json::arrayValue;
    std::set<ApplicationScope> attrList = Globals::getIdentityManager()->authController->listApplicationScopes(appName);
    int i = 0;
    for (const auto &scope : attrList)
    {
        payloadOut["scopes"][i] = scope.toJSON();
        i++;
    }

    // Get associated direct accounts...
    payloadOut["accounts"] = getApplicationAccountDetails(appName);



    std::map<std::string, IdentityManager::ApplicationActivities::ActivityData> activities = Globals::getIdentityManager()->applicationActivities->listApplicationActivities(appName);
    i=0;
    payloadOut["activities"] = Json::arrayValue;
    for ( const auto & activity : activities )
    {
        payloadOut["activities"][i] = activity.second.toJSON();
        payloadOut["activities"][i]["name"] = activity.first;
        i++;
    }

    (*response.responseJSON()) = payloadOut;
    return response;

}

API::APIReturn AdminPortal_Endpoints_Applications::updateApplicationDetails(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    IdentityManager::Applications::ApplicationAttributes attribs;
    attribs.fromJSON((*request.inputJSON)["applicationAttributes"]);

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return response;
    }

    if (!Globals::getIdentityManager()->applications->updateApplicationAttributes(authClientDetails, request.jwtToken->getSubject(),appName, attribs))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update some application attributes.");
        return response;
    }

    if (!Globals::getIdentityManager()->applications->updateApplicationDescription(authClientDetails, request.jwtToken->getSubject(),appName, JSON_ASSTRING(*request.inputJSON, "description", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update application description.");
    }
    return response;

}

API::APIReturn AdminPortal_Endpoints_Applications::updateApplicationAPIKey(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return response;
    }

    if (!Globals::getIdentityManager()->applications->updateApplicationAPIKey(authClientDetails, request.jwtToken->getSubject(),appName, JSON_ASSTRING(*request.inputJSON, "appKey", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update application API key.");
    }
    return response;

}


API::APIReturn AdminPortal_Endpoints_Applications::updateWebLoginJWTConfigForApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    ApplicationTokenProperties tokenInfo;
    auto err = tokenInfo.fromJSON( *request.inputJSON );
    if (err.has_value())
    {
        response.setError((Network::Protocols::HTTP::Status::Codes)err->http_code, err->error, err->message);
        return response;
    }

    if (!Globals::getIdentityManager()->applications->updateWebLoginJWTConfigForApplication(authClientDetails, request.jwtToken->getSubject(),tokenInfo))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update web login JWT configuration.");
        return response;
    }
    return response;

}



API::APIReturn AdminPortal_Endpoints_Applications::updateApplicationLoginCallbackURI(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string callbackURI = JSON_ASSTRING(*request.inputJSON, "callbackURI", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return response;
    }

    if (!Globals::getIdentityManager()->applications->setApplicationWebLoginCallbackURI(authClientDetails, request.jwtToken->getSubject(),appName, callbackURI))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the callback URI.");
        return response;
    }

    (*response.responseJSON()) = getLoginFlowDetails(appName);
    return response;
}

API::APIReturn AdminPortal_Endpoints_Applications::addApplicationLoginOrigin(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return response;
    }


    if (!Globals::getIdentityManager()->applications->addWebLoginOriginURLToApplication(authClientDetails, request.jwtToken->getSubject(),appName, JSON_ASSTRING(*request.inputJSON, "loginOrigin", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add login origin. Please check if the database is accessible or if the value already exists.");
        return response;
    }

    (*response.responseJSON()) = getLoginFlowDetails(appName);
    return response;

}

API::APIReturn AdminPortal_Endpoints_Applications::removeApplicationLoginOrigin(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return response;
    }

    if (!Globals::getIdentityManager()->applications->removeWebLoginOriginURLToApplication(authClientDetails, request.jwtToken->getSubject(),appName, JSON_ASSTRING(*request.inputJSON, "loginOrigin", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove login origin. Refresh and try again.");
        return response;
    }

    (*response.responseJSON()) = getLoginFlowDetails(appName);
    return response;
}


API::APIReturn AdminPortal_Endpoints_Applications::addApplicationLoginRedirectURI(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return response;
    }

    if (!Globals::getIdentityManager()->applications->addWebLoginAllowedRedirectURIToApplication(authClientDetails, request.jwtToken->getSubject(),appName, JSON_ASSTRING(*request.inputJSON, "redirectURI", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add redirect URI. Please check if the database is accessible or if the value already exists.");
        return response;
    }

    (*response.responseJSON()) = getLoginFlowDetails(appName);
    return response;

}

API::APIReturn AdminPortal_Endpoints_Applications::removeApplicationLoginRedirectURI(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return response;
    }

    if (!Globals::getIdentityManager()->applications->removeWebLoginAllowedRedirectURIToApplication(authClientDetails, request.jwtToken->getSubject(),appName,
                                                                                             JSON_ASSTRING(*request.inputJSON, "redirectURI", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove redirect URI. Refresh and try again.");
        return response;
    }

    (*response.responseJSON()) = getLoginFlowDetails(appName);
    return response;
}

AdminPortal_Endpoints_Applications::APIReturn AdminPortal_Endpoints_Applications::updateWebLoginDefaultRedirectURIForApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return response;
    }

    if (!Globals::getIdentityManager()->applications->updateWebLoginDefaultRedirectURIForApplication(authClientDetails, request.jwtToken->getSubject(),appName,JSON_ASSTRING(*request.inputJSON, "redirectURI", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to set default redirect URI. Please verify the application name and URI are valid.");
        return response;
    }

    (*response.responseJSON()) = getLoginFlowDetails(appName);
    return response;
}


json AdminPortal_Endpoints_Applications::getLoginFlowDetails(const std::string &appName)
{
    json payloadOut;

    std::set<std::string> webLoginOrigins      = Globals::getIdentityManager()->applications->listWebLoginOriginUrlsFromApplication(appName);
    std::set<std::string> acceptedRedirectURIs = Globals::getIdentityManager()->applications->listWebLoginAllowedRedirectURIsFromApplication(appName);

    payloadOut["callbackURI"]        = Globals::getIdentityManager()->applications->getApplicationCallbackURI(appName);
    payloadOut["defaultRedirectURI"] = Globals::getIdentityManager()->applications->getWebLoginDefaultRedirectURIForApplication(appName);
    payloadOut["loginOrigins"]       = Json::arrayValue;
    payloadOut["redirectURIs"]       = Json::arrayValue;

    for (const std::string & url : webLoginOrigins)
    {
        payloadOut["loginOrigins"].append(url);
    }
    for (const std::string & url : acceptedRedirectURIs)
    {
        payloadOut["redirectURIs"].append(url);
    }

    return payloadOut;
}

json AdminPortal_Endpoints_Applications::getApplicationAccountDetails(const std::string &appName)
{
    json payloadOut;
    std::set<std::string> acctList = Globals::getIdentityManager()->applications->listApplicationAccounts(appName);
    std::set<std::string> appAdmins = Globals::getIdentityManager()->applications->listApplicationAdmins(appName);
    uint32_t i = 0;
    payloadOut = Json::arrayValue;
    for (const auto &acct : acctList)
    {
        payloadOut[i]["name"] = acct;
        payloadOut[i]["isAppAdmin"] = (appAdmins.find(acct) != appAdmins.end());
        i++;
    }
    return payloadOut;
}
