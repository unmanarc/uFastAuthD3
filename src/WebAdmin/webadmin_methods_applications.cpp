#include "webadmin_methods_applications.h"

#include "../globals.h"
#include "defs.h"
#include "json/value.h"
#include <Mantids30/Program_Logs/applog.h>

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocols;

using ClientDetails = Mantids30::Sessions::ClientDetails;

void WebAdminMethods_Applications::addMethods_Applications(std::shared_ptr<MethodsHandler> methods)
{
    using SecurityOptions = Mantids30::API::RESTful::MethodsHandler::SecurityOptions;
    methods->addResource(MethodsHandler::GET, "searchApplications", &searchApplications, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::DELETE, "removeApplication", &removeApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_DELETE"});
    methods->addResource(MethodsHandler::POST, "addApplication", &addApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_CREATE"});
    methods->addResource(MethodsHandler::GET, "doesApplicationExist", &doesApplicationExist, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "getApplicationInfo", &getApplicationInfo, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::PATCH, "updateApplicationDescription", &updateApplicationDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::PATCH, "updateApplicationAPIKey", &updateApplicationAPIKey, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::PATCH, "updateWebLoginJWTConfigForApplication", &updateWebLoginJWTConfigForApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::PATCH, "updateApplicationLoginCallbackURI", &updateApplicationLoginCallbackURI, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});

    methods->addResource(MethodsHandler::PUT, "addApplicationLoginOrigin", &addApplicationLoginOrigin, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::DELETE, "removeApplicationLoginOrigin", &removeApplicationLoginOrigin, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});

    methods->addResource(MethodsHandler::PUT, "addApplicationLoginRedirectURI", &addApplicationLoginRedirectURI, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::DELETE, "removeApplicationLoginRedirectURI", &removeApplicationLoginRedirectURI, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});

    // Applications
   /*
    methods->addResource(MethodsHandler::GET, "getApplicationDescription", &getApplicationDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "listApplications", &listApplications, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "validateApplicationOwner", &validateApplicationOwner, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "validateApplicationAccount", &validateApplicationAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "listApplicationOwners", &listApplicationOwners, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "listApplicationAccounts", &listApplicationAccounts, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "listAccountApplications", &listAccountApplications, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::POST, "addApplicationOwner", &addApplicationOwner, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::POST, "removeApplicationOwner", &removeApplicationOwner, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::GET, "getWebLoginJWTConfigFromApplication", &getWebLoginJWTConfigFromApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::POST, "setWebLoginJWTSigningKeyForApplication", &setWebLoginJWTSigningKeyForApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::GET, "getWebLoginJWTSigningKeyForApplication", &getWebLoginJWTSigningKeyForApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::POST, "addWebLoginRedirectURIToApplication", &addWebLoginRedirectURIToApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::POST, "removeWebLoginRedirectURIToApplication", &removeWebLoginRedirectURIToApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::GET, "listWebLoginRedirectURIsFromApplication", &listWebLoginRedirectURIsFromApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "listWebLoginOriginUrlsFromApplication", &listWebLoginOriginUrlsFromApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});*/
}


void WebAdminMethods_Applications::searchApplications(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->applications->searchApplications(*request.inputJSON);
}

void WebAdminMethods_Applications::removeApplication(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName == DB_APPNAME)
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Can't remove the IAM application");
        return;
    }

    // Validate input data
    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return;
    }

    if (!Globals::getIdentityManager()->applications->removeApplication(appName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
        return;
    }
}
void WebAdminMethods_Applications::addApplication(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{

    // Extract application name and description from input JSON
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string appDescription = JSON_ASSTRING(*request.inputJSON, "appDescription", "");

    // Validate input data
    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return;
    }

    if (appName.length() > 255)
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name must be less than 255 characters");
        return;
    }

    // Check for invalid characters in appName
    if (appName.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != std::string::npos)
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name contains invalid characters");
        return;
    }

    // Validate that the application doesn't already exist
    if (Globals::getIdentityManager()->applications->doesApplicationExist(appName))
    {
        response.setError(HTTP::Status::S_409_CONFLICT, "conflict", "Application already exists");
        return;
    }

    // Attempt to create the new application
    if (!Globals::getIdentityManager()->applications->addApplication(JSON_ASSTRING(*request.inputJSON, "appName", ""),
                                                                     JSON_ASSTRING(*request.inputJSON, "description", ""),
                                                                     JSON_ASSTRING(*request.inputJSON, "appKey", ""),
                                                                     request.jwtToken->getSubject(),
                                                                     JSON_ASBOOL(*request.inputJSON, "scopesModifiable", false)
                                                                     ))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to create application");
        return;
    }

    return;
}

void WebAdminMethods_Applications::doesApplicationExist(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return;
    }

    if (!Globals::getIdentityManager()->applications->doesApplicationExist(appName))
    {
        response.setError(HTTP::Status::S_404_NOT_FOUND, "not_found", "The Application does not exist in the system.");
        return;
    }

}
void WebAdminMethods_Applications::getApplicationInfo(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    json payloadOut;
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");


    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return;
    }

    payloadOut["loginFlow"] = getLoginFlowDetails(appName);
    
    auto scopesModifiable = Globals::getIdentityManager()->applications->canManuallyModifyApplicationScopes(appName);
    if (scopesModifiable.has_value())
    {
        payloadOut["advanced"]["scopesModifiable"] = scopesModifiable.value();
    }
    else
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to retrieve scopes modifiable status");
        return;
    }

    ApplicationTokenProperties appWebLoginTokenConfig = Globals::getIdentityManager()->applications->getWebLoginJWTConfigFromApplication(appName);
    payloadOut["tokenConfig"] = appWebLoginTokenConfig.toJSON();
    payloadOut["details"]["description"] = Globals::getIdentityManager()->applications->getApplicationDescription(appName);

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
    std::set<std::string> acctList = Globals::getIdentityManager()->applications->listApplicationAccounts(appName);
    i = 0;
    payloadOut["accounts"] = Json::arrayValue;
    for (const auto &acct : acctList)
    {
        auto getAccountDetails = Globals::getIdentityManager()->accounts->getAccountDetails(acct);
        payloadOut["accounts"][i]["name"] = acct;
        i++;
    }


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
}

void WebAdminMethods_Applications::updateApplicationDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return;
    }

    if (!Globals::getIdentityManager()->applications->updateApplicationDescription(appName, JSON_ASSTRING(*request.inputJSON, "description", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update application description.");
    }
}

void WebAdminMethods_Applications::updateApplicationAPIKey(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return;
    }

    if (!Globals::getIdentityManager()->applications->updateApplicationAPIKey(appName, JSON_ASSTRING(*request.inputJSON, "appKey", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update application API key.");
    }
}


void WebAdminMethods_Applications::updateWebLoginJWTConfigForApplication(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    ApplicationTokenProperties tokenInfo;
    auto err = tokenInfo.fromJSON( *request.inputJSON );
    if (err.has_value())
    {
        response.setError((Network::Protocols::HTTP::Status::Codes)err->http_code, err->error, err->message);
        return;
    }

    if (!Globals::getIdentityManager()->applications->updateWebLoginJWTConfigForApplication(tokenInfo))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update web login JWT configuration.");
        return;
    }
}

void WebAdminMethods_Applications::updateApplicationLoginCallbackURI(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string callbackURI = JSON_ASSTRING(*request.inputJSON, "callbackURI", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return;
    }

    if (!Globals::getIdentityManager()->applications->setApplicationWebLoginCallbackURI(appName, callbackURI))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the callback URI.");
        return;
    }

    (*response.responseJSON()) = getLoginFlowDetails(appName);
}

void WebAdminMethods_Applications::addApplicationLoginOrigin(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return;
    }


    if (!Globals::getIdentityManager()->applications->addWebLoginOriginURLToApplication(appName, JSON_ASSTRING(*request.inputJSON, "loginOrigin", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add login origin. Please check if the database is accessible or if the value already exists.");
        return;
    }

    (*response.responseJSON()) = getLoginFlowDetails(appName);

}

void WebAdminMethods_Applications::removeApplicationLoginOrigin(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return;
    }

    if (!Globals::getIdentityManager()->applications->removeWebLoginOriginURLToApplication(appName, JSON_ASSTRING(*request.inputJSON, "loginOrigin", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove login origin. Refresh and try again.");
        return;
    }

    (*response.responseJSON()) = getLoginFlowDetails(appName);
}


void WebAdminMethods_Applications::addApplicationLoginRedirectURI(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return;
    }

    if (!Globals::getIdentityManager()->applications->addWebLoginRedirectURIToApplication(appName, JSON_ASSTRING(*request.inputJSON, "redirectURI", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add redirect URI. Please check if the database is accessible or if the value already exists.");
        return;
    }

    (*response.responseJSON()) = getLoginFlowDetails(appName);

}

void WebAdminMethods_Applications::removeApplicationLoginRedirectURI(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty");
        return;
    }

    if (!Globals::getIdentityManager()->applications->removeWebLoginRedirectURIToApplication(appName,
                                                                                             JSON_ASSTRING(*request.inputJSON, "redirectURI", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove redirect URI. Refresh and try again.");
        return;
    }

    (*response.responseJSON()) = getLoginFlowDetails(appName);

}


json WebAdminMethods_Applications::getLoginFlowDetails(const std::string &appName)
{
    json payloadOut;
    payloadOut["callbackURI"]  = Globals::getIdentityManager()->applications->getApplicationCallbackURI(appName);
    std::list<std::string> webLoginOrigins = Globals::getIdentityManager()->applications->listWebLoginOriginUrlsFromApplication(appName);
    for (const auto & url : webLoginOrigins)
    {
        payloadOut["loginOrigins"].append(url);
    }
    std::list<std::string> acceptedRedirectURIs = Globals::getIdentityManager()->applications->listWebLoginRedirectURIsFromApplication(appName);
    for (const auto & url : acceptedRedirectURIs)
    {
        payloadOut["redirectURIs"].append(url);
    }
    return payloadOut;
}

/*
void WebAdminMethods_Applications::getApplicationDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->applications->getApplicationDescription(JSON_ASSTRING(*request.inputJSON, "appName", ""));
}*/
/*
void WebAdminMethods_Applications::getApplicationAPIKey(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{

    payloadOut["appKey"] = Globals::getIdentityManager()->getApplicationAPIKey( JSON_ASSTRING(*request.inputJSON,"appName",""));
    return payloadOut;
}


void WebAdminMethods_Applications::listApplications(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->applications->listApplications());
}

void WebAdminMethods_Applications::validateApplicationOwner(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->validateApplicationOwner(JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "accountName", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::validateApplicationAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->validateApplicationAccount(JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "accountName", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::listApplicationOwners(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->applications->listApplicationOwners(JSON_ASSTRING(*request.inputJSON, "applicationName", "")));
}

void WebAdminMethods_Applications::listApplicationAccounts(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->applications->listApplicationAccounts(JSON_ASSTRING(*request.inputJSON, "applicationName", "")));
}

void WebAdminMethods_Applications::listAccountApplications(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->applications->listAccountApplications(JSON_ASSTRING(*request.inputJSON, "accountName", "")));
}


void WebAdminMethods_Applications::addApplicationOwner(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->addApplicationOwner(JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "accountName", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::removeApplicationOwner(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->removeApplicationOwner(JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "accountName", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}


void WebAdminMethods_Applications::listWebLoginRedirectURIsFromApplication(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::listToJSON(Globals::getIdentityManager()->applications->listWebLoginRedirectURIsFromApplication(JSON_ASSTRING(*request.inputJSON, "appName", "")));
}



void WebAdminMethods_Applications::listWebLoginOriginUrlsFromApplication(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::listToJSON(Globals::getIdentityManager()->applications->listWebLoginOriginUrlsFromApplication(JSON_ASSTRING(*request.inputJSON, "appName", "")));
}


void WebAdminMethods_Applications::getWebLoginJWTConfigFromApplication(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    json payloadOut;
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    ApplicationTokenProperties tokenInfo = Globals::getIdentityManager()->applications->getWebLoginJWTConfigFromApplication(appName);

    payloadOut["appName"] = tokenInfo.appName;
    payloadOut["tokensConfiguration"] = tokenInfo.tokensConfiguration;
    payloadOut["tempMFATokenTimeout"] = tokenInfo.tempMFATokenTimeout;
    payloadOut["sessionInactivityTimeout"] = tokenInfo.sessionInactivityTimeout;
    payloadOut["tokenType"] = tokenInfo.tokenType;
    payloadOut["includeApplicationScopes"] = tokenInfo.includeApplicationScopes;
    payloadOut["includeBasicAccountInfo"] = tokenInfo.includeBasicAccountInfo;
    payloadOut["maintainRevocationAndLogoutInfo"] = tokenInfo.maintainRevocationAndLogoutInfo;
    payloadOut["allowRefreshTokenRenovation"] = tokenInfo.allowRefreshTokenRenovation;

    (*response.responseJSON()) = payloadOut;
}

void WebAdminMethods_Applications::setWebLoginJWTSigningKeyForApplication(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string signingKey = JSON_ASSTRING(*request.inputJSON, "signingKey", "");

    if (!Globals::getIdentityManager()->applications->setWebLoginJWTSigningKeyForApplication(appName, signingKey))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::getWebLoginJWTSigningKeyForApplication(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string signingKey = Globals::getIdentityManager()->applications->getWebLoginJWTSigningKeyForApplication(appName);
    (*response.responseJSON()) = signingKey;
}*/
