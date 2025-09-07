#include "webadmin_methods_applications.h"

#include "../globals.h"
#include "defs.h"
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
    methods->addResource(MethodsHandler::POST, "addWebLoginOriginURLToApplication", &addWebLoginOriginURLToApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::POST, "removeWebLoginOriginURLToApplication", &removeWebLoginOriginURLToApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
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
    auto attrList = Globals::getIdentityManager()->authController->listApplicationScopes(appName);
    int i = 0;
    for (const auto &scope : attrList)
    {
        payloadOut["scopes"][i]["id"] = scope.id;
        payloadOut["scopes"][i]["description"] = Globals::getIdentityManager()->authController->getApplicationScopeDescription(scope);
        i++;
    }

    // Get associated direct accounts...
    auto acctList = Globals::getIdentityManager()->applications->listApplicationAccounts(appName);
    i = 0;
    for (const auto &acct : acctList)
    {
        auto getAccountDetails = Globals::getIdentityManager()->accounts->getAccountDetails(acct);
        payloadOut["accounts"][i]["name"] = acct;
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
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
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
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
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
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
        return;
    }
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


void WebAdminMethods_Applications::addWebLoginRedirectURIToApplication(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->addWebLoginRedirectURIToApplication(JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "loginRedirectURI", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::removeWebLoginRedirectURIToApplication(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->removeWebLoginRedirectURIToApplication(JSON_ASSTRING(*request.inputJSON, "appName", ""),
                                                                                             JSON_ASSTRING(*request.inputJSON, "loginRedirectURI", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::listWebLoginRedirectURIsFromApplication(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::listToJSON(Globals::getIdentityManager()->applications->listWebLoginRedirectURIsFromApplication(JSON_ASSTRING(*request.inputJSON, "appName", "")));
}

void WebAdminMethods_Applications::addWebLoginOriginURLToApplication(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->addWebLoginOriginURLToApplication(JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "originUrl", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Applications::removeWebLoginOriginURLToApplication(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->applications->removeWebLoginOriginURLToApplication(JSON_ASSTRING(*request.inputJSON, "appName", ""), JSON_ASSTRING(*request.inputJSON, "originUrl", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
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
