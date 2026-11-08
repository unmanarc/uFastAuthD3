#include "adminportal_endpoints_applications.h"

#include "defs.h"
#include "globals.h"
#include <Mantids30/DataFormat_JSON/json.h>
#include <Mantids30/Program_Logs/applog.h>
#include <Mantids30/Protocol_HTTP/api_return.h>
#include <optional>
#include <string>

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocol;

using ClientDetails = Mantids30::Sessions::ClientDetails;

void AdminPortal_Endpoints_Applications::addEndpoints_Applications(const std::shared_ptr<Endpoints> &endpoints)
{
    using SecurityRequirements = API::Security::Requirements;

    endpoints->addEndpoint(HTTP::Method::GET, "searchApplications", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_READ"}, nullptr, &searchApplications);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeApplication", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_DELETE"}, nullptr, &removeApplication);
    endpoints->addEndpoint(HTTP::Method::POST, "createApplication", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_CREATE"}, nullptr, &addApplication);
    endpoints->addEndpoint(HTTP::Method::GET, "doesApplicationExist", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_READ"}, nullptr, &doesApplicationExist);
    endpoints->addEndpoint(HTTP::Method::GET, "getApplicationInfo", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_READ"}, nullptr, &getApplicationInfo);
    endpoints->addEndpoint(HTTP::Method::PATCH, "updateApplicationDetails", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &updateApplicationDetails);
    endpoints->addEndpoint(HTTP::Method::PATCH, "updateApplicationAPIKey", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &updateApplicationAPIKey);
    endpoints->addEndpoint(HTTP::Method::PATCH, "updateAuthSettingsForApplication", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &updateAuthSettingsForApplication);
    endpoints->addEndpoint(HTTP::Method::PATCH, "updateApplicationLoginCallbackURI", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &updateApplicationLoginCallbackURI);
    endpoints->addEndpoint(HTTP::Method::PUT, "addApplicationLoginOrigin", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &addApplicationLoginOrigin);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeApplicationLoginOrigin", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &removeApplicationLoginOrigin);
    endpoints->addEndpoint(HTTP::Method::PUT, "addApplicationLoginRedirectURI", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &addApplicationLoginRedirectURI);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeApplicationLoginRedirectURI", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &removeApplicationLoginRedirectURI);
    endpoints->addEndpoint(HTTP::Method::PATCH,
                           "updateWebLoginDefaultRedirectURIForApplication",
                           SecurityRequirements::JWT_COOKIE_AUTH,
                           {"APP_MODIFY"},
                           nullptr,
                           &updateWebLoginDefaultRedirectURIForApplication);
    endpoints->addEndpoint(HTTP::Method::PATCH, "setAccountAsApplicationAdmin", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &setAccountAsApplicationAdmin);
}

API::APIReturn AdminPortal_Endpoints_Applications::searchApplications(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    return Globals::getIdentityManager()->applications->searchApplications(*request.inputJSON);
}

API::APIReturn AdminPortal_Endpoints_Applications::removeApplication(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName(Helpers::JSON::ASSTRING(*request.inputJSON, "appName", ""));

    if (appName == IAM_ADMPORTAL_APPNAME)
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Can't remove the IAM application"};
    }

    // Validate input data
    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required"};
    }

    if (!Globals::getIdentityManager()->applications->removeApplication(authClientDetails, request.jwtToken->getSubject(), appName))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error"};
    }
    return response;
}
API::APIReturn AdminPortal_Endpoints_Applications::addApplication(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    // Extract application name and description from input JSON
    std::string appName(Helpers::JSON::ASSTRING(*request.inputJSON, "appName", ""));
    std::string appDescription(Helpers::JSON::ASSTRING(*request.inputJSON, "description", ""));

    // Validate input data
    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required"};
    }

    if (appName.length() > 255)
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name must be less than 255 characters"};
    }

    // Check for invalid characters in appName
    if (appName.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != std::string::npos)
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name contains invalid characters"};
    }

    // Validate that the application doesn't already exist
    if (Globals::getIdentityManager()->applications->doesApplicationExist(appName))
    {
        return {HTTP::Status::Code::S_409_CONFLICT, "conflict", "Application already exists"};
    }

    IdentityManager::Applications::ApplicationAttributes attribs;
    attribs.fromJSON(Helpers::JSON::MEMBER_OR_NULL(*request.inputJSON, "applicationAttributes"));

    // Attempt to create the new application
    if (!Globals::getIdentityManager()->applications->createApplication(authClientDetails,
                                                                        request.jwtToken->getSubject(),
                                                                        appName,
                                                                        appDescription,
                                                                        Helpers::JSON::ASSTRING(*request.inputJSON, "appURL", ""),
                                                                        Helpers::JSON::ASSTRING(*request.inputJSON, "appKey", ""),
                                                                        request.jwtToken->getSubject(),
                                                                        attribs,
                                                                        Helpers::JSON::ASBOOL(*request.inputJSON, "initializeDefaults", true)))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to create application"};
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_Applications::doesApplicationExist(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::string appName(Helpers::JSON::ASSTRING(*request.inputJSON, "appName", ""));

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty"};
    }

    if (!Globals::getIdentityManager()->applications->doesApplicationExist(appName))
    {
        return {HTTP::Status::Code::S_404_NOT_FOUND, "not_found", "The Application does not exist in the system."};
    }
    return response;
}

AdminPortal_Endpoints_Applications::APIReturn AdminPortal_Endpoints_Applications::setAccountAsApplicationAdmin(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::string appName(Helpers::JSON::ASSTRING(*request.inputJSON, "appName", ""));

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty"};
    }

    std::string accountUUID(Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", ""));

    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty"};
    }

    if (!Globals::getIdentityManager()
             ->applications->setAccountAsApplicationAdmin(authClientDetails, request.jwtToken->getSubject(), appName, accountUUID, Helpers::JSON::ASBOOL(*request.inputJSON, "isAppAdmin", false)))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error"};
    }
    return getApplicationAccountDetails(appName);
}

API::APIReturn AdminPortal_Endpoints_Applications::getApplicationInfo(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    std::string appName(Helpers::JSON::ASSTRING(*request.inputJSON, "appName", ""));

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty"};
    }

    std::optional<IdentityManager::Applications::ApplicationAttributes> attribs = Globals::getIdentityManager()->applications->getApplicationAttributes(appName);

    if (!attribs.has_value())
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to retrieve the application attributes"};
    }

    ApplicationAuthSettings appWebLoginTokenConfig = Globals::getIdentityManager()->applications->getAuthSettingsFromApplication(appName);

    // Get associated scopes...
    boost::json::array scopes{};
    std::set<ApplicationScope> attrList = Globals::getIdentityManager()->applicationScopes->listApplicationScopes(appName);
    for (const ApplicationScope &scope : attrList)
    {
        Helpers::JSON::ARRAY_APPEND(scopes, scope.toJSON());
    }

    // Get associated activities...
    boost::json::array activities{};
    std::map<std::string, IdentityManager::ApplicationActivities::ActivityData> activitiesMap = Globals::getIdentityManager()->applicationActivities->listApplicationActivities(appName);
    for (const auto &activity : activitiesMap)
    {
        boost::json::object jActivity = activity.second.toJSON();
        jActivity["name"] = activity.first;
        Helpers::JSON::ARRAY_APPEND(activities, jActivity);
    }

    return boost::json::value{
        {"loginFlow",             getLoginFlowDetails(appName)},
        {"tokenConfig",           appWebLoginTokenConfig.toJSON()},
        {"applicationAttributes", attribs->toJSON()},
        {"scopes",                scopes},
        {"accounts",              getApplicationAccountDetails(appName)},
        {"activities",            activities},
        {"details",               boost::json::object{
            {"description", Globals::getIdentityManager()->applications->getApplicationDescription(appName)},
        }},
    };
}

API::APIReturn AdminPortal_Endpoints_Applications::updateApplicationDetails(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName(Helpers::JSON::ASSTRING(*request.inputJSON, "appName", ""));

    IdentityManager::Applications::ApplicationAttributes attribs;
    attribs.fromJSON(Helpers::JSON::MEMBER_OR_NULL(*request.inputJSON, "applicationAttributes"));

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty"};
    }

    if (!Globals::getIdentityManager()->applications->updateApplicationAttributes(authClientDetails, request.jwtToken->getSubject(), appName, attribs))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update some application attributes."};
    }

    if (!Globals::getIdentityManager()->applications->updateApplicationDescription(authClientDetails,
                                                                                   request.jwtToken->getSubject(),
                                                                                   appName,
                                                                                   Helpers::JSON::ASSTRING(*request.inputJSON, "description", "")))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update application description."};
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_Applications::updateApplicationAPIKey(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName(Helpers::JSON::ASSTRING(*request.inputJSON, "appName", ""));

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty"};
    }

    if (!Globals::getIdentityManager()->applications->updateApplicationAPIKey(authClientDetails, request.jwtToken->getSubject(), appName, Helpers::JSON::ASSTRING(*request.inputJSON, "appKey", "")))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update application API key."};
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_Applications::updateAuthSettingsForApplication(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    ApplicationAuthSettings tokenInfo;
    std::optional<AppError> err = tokenInfo.fromJSON(*request.inputJSON);
    if (err.has_value())
    {
        return {static_cast<Network::Protocol::HTTP::Status::Code>(err->http_code), err->error, err->message};
    }

    if (!Globals::getIdentityManager()->applications->updateAuthSettingsForApplication(authClientDetails, request.jwtToken->getSubject(), tokenInfo))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update web login JWT configuration."};
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_Applications::updateApplicationLoginCallbackURI(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName(Helpers::JSON::ASSTRING(*request.inputJSON, "appName", ""));
    std::string callbackURI(Helpers::JSON::ASSTRING(*request.inputJSON, "callbackURI", ""));

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty"};
    }

    if (!Globals::getIdentityManager()->applications->setApplicationWebLoginCallbackURI(authClientDetails, request.jwtToken->getSubject(), appName, callbackURI))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the callback URI."};
    }

    return getLoginFlowDetails(appName);
}

API::APIReturn AdminPortal_Endpoints_Applications::addApplicationLoginOrigin(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName(Helpers::JSON::ASSTRING(*request.inputJSON, "appName", ""));

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty"};
    }

    if (!Globals::getIdentityManager()->applications->addWebLoginOriginURLToApplication(authClientDetails,
                                                                                        request.jwtToken->getSubject(),
                                                                                        appName,
                                                                                        Helpers::JSON::ASSTRING(*request.inputJSON, "loginOrigin", "")))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add login origin. Please check if the database is accessible or if the value already exists."};
    }

    return getLoginFlowDetails(appName);
}

API::APIReturn AdminPortal_Endpoints_Applications::removeApplicationLoginOrigin(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName(Helpers::JSON::ASSTRING(*request.inputJSON, "appName", ""));

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty"};
    }

    if (!Globals::getIdentityManager()->applications->removeWebLoginOriginURLToApplication(authClientDetails,
                                                                                           request.jwtToken->getSubject(),
                                                                                           appName,
                                                                                           Helpers::JSON::ASSTRING(*request.inputJSON, "loginOrigin", "")))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove login origin. Refresh and try again."};
    }

    return getLoginFlowDetails(appName);
}

API::APIReturn AdminPortal_Endpoints_Applications::addApplicationLoginRedirectURI(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName(Helpers::JSON::ASSTRING(*request.inputJSON, "appName", ""));

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty"};
    }

    if (!Globals::getIdentityManager()->applications->addWebLoginAllowedRedirectURIToApplication(authClientDetails,
                                                                                                 request.jwtToken->getSubject(),
                                                                                                 appName,
                                                                                                 Helpers::JSON::ASSTRING(*request.inputJSON, "redirectURI", "")))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add redirect URI. Please check if the database is accessible or if the value already exists."};
    }

    return getLoginFlowDetails(appName);
}

API::APIReturn AdminPortal_Endpoints_Applications::removeApplicationLoginRedirectURI(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName(Helpers::JSON::ASSTRING(*request.inputJSON, "appName", ""));

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty"};
    }

    if (!Globals::getIdentityManager()->applications->removeWebLoginAllowedRedirectURIToApplication(authClientDetails,
                                                                                                    request.jwtToken->getSubject(),
                                                                                                    appName,
                                                                                                    Helpers::JSON::ASSTRING(*request.inputJSON, "redirectURI", "")))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove redirect URI. Refresh and try again."};
    }

    return getLoginFlowDetails(appName);
}

AdminPortal_Endpoints_Applications::APIReturn AdminPortal_Endpoints_Applications::updateWebLoginDefaultRedirectURIForApplication(void *context, const RequestContext &request,
                                                                                                                                 ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName(Helpers::JSON::ASSTRING(*request.inputJSON, "appName", ""));

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application Name is Empty"};
    }

    if (!Globals::getIdentityManager()->applications->updateWebLoginDefaultRedirectURIForApplication(authClientDetails,
                                                                                                     request.jwtToken->getSubject(),
                                                                                                     appName,
                                                                                                     Helpers::JSON::ASSTRING(*request.inputJSON, "redirectURI", "")))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to set default redirect URI. Please verify the application name and URI are valid."};
    }

    return getLoginFlowDetails(appName);
}

boost::json::value AdminPortal_Endpoints_Applications::getLoginFlowDetails(const std::string &appName)
{
    std::set<std::string> webLoginOrigins = Globals::getIdentityManager()->applications->listWebLoginOriginUrlsFromApplication(appName);
    std::set<std::string> acceptedRedirectURIs = Globals::getIdentityManager()->applications->listWebLoginAllowedRedirectURIsFromApplication(appName);

    boost::json::array loginOrigins{};
    for (const std::string &url : webLoginOrigins)
    {
        Helpers::JSON::ARRAY_APPEND(loginOrigins, boost::json::value(url));
    }

    boost::json::array redirectURIs{};
    for (const std::string &url : acceptedRedirectURIs)
    {
        Helpers::JSON::ARRAY_APPEND(redirectURIs, boost::json::value(url));
    }

    return boost::json::object{
        {"callbackURI", Globals::getIdentityManager()->applications->getApplicationCallbackURI(appName)},
        {"defaultRedirectURI", Globals::getIdentityManager()->applications->getWebLoginDefaultRedirectURIForApplication(appName)},
        {"loginOrigins", loginOrigins},
        {"redirectURIs", redirectURIs},
    };
}

boost::json::value AdminPortal_Endpoints_Applications::getApplicationAccountDetails(const std::string &appName)
{
    boost::json::array payloadOut{};
    std::set<std::string> acctList = Globals::getIdentityManager()->applications->listApplicationAccounts(appName);
    std::set<std::string> appAdmins = Globals::getIdentityManager()->applications->listApplicationAdmins(appName);
    for (const std::string &accountUUID : acctList)
    {
        boost::json::object jAccount{
            {"accountUUID", accountUUID},
            {"displayName", Globals::getIdentityManager()->accounts->getAccountDisplayName(accountUUID)},
            {"isAppAdmin", (appAdmins.find(accountUUID) != appAdmins.end())},
        };
        Helpers::JSON::ARRAY_APPEND(payloadOut, jAccount);
    }
    return payloadOut;
}
