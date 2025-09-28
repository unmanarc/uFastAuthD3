#include "webadmin_methods_application_activities.h"

#include "../globals.h"
#include <Mantids30/Program_Logs/applog.h>
#include <optional>
#include <string>


using namespace Mantids30::Program;
using namespace Mantids30;

using namespace Mantids30::Network::Protocols;

void WebAdminMethods_ApplicationActivities::addMethods_Activities(std::shared_ptr<MethodsHandler> methods)
{
    using SecurityOptions = Mantids30::API::RESTful::MethodsHandler::SecurityOptions;

    methods->addResource(MethodsHandler::GET, "getActivityInfo", &getActivityInfo, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::GET, "listApplicationActivities", &listApplicationActivities, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::POST, "addApplicationActivity", &addApplicationActivity, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::DELETE, "removeApplicationActivity", &removeApplicationActivity, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});

    methods->addResource(MethodsHandler::PATCH, "updateActivityDescription", &updateActivityDescription, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::PATCH, "updateActivityParentActivity", &updateActivityParentActivity, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});

    methods->addResource(MethodsHandler::POST, "addSchemeToApplicationActivity", &addSchemeToApplicationActivity, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::DELETE, "removeSchemeFromApplicationActivity", &removeSchemeFromApplicationActivity, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});

    methods->addResource(MethodsHandler::PATCH, "updateDefaultSchemeOnApplicationActivity", &updateDefaultSchemeOnApplicationActivity, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
}

void WebAdminMethods_ApplicationActivities::updateDefaultSchemeOnApplicationActivity(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    uint32_t schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", 0);

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return;
    }

    if (schemeId == 0)
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Scheme ID is required");
        return;
    }

    if (!Globals::getIdentityManager()->applicationActivities->setApplicationActivityDefaultScheme(appName, activityName, schemeId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to set the default authentication scheme on the activity.");
    }
}


void WebAdminMethods_ApplicationActivities::addSchemeToApplicationActivity(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    uint32_t schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", 0);

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return;
    }

    if (schemeId == 0)
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Scheme ID is required");
        return;
    }

    if (!Globals::getIdentityManager()->applicationActivities->addAuthenticationSchemeToApplicationActivity(appName, activityName, schemeId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the authentication scheme to the activity.");
    }
}

void WebAdminMethods_ApplicationActivities::removeSchemeFromApplicationActivity(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    uint32_t schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", 0);

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return;
    }

    if (schemeId == 0)
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Scheme ID is required");
        return;
    }

    if (!Globals::getIdentityManager()->applicationActivities->removeAuthenticationSchemeFromApplicationActivity(appName, activityName, schemeId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the authentication scheme from the activity.");
    }
}


void WebAdminMethods_ApplicationActivities::updateActivityDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    std::string activityDescription = JSON_ASSTRING(*request.inputJSON, "activityDescription", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return;
    }

    if (activityDescription.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request","Activity description cannot be empty.");
        return;
    }

    if (!Globals::getIdentityManager()->applicationActivities->setApplicationActivityDescription(appName, activityName, activityDescription))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the activity description.");
    }
}

void WebAdminMethods_ApplicationActivities::updateActivityParentActivity(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    std::string parentActivityName = JSON_ASSTRING(*request.inputJSON, "parentActivityName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return;
    }

    if (!Globals::getIdentityManager()->applicationActivities->setApplicationActivityParentActivity(appName, activityName, parentActivityName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the activity parent activity.");
    }
}



void WebAdminMethods_ApplicationActivities::getActivityInfo(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Activitity name is required");
        return;
    }


    // Details:
    std::map<std::string, IdentityManager::ApplicationActivities::ActivityData> activities = Globals::getIdentityManager()->applicationActivities->listApplicationActivities(appName);

    if (activities.find(activityName)== activities.end())
    {
        response.setError(HTTP::Status::S_404_NOT_FOUND, "not_found", "Activitity name not found in this application");
        return;
    }

    (*response.responseJSON())["details"] = activities[activityName].toJSON();
    (*response.responseJSON())["allActivities"] = Json::arrayValue;
    for ( const auto & activity : activities )
    {
        json jActivity;
        jActivity["name"] = activity.first;
        (*response.responseJSON())["allActivities"].append(jActivity);
    }

    // Activity Schemes:
    std::set<uint32_t> authSchemes =  Globals::getIdentityManager()->applicationActivities->listAuthenticationSchemesForApplicationActivity(appName, activityName);
    // All Schemes:
    std::map<uint32_t, std::string> allSchemes = Globals::getIdentityManager()->authController->listAuthenticationSchemes();

    // Arrays:
    (*response.responseJSON())["schemes"] = Json::arrayValue;
    (*response.responseJSON())["leftSchemes"] = Json::arrayValue;  
    
    for ( const auto & scheme : allSchemes )
    {
        json jScheme;
        jScheme["id"] = scheme.first;
        jScheme["name"] = scheme.second;
        
        if ( authSchemes.find(scheme.first) != authSchemes.end() )
        {
            (*response.responseJSON())["schemes"].append(jScheme);
        }
        else
        {
            (*response.responseJSON())["leftSchemes"].append(jScheme);
        }
    }

    std::optional<uint32_t> defaultScheme = Globals::getIdentityManager()->applicationActivities->getApplicationActivityDefaultScheme(appName,activityName);
    if (defaultScheme)
    {
        (*response.responseJSON())["defaultScheme"] = *defaultScheme;
    }
    else
    {
        (*response.responseJSON())["defaultScheme"] = Json::nullValue;
    }
}

void WebAdminMethods_ApplicationActivities::listApplicationActivities(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return;
    }

    std::map<std::string, IdentityManager::ApplicationActivities::ActivityData> activities = Globals::getIdentityManager()->applicationActivities->listApplicationActivities(appName);

    int i=0;
    (*response.responseJSON()) = Json::arrayValue;
    for ( const auto & activity : activities )
    {
        (*response.responseJSON())[i] = activity.second.toJSON();
        (*response.responseJSON())[i]["name"] = activity.first;
        i++;
    }
}

void WebAdminMethods_ApplicationActivities::addApplicationActivity(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    std::string activityDescription = JSON_ASSTRING(*request.inputJSON, "activityDescription", "");

    if (activityName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request","Activity name cannot be empty.");
        return;
    }

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return;
    }

    if (activityDescription.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request","Activity description cannot be empty.");
        return;
    }

    if (!Globals::getIdentityManager()->applicationActivities->addApplicationActivity(appName, activityName, activityDescription))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to create the new activity.\nThe activity ID may already exist.");
    }
}

void WebAdminMethods_ApplicationActivities::removeApplicationActivity(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return;
    }

    if (!Globals::getIdentityManager()->applicationActivities->removeApplicationActivity(appName, activityName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the activity.");
    }
}
