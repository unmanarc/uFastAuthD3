#include "webadmin_endpoints_application_activities.h"

#include "../globals.h"
#include <Mantids30/Program_Logs/applog.h>
#include <optional>
#include <string>


using namespace Mantids30::Program;
using namespace Mantids30;

using namespace Mantids30::Network::Protocols;

void WebAdminMethods_ApplicationActivities::addEndpoints_Activities(std::shared_ptr<Endpoints> endpoints)
{
    using SecurityOptions = Mantids30::API::RESTful::Endpoints::SecurityOptions;

    endpoints->addEndpoint(Endpoints::GET,    "getActivityInfo",           SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"},  nullptr, &getActivityInfo);
    endpoints->addEndpoint(Endpoints::GET,    "listApplicationActivities", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"},  nullptr, &listApplicationActivities);
    endpoints->addEndpoint(Endpoints::POST,   "addApplicationActivity",    SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &addApplicationActivity);
    endpoints->addEndpoint(Endpoints::DELETE, "removeApplicationActivity", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &removeApplicationActivity);

    endpoints->addEndpoint(Endpoints::PATCH, "updateActivityDescription",      SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &updateActivityDescription);
    endpoints->addEndpoint(Endpoints::PATCH, "updateActivityParentActivity",   SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &updateActivityParentActivity);

    endpoints->addEndpoint(Endpoints::POST,  "addSchemeToApplicationActivity", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &addSchemeToApplicationActivity);
    endpoints->addEndpoint(Endpoints::DELETE, "removeSchemeFromApplicationActivity", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &removeSchemeFromApplicationActivity);

    endpoints->addEndpoint(Endpoints::PATCH, "updateDefaultSchemeOnApplicationActivity", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &updateDefaultSchemeOnApplicationActivity);
}

API::APIReturn WebAdminMethods_ApplicationActivities::updateDefaultSchemeOnApplicationActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    uint32_t schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", 0);

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return response;
    }

    if (schemeId == 0)
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Scheme ID is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationActivities->setApplicationActivityDefaultScheme(appName, activityName, schemeId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to set the default authentication scheme on the activity.");
    }
    return response;
}


API::APIReturn WebAdminMethods_ApplicationActivities::addSchemeToApplicationActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    uint32_t schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", 0);

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return response;
    }

    if (schemeId == 0)
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Scheme ID is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationActivities->addAuthenticationSchemeToApplicationActivity(appName, activityName, schemeId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the authentication scheme to the activity.");
    }
    return response;
}

API::APIReturn WebAdminMethods_ApplicationActivities::removeSchemeFromApplicationActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    uint32_t schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", 0);

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return response;
    }

    if (schemeId == 0)
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Scheme ID is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationActivities->removeAuthenticationSchemeFromApplicationActivity(appName, activityName, schemeId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the authentication scheme from the activity.");
    }
    return response;
}


API::APIReturn WebAdminMethods_ApplicationActivities::updateActivityDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    std::string activityDescription = JSON_ASSTRING(*request.inputJSON, "activityDescription", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return response;
    }

    if (activityDescription.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request","Activity description cannot be empty.");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationActivities->setApplicationActivityDescription(appName, activityName, activityDescription))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the activity description.");
    }
    return response;
}

API::APIReturn WebAdminMethods_ApplicationActivities::updateActivityParentActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    std::string parentActivityName = JSON_ASSTRING(*request.inputJSON, "parentActivityName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationActivities->setApplicationActivityParentActivity(appName, activityName, parentActivityName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the activity parent activity.");
    }
    return response;
}



API::APIReturn WebAdminMethods_ApplicationActivities::getActivityInfo(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Activitity name is required");
        return response;
    }

    // Details:
    std::map<std::string, IdentityManager::ApplicationActivities::ActivityData> activities = Globals::getIdentityManager()->applicationActivities->listApplicationActivities(appName);

    if (activities.find(activityName)== activities.end())
    {
        response.setError(HTTP::Status::S_404_NOT_FOUND, "not_found", "Activitity name not found in this application");
        return response;
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

    return response;
}

API::APIReturn WebAdminMethods_ApplicationActivities::listApplicationActivities(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
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
    return response;
}

API::APIReturn WebAdminMethods_ApplicationActivities::addApplicationActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    std::string activityDescription = JSON_ASSTRING(*request.inputJSON, "activityDescription", "");

    if (activityName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request","Activity name cannot be empty.");
        return response;
    }

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (activityDescription.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request","Activity description cannot be empty.");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationActivities->addApplicationActivity(appName, activityName, activityDescription))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to create the new activity.\nThe activity ID may already exist.");
    }
    return response;
}

API::APIReturn WebAdminMethods_ApplicationActivities::removeApplicationActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationActivities->removeApplicationActivity(appName, activityName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the activity.");
    }
    return response;
}
