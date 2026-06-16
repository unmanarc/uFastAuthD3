#include "adminportal_endpoints_application_activities.h"

#include "globals.h"
#include <Mantids30/Program_Logs/applog.h>
#include <optional>
#include <string>

using namespace Mantids30::Program;
using namespace Mantids30;

using namespace Mantids30::Network::Protocol;

void AdminPortal_Endpoints_ApplicationActivities::addEndpoints_Activities(std::shared_ptr<Endpoints> endpoints)
{
    using SecurityRequirements = API::Security::Requirements;

    endpoints->addEndpoint(HTTP::Method::GET, "getActivityInfo", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_READ"}, nullptr, &getActivityInfo);
    endpoints->addEndpoint(HTTP::Method::GET, "listApplicationActivities", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_READ"}, nullptr, &listApplicationActivities);
    endpoints->addEndpoint(HTTP::Method::POST, "addApplicationActivity", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &addApplicationActivity);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeApplicationActivity", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &removeApplicationActivity);

    endpoints->addEndpoint(HTTP::Method::PATCH, "updateActivityDescription", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &updateActivityDescription);
    endpoints->addEndpoint(HTTP::Method::PATCH, "updateActivityParentActivity", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &updateActivityParentActivity);

    endpoints->addEndpoint(HTTP::Method::POST, "addSchemeToApplicationActivity", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &addSchemeToApplicationActivity);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeSchemeFromApplicationActivity", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &removeSchemeFromApplicationActivity);

    endpoints->addEndpoint(HTTP::Method::PATCH, "updateDefaultSchemeOnApplicationActivity", SecurityRequirements::JWT_COOKIE_AUTH, {"APP_MODIFY"}, nullptr, &updateDefaultSchemeOnApplicationActivity);
}

API::APIReturn AdminPortal_Endpoints_ApplicationActivities::updateDefaultSchemeOnApplicationActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    uint32_t schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", 0);

    if (appName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return response;
    }

    if (schemeId == 0)
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Scheme ID is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationActivities->setApplicationActivityDefaultScheme(authClientDetails, request.jwtToken->getSubject(), appName, activityName, schemeId))
    {
        response.setError(HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to set the default authentication scheme on the activity.");
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationActivities::addSchemeToApplicationActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    uint32_t schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", 0);

    if (appName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return response;
    }

    if (schemeId == 0)
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Scheme ID is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationActivities->addAuthenticationSchemeToApplicationActivity(authClientDetails, request.jwtToken->getSubject(), appName, activityName, schemeId))
    {
        response.setError(HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the authentication scheme to the activity.");
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationActivities::removeSchemeFromApplicationActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    uint32_t schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", 0);

    if (appName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return response;
    }

    if (schemeId == 0)
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Scheme ID is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationActivities->removeAuthenticationSchemeFromApplicationActivity(authClientDetails, request.jwtToken->getSubject(), appName, activityName, schemeId))
    {
        response.setError(HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the authentication scheme from the activity.");
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationActivities::updateActivityDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    std::string activityDescription = JSON_ASSTRING(*request.inputJSON, "activityDescription", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return response;
    }

    if (activityDescription.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Activity description cannot be empty.");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationActivities->setApplicationActivityDescription(authClientDetails, request.jwtToken->getSubject(), appName, activityName, activityDescription))
    {
        response.setError(HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the activity description.");
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationActivities::updateActivityParentActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    std::string parentActivityName = JSON_ASSTRING(*request.inputJSON, "parentActivityName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationActivities->setApplicationActivityParentActivity(authClientDetails, request.jwtToken->getSubject(), appName, activityName, parentActivityName))
    {
        response.setError(HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the activity parent activity.");
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationActivities::getActivityInfo(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Activitity name is required");
        return response;
    }

    // Details:
    std::map<std::string, IdentityManager::ApplicationActivities::ActivityData> activities = Globals::getIdentityManager()->applicationActivities->listApplicationActivities(appName);

    if (activities.find(activityName) == activities.end())
    {
        response.setError(HTTP::Status::Code::S_404_NOT_FOUND, "not_found", "Activitity name not found in this application");
        return response;
    }

    (*response.responseJSON())["details"] = activities[activityName].toJSON();
    (*response.responseJSON())["allActivities"] = Json::arrayValue;
    for (const std::pair<std::string, IdentityManager::ApplicationActivities::ActivityData> &activity : activities)
    {
        json jActivity;
        jActivity["name"] = activity.first;
        (*response.responseJSON())["allActivities"].append(jActivity);
    }

    // Activity Schemes:
    std::set<uint32_t> authSchemes = Globals::getIdentityManager()->applicationActivities->listAuthenticationSchemesForApplicationActivity(appName, activityName);
    // All Schemes:
    std::map<uint32_t, std::string> allSchemes = Globals::getIdentityManager()->authController->listAuthenticationSchemes();

    // Arrays:
    (*response.responseJSON())["schemes"] = Json::arrayValue;
    (*response.responseJSON())["leftSchemes"] = Json::arrayValue;

    for (const std::pair<uint32_t, std::string> &scheme : allSchemes)
    {
        json jScheme;
        jScheme["id"] = scheme.first;
        jScheme["name"] = scheme.second;

        if (authSchemes.find(scheme.first) != authSchemes.end())
        {
            (*response.responseJSON())["schemes"].append(jScheme);
        }
        else
        {
            (*response.responseJSON())["leftSchemes"].append(jScheme);
        }
    }

    std::optional<uint32_t> defaultScheme = Globals::getIdentityManager()->applicationActivities->getApplicationActivityDefaultScheme(appName, activityName);
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

API::APIReturn AdminPortal_Endpoints_ApplicationActivities::listApplicationActivities(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    std::map<std::string, IdentityManager::ApplicationActivities::ActivityData> activities = Globals::getIdentityManager()->applicationActivities->listApplicationActivities(appName);

    int i = 0;
    (*response.responseJSON()) = Json::arrayValue;
    for (const std::pair<std::string, IdentityManager::ApplicationActivities::ActivityData> &activity : activities)
    {
        (*response.responseJSON())[i] = activity.second.toJSON();
        (*response.responseJSON())[i]["name"] = activity.first;
        i++;
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationActivities::addApplicationActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");
    std::string activityDescription = JSON_ASSTRING(*request.inputJSON, "activityDescription", "");

    if (activityName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Activity name cannot be empty.");
        return response;
    }

    if (appName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (activityDescription.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Activity description cannot be empty.");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationActivities->addApplicationActivity(authClientDetails, request.jwtToken->getSubject(), appName, activityName, activityDescription))
    {
        response.setError(HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to create the new activity.\nThe activity ID may already exist.");
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_ApplicationActivities::removeApplicationActivity(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");
    std::string activityName = JSON_ASSTRING(*request.inputJSON, "activityName", "");

    if (appName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (activityName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Activity name is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationActivities->removeApplicationActivity(authClientDetails, request.jwtToken->getSubject(), appName, activityName))
    {
        response.setError(HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the activity.");
    }
    return response;
}
