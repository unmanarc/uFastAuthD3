#include "webadmin_methods_application_activities.h"

#include "../globals.h"
#include <Mantids30/Program_Logs/applog.h>


using namespace Mantids30::Program;
using namespace Mantids30;

using namespace Mantids30::Network::Protocols;

void WebAdminMethods_ApplicationActivities::addMethods_Activities(std::shared_ptr<MethodsHandler> methods)
{
    using SecurityOptions = Mantids30::API::RESTful::MethodsHandler::SecurityOptions;

    methods->addResource(MethodsHandler::GET, "listApplicationActivities", &listApplicationActivities, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_READ"});
    methods->addResource(MethodsHandler::POST, "addApplicationActivity", &addApplicationActivity, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
    methods->addResource(MethodsHandler::DELETE, "removeApplicationActivity", &removeApplicationActivity, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"APP_MODIFY"});
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
