#include "identitymanager_db.h"
#include <Mantids30/Helpers/encoders.h>

#include <Mantids30/Threads/lock_shared.h>

#include <Mantids30/Memory/a_bool.h>
#include <Mantids30/Memory/a_datetime.h>
#include <Mantids30/Memory/a_int32.h>
#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_uint32.h>
#include <Mantids30/Memory/a_uint64.h>
#include <Mantids30/Memory/a_var.h>

using namespace Mantids30::Memory;
using namespace Mantids30::Database;
using namespace Mantids30::Helpers;
using namespace Mantids30;

bool IdentityManager_DB::ApplicationActivities_DB::addApplicationActivity(const std::string &appName, const std::string &activityName, const std::string &activityDescription)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (!_parent->m_sqlConnector->execute("INSERT INTO iam.applicationActivities (f_appName, activityName, parentActivity, description) VALUES (:appName, :activityName, NULL, :description);",
                                           {{":appName", MAKE_VAR(STRING, appName)},
                                            {":activityName", MAKE_VAR(STRING, activityName)},
                                            {":description", MAKE_VAR(STRING, activityDescription)}}))
    {
        return false;
    }

    return true;
}

bool IdentityManager_DB::ApplicationActivities_DB::removeApplicationActivity(const std::string &appName, const std::string &activityName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (!_parent->m_sqlConnector->execute("DELETE FROM iam.applicationActivities WHERE `f_appName` = :appName AND `activityName` = :activityName;",
                                           {{":appName", MAKE_VAR(STRING, appName)},
                                            {":activityName", MAKE_VAR(STRING, activityName)}}))
    {
        return false;
    }

    return true;

}

bool IdentityManager_DB::ApplicationActivities_DB::setApplicationActivities(const std::string &appName, const std::map<std::string, ActivityData> &activities)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Get the current activities from the database
    std::set<std::string> currentActivities;
    Abstract::STRING activityName;

    {
        SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `activityName` FROM iam.applicationActivities WHERE `f_appName` = :appName;",
                                                                         {{":appName", MAKE_VAR(STRING, appName)}}, {&activityName});

        if (i.getResultsOK())
        {
            while (i.query->step())
            {
                currentActivities.insert(activityName.getValue());
            }
        }
        else
        {
            return false;
        }
    }

    // Remove the activities not present in the new map.
    for (const auto &currentActivity : currentActivities)
    {
        if (activities.find(currentActivity) == activities.end())
        {
            if (!_parent->m_sqlConnector->execute("DELETE FROM iam.applicationActivities WHERE `f_appName` = :appName AND `activityName` = :activityName;",
                                                  {{":appName", MAKE_VAR(STRING, appName)}, {":activityName", MAKE_VAR(STRING, currentActivity)}}))
            {
                return false;
            }
        }
    }

    // Update or insert the activity...
    for (const auto &activity : activities)
    {
        if (currentActivities.find(activity.first) != currentActivities.end())
        {
            // Update it (
            if (!_parent->m_sqlConnector->execute("UPDATE iam.applicationActivities "
                                                  "SET `description` = :description, `parentActivity` = :parentActivity "
                                                  "WHERE `f_appName` = :appName AND `activityName` = :activityName;",
                                                  {{":description", MAKE_VAR(STRING, activity.second.description)},
                                                   {":parentActivity", MAKE_VAR(STRING, activity.second.parentActivity)},
                                                   {":appName", MAKE_VAR(STRING, appName)},
                                                   {":activityName", MAKE_VAR(STRING, activity.first)}}))
            {
                return false;
            }
        }
        else
        {
            // Insert the new activity
            if (!_parent->m_sqlConnector->execute("INSERT INTO iam.applicationActivities (`f_appName`, `activityName`, `parentActivity`, `description`) "
                                                  "VALUES(:appName, :activityName, :parentActivity, :description);",
                                                  {{":appName", MAKE_VAR(STRING, appName)},
                                                   {":activityName", MAKE_VAR(STRING, activity.first)},
                                                   {":parentActivity", MAKE_VAR(STRING, activity.second.parentActivity)},
                                                   {":description", MAKE_VAR(STRING, activity.second.description)}}))
            {
                return false;
            }
        }
    }

    return true;
}

bool IdentityManager_DB::ApplicationActivities_DB::removeApplicationActivities(const std::string &appName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Delete all activities for the specified application
    if (!_parent->m_sqlConnector->execute("DELETE FROM iam.applicationActivities WHERE `f_appName` = :appName;", {{":appName", MAKE_VAR(STRING, appName)}}))
    {
        return false;
    }

    return true;
}

std::map<std::string, IdentityManager::ApplicationActivities::ActivityData> IdentityManager_DB::ApplicationActivities_DB::listApplicationActivities(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING name, description, parentActivity, defaultSchemeDescription;
    Abstract::UINT32 defaultSchemeId;
    std::map<std::string, IdentityManager::ApplicationActivities::ActivityData> activities;

    SQLConnector::QueryInstance i = _parent->m_sqlConnector
                                        ->qSelect(
                                            R"(SELECT
                                                    `activityName`,
                                                    `parentActivity`,
                                                    `applicationActivities`.`description`,
                                                    `defaultSchemeId`,
                                                    `authenticationSchemes`.`description` as schemeDescription
                                                FROM applicationActivities
                                                LEFT JOIN authenticationSchemes ON `defaultSchemeId` = `schemeId`
                                                WHERE `f_appName` = :appName;)",
                                                  {{":appName", MAKE_VAR(STRING, appName)}}, {&name, &parentActivity, &description, &defaultSchemeId, &defaultSchemeDescription});
    while (i.getResultsOK() && i.query->step())
    {
        activities[name.toString()] = {.description = description.toString(), .parentActivity = parentActivity.toString(), .defaultSchemeDescription = defaultSchemeDescription.toString(), .defaultSchemeID = defaultSchemeId.getValue() };
    }
    return activities;
}
