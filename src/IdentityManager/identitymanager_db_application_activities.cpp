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
#include <optional>

using namespace Mantids30::Memory;
using namespace Mantids30::Database;
using namespace Mantids30::Helpers;
using namespace Mantids30;

bool IdentityManager_DB::ApplicationActivities_DB::addApplicationActivity(const std::string &appName, const std::string &activityName, const std::string &activityDescription)
{
    std::optional<uint32_t> defaultAuthScheme = _parent->authController->getDefaultAuthScheme();

    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Determine if we should include the default scheme ID in the insert
    uint32_t defaultSchemeId;
    if (defaultAuthScheme.has_value())
    {
        defaultSchemeId = defaultAuthScheme.value();
        // Insert the new application activity with the default scheme ID
        if (!_parent->m_sqlConnector->execute("INSERT INTO iam.applicationActivities (f_appName, activityName, parentActivity, description, defaultSchemeId) VALUES (:appName, :activityName, NULL, :description, :defaultSchemeId);",
                                              {{":appName", MAKE_VAR(STRING, appName)},
                                               {":activityName", MAKE_VAR(STRING, activityName)},
                                               {":description", MAKE_VAR(STRING, activityDescription)},
                                               {":defaultSchemeId", MAKE_VAR(UINT32, defaultSchemeId)}}))
        {
            return false;
        }
    }
    else
    {
        // we'll handle it by not including the parameter if it's null
        if (!_parent->m_sqlConnector->execute("INSERT INTO iam.applicationActivities (f_appName, activityName, parentActivity, description) VALUES (:appName, :activityName, NULL, :description);",
                                              {{":appName", MAKE_VAR(STRING, appName)},
                                               {":activityName", MAKE_VAR(STRING, activityName)},
                                               {":description", MAKE_VAR(STRING, activityDescription)}}))
        {
            return false;
        }
    }


    return true;
}

bool IdentityManager_DB::ApplicationActivities_DB::removeApplicationActivity(const std::string &appName, const std::string &activityName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (!_parent->m_sqlConnector->execute("DELETE FROM iam.applicationActivities WHERE `f_appName` = :appName AND `activityName` = :activityName;",
                                          {{":appName", MAKE_VAR(STRING, appName)}, {":activityName", MAKE_VAR(STRING, activityName)}}))
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

bool IdentityManager_DB::ApplicationActivities_DB::setApplicationActivityParentActivity(const std::string &appName, const std::string &activityName, const std::string &parentActivityName)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    if (parentActivityName.empty())
    {
        // Update the parent activity for the specified application activity
        return _parent->m_sqlConnector->execute("UPDATE iam.applicationActivities SET `parentActivity`=NULL WHERE `f_appName`=:appName AND `activityName`=:activityName;",
                                                { {":appName", MAKE_VAR(STRING, appName)}, {":activityName", MAKE_VAR(STRING, activityName)}});
    }

    // Update the parent activity for the specified application activity
    return _parent->m_sqlConnector->execute("UPDATE iam.applicationActivities SET `parentActivity`=:parentActivityName WHERE `f_appName`=:appName AND `activityName`=:activityName;",
                                            {{":parentActivityName", MAKE_VAR(STRING, parentActivityName)}, {":appName", MAKE_VAR(STRING, appName)}, {":activityName", MAKE_VAR(STRING, activityName)}});
}

bool IdentityManager_DB::ApplicationActivities_DB::setApplicationActivityDescription(const std::string &appName, const std::string &activityName, const std::string &description)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Update the description for the specified application activity
    return _parent->m_sqlConnector->execute("UPDATE iam.applicationActivities SET `description`=:description WHERE `f_appName`=:appName AND `activityName`=:activityName;",
                                            {{":description", MAKE_VAR(STRING, description)}, {":appName", MAKE_VAR(STRING, appName)}, {":activityName", MAKE_VAR(STRING, activityName)}});
}

std::optional<IdentityManager::ApplicationActivities::ActivityData> IdentityManager_DB::ApplicationActivities_DB::getApplicationActivityInfo(const std::string &appName, const std::string &activityName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING description, parentActivity, defaultSchemeDescription;
    Abstract::UINT32 defaultSchemeId;
    std::map<std::string, IdentityManager::ApplicationActivities::ActivityData> activities;

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect(
        R"(SELECT
                                                    `parentActivity`,
                                                    `applicationActivities`.`description`,
                                                    `defaultSchemeId`,
                                                    `authenticationSchemes`.`description` as schemeDescription
                                                FROM applicationActivities
                                                LEFT JOIN authenticationSchemes ON `defaultSchemeId` = `schemeId`
                                                WHERE `f_appName` = :appName AND `activityName` = :activityName;)",
        {{":appName", MAKE_VAR(STRING, appName)}, {":activityName", MAKE_VAR(STRING, activityName)}}, {&parentActivity, &description, &defaultSchemeId, &defaultSchemeDescription});
    if (i.getResultsOK() && i.query->step())
    {
        IdentityManager::ApplicationActivities::ActivityData r;
        r = {.description = description.toString(),
             .parentActivity = parentActivity.toString(),
             .defaultSchemeDescription = defaultSchemeDescription.toString(),
             .defaultSchemeID = defaultSchemeId.getValue()};
        return r;
    }
    return std::nullopt;
}

std::map<std::string, IdentityManager::ApplicationActivities::ActivityData> IdentityManager_DB::ApplicationActivities_DB::listApplicationActivities(const std::string &appName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::STRING name, description, parentActivity, defaultSchemeDescription;
    Abstract::UINT32 defaultSchemeId;
    std::map<std::string, IdentityManager::ApplicationActivities::ActivityData> activities;

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect(
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
        activities[name.toString()] = {.description = description.toString(),
                                       .parentActivity = parentActivity.toString(),
                                       .defaultSchemeDescription = defaultSchemeDescription.toString(),
                                       .defaultSchemeID = defaultSchemeId.getValue()};
    }
    return activities;
}

std::optional<uint32_t> IdentityManager_DB::ApplicationActivities_DB::getApplicationActivityDefaultScheme(const std::string &appName, const std::string &activityName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    // Temporal variable to store the result
    Abstract::UINT32 uDefaultSchemeId;

    // Query to get the default scheme ID for the application activity
    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `defaultSchemeId` FROM iam.applicationActivities WHERE `f_appName`=:appName AND `activityName`=:activityName;",
                                                                     {{":appName", MAKE_VAR(STRING, appName)}, {":activityName", MAKE_VAR(STRING, activityName)}}, {&uDefaultSchemeId});

    // Check if a result is available
    if (i.getResultsOK() && i.query->step())
    {
        // Return nullopt if no default scheme is set
        if (uDefaultSchemeId.isNull())
            return std::nullopt;

        return uDefaultSchemeId.getValue();
    }

    // Return nullopt if failed to found the app activity.
    return std::nullopt;
}

bool IdentityManager_DB::ApplicationActivities_DB::setApplicationActivityDefaultScheme(const std::string &appName, const std::string &activityName, const uint32_t &schemeId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Update the default scheme ID for the specified application activity
    return _parent->m_sqlConnector->execute("UPDATE iam.applicationActivities SET `defaultSchemeId`=:schemeId WHERE `f_appName`=:appName AND `activityName`=:activityName;",
                                            {{":schemeId", MAKE_VAR(UINT32, schemeId)}, {":appName", MAKE_VAR(STRING, appName)}, {":activityName", MAKE_VAR(STRING, activityName)}});
}

std::set<uint32_t> IdentityManager_DB::ApplicationActivities_DB::listAuthenticationSchemesForApplicationActivity(const std::string &appName, const std::string &activityName)
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::set<uint32_t> ret;

    // Temporal Variables to store the results
    Abstract::UINT32 uSchemeId;

    SQLConnector::QueryInstance i = _parent->m_sqlConnector->qSelect("SELECT `f_schemeId` FROM iam.applicationActivitiesAuthSchemes WHERE `f_appName`=:appName AND `f_activityName`=:activityName;",
                                                                     {{":appName", MAKE_VAR(STRING, appName)}, {":activityName", MAKE_VAR(STRING, activityName)}}, {&uSchemeId});

    // Iterate:
    while (i.getResultsOK() && i.query->step())
    {
        ret.insert(uSchemeId.getValue());
    }

    return ret;
}

bool IdentityManager_DB::ApplicationActivities_DB::addAuthenticationSchemeToApplicationActivity(const std::string &appName, const std::string &activityName, const uint32_t &schemeId)
{
    // Acquire a write lock since we are modifying the database
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Execute the query using direct parameter passing...
    return _parent->m_sqlConnector->execute("INSERT INTO iam.applicationActivitiesAuthSchemes (`f_appName`, `f_activityName`, `f_schemeId`) "
                                            "VALUES (:appName, :activityName, :schemeId);",
                                            {{":appName", MAKE_VAR(STRING, appName)}, {":activityName", MAKE_VAR(STRING, activityName)}, {":schemeId", MAKE_VAR(UINT32, schemeId)}});
}

bool IdentityManager_DB::ApplicationActivities_DB::removeAuthenticationSchemeFromApplicationActivity(const std::string &appName, const std::string &activityName, const uint32_t &schemeId)
{
    // Acquire a write lock since we are modifying the database
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Execute the query with direct parameter passing
    return _parent->m_sqlConnector->execute("DELETE FROM iam.applicationActivitiesAuthSchemes "
                                            "WHERE `f_appName` = :appName AND `f_activityName` = :activityName AND `f_schemeId` = :schemeId;",
                                            {{":appName", MAKE_VAR(STRING, appName)}, {":activityName", MAKE_VAR(STRING, activityName)}, {":schemeId", MAKE_VAR(UINT32, schemeId)}});
}
