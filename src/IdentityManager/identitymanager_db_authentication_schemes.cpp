#include "identitymanager_db.h"

#include <Mantids30/Helpers/datatables.h>
#include <Mantids30/Threads/lock_shared.h>

#include <Mantids30/Memory/a_bool.h>
#include <Mantids30/Memory/a_datetime.h>
#include <Mantids30/Memory/a_int32.h>
#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_uint32.h>
#include <Mantids30/Memory/a_uint64.h>
#include <Mantids30/Memory/a_var.h>
#include <string>

using namespace Mantids30::Memory;
using namespace Mantids30::Database;
using namespace Mantids30;

bool IdentityManager_DB::AuthController_DB::updateDefaultAuthScheme(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &schemeId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Delete any existing default scheme
    _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.defaultAuthScheme;", {});

    // Insert the new default scheme
    bool success = _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.defaultAuthScheme (`f_defaultSchemeId`) VALUES (:schemeId);", {{":schemeId", MAKE_VAR(UINT32, schemeId)}});

    if (success)
    {
        _parent->logSecurityEventOnAuthenticationSchemes(schemeId, SecurityEventAction::UPDATE, "Set as default scheme", performedBy, clientDetails);
    }

    return success;
}

std::optional<uint32_t> IdentityManager_DB::AuthController_DB::getDefaultAuthScheme()
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    Abstract::UINT32 schemeId;
    if (!_parent->m_sqlConnector->qSelectSingleRow("SELECT f_defaultSchemeId FROM iam.defaultAuthScheme WHERE id = 1;", {}, {&schemeId}))
    {
        return std::nullopt;
    }
    return schemeId.getValue();
}

std::optional<uint32_t> IdentityManager_DB::AuthController_DB::createAuthenticationScheme(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &description)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    uint32_t newSchemeId = 0;
    {
        std::shared_ptr<Query> i = _parent->m_sqlConnector->qExecute("INSERT INTO iam.authenticationSchemes (`description`) VALUES(:description);", {{":description", MAKE_VAR(STRING, description)}});

        if (!i || !i->isSuccessful())
        {
            return std::nullopt;
        }

        newSchemeId = i->getLastInsertRowID();
    }

    _parent->logSecurityEventOnAuthenticationSchemes(newSchemeId, SecurityEventAction::CREATE, "New authentication scheme created", performedBy, clientDetails);

    return newSchemeId;
}

bool IdentityManager_DB::AuthController_DB::updateAuthenticationScheme(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &schemeId, const std::string &description)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Update...
    bool success = _parent->m_sqlConnector->qExecuteEx("UPDATE iam.authenticationSchemes SET "
                                                       "`description` = :description "
                                                       "WHERE `schemeId` = :schemeId;",
                                                       {{":schemeId", MAKE_VAR(UINT32, schemeId)}, {":description", MAKE_VAR(STRING, description)}});

    if (success)
    {
        _parent->logSecurityEventOnAuthenticationSchemes(schemeId, SecurityEventAction::UPDATE, "Authentication scheme updated", performedBy, clientDetails);
    }

    return success;
}

bool IdentityManager_DB::AuthController_DB::removeAuthenticationScheme(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &schemeId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    bool success = _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.authenticationSchemes WHERE `schemeId`=:schemeId;", {{":schemeId", MAKE_VAR(UINT32, schemeId)}});

    if (success)
    {
        _parent->logSecurityEventOnAuthenticationSchemes(schemeId, SecurityEventAction::DELETE, "Authentication scheme removed", performedBy, clientDetails);
    }

    return success;
}

std::map<uint32_t, std::string> IdentityManager_DB::AuthController_DB::listAuthenticationSchemes()
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::map<uint32_t, std::string> ret;

    // Temporal Variables to store the results
    Abstract::UINT32 uSlotId;
    Abstract::STRING sDescription;

    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect("SELECT `schemeId`, `description` FROM iam.authenticationSchemes;", {}, {&uSlotId, &sDescription});

    // Iterate:
    while (i && i->isSuccessful() && i->step())
    {
        ret.insert({uSlotId.getValue(), sDescription.getValue()});
    }

    return ret;
}

std::vector<AuthenticationSchemeUsedSlot> IdentityManager_DB::AuthController_DB::listAuthenticationSlotsUsedByScheme(const uint32_t &schemeId)
{
    std::vector<AuthenticationSchemeUsedSlot> slotsList;
    std::map<uint32_t, AuthenticationSlotDetails> allAuthSlots = listAllAuthenticationSlots();

    // Acquire a read lock for thread-safe read operation
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    Abstract::UINT32 uSlotId;
    Abstract::UINT32 uOrderPriority;
    Abstract::BOOL uOptional;

    // Prepare the SQL SELECT statement to fetch slot details by schemeId
    std::string sql = "SELECT `f_slotId`, `orderPriority`, `optional` "
                      "FROM `iam`.`authenticationSchemeUsedSlots` "
                      "WHERE `f_schemeId` = :schemeId "
                      "ORDER BY `orderPriority` ASC;"; // Assuming you want to order by priority

    // Execute the query with direct parameter passing
    std::shared_ptr<Query> queryInstance = _parent->m_sqlConnector->qSelect(sql, {{":schemeId", MAKE_VAR(UINT32, schemeId)}}, {&uSlotId, &uOrderPriority, &uOptional});

    // Assuming queryInstance->query provides a way to iterate over results and bind columns to variables

    while (queryInstance && queryInstance->isSuccessful() && queryInstance->step())
    {
        uint32_t slotId = uSlotId.getValue(), orderPriority = uOrderPriority.getValue();
        bool optional = uOptional.getValue();

        // Add the fetched slot details to the list
        if (allAuthSlots.find(slotId) != allAuthSlots.end())
        {
            slotsList.emplace_back(slotId, orderPriority, optional, allAuthSlots[slotId]);
        }
    }

    return slotsList;
}

bool IdentityManager_DB::AuthController_DB::updateAuthenticationSlotUsedByScheme(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &schemeId,
                                                                                 const std::list<AuthenticationSchemeUsedSlot> &slotsUsedByScheme)
{
    // Acquire a write lock for thread-safe database modification
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Remove existing slots for the scheme
    std::string deleteSql = "DELETE FROM `iam`.`authenticationSchemeUsedSlots` WHERE `f_schemeId` = :schemeId;";
    if (!_parent->m_sqlConnector->qExecuteEx(deleteSql, {{":schemeId", MAKE_VAR(UINT32, schemeId)}}))
    {
        return false; // If deletion fails, return false
    }

    // Repopulate the table with new slots
    for (const AuthenticationSchemeUsedSlot &slot : slotsUsedByScheme)
    {
        std::string insertSql = "INSERT INTO `iam`.`authenticationSchemeUsedSlots` (`f_schemeId`, `f_slotId`, `orderPriority`, `optional`) VALUES (:schemeId, "
                                ":slotId, :orderPriority, :optional);";
        if (!_parent->m_sqlConnector->qExecuteEx(insertSql, {{":schemeId", MAKE_VAR(UINT32, schemeId)},
                                                             {":slotId", MAKE_VAR(UINT32, slot.slotId)},
                                                             {":orderPriority", MAKE_VAR(UINT32, slot.orderPriority)},
                                                             {":optional", MAKE_VAR(BOOL, slot.optional)}}))
        {
            // If any insert fails, there's limited context here to handle rollback or partial success scenarios
            return false;
        }
    }

    {
        _parent->logSecurityEventOnAuthenticationSchemes(schemeId, SecurityEventAction::UPDATE, "Authentication scheme slots configuration updated", performedBy, clientDetails);
    }

    return true; // Return true if deletion and all insert operations succeed
}
