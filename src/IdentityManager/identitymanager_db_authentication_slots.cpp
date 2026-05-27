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

using namespace Mantids30::Memory;
using namespace Mantids30::Database;
using namespace Mantids30;

std::optional<uint32_t> IdentityManager_DB::AuthController_DB::addNewAuthenticationSlot(const ClientDetails &clientDetails, const std::string &performedBy, const AuthenticationSlotDetails &details)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    auto i = _parent->m_sqlConnector->qExecute("INSERT INTO iam.authenticationSlots (`description`,`function`,`defaultExpirationSeconds`,`strengthJSONValidator`,`totp2FAStepsToleranceWindow`) "
                                               "VALUES(:description,:function,:defaultExpirationSeconds,:strengthJSONValidator,:totp2FAStepsToleranceWindow);",
                                               {{":description", MAKE_VAR(STRING, details.description)},
                                                {":function", MAKE_VAR(UINT32, details.passwordFunction)},
                                                {":defaultExpirationSeconds", MAKE_VAR(UINT32, details.defaultExpirationSeconds)},
                                                {":totp2FAStepsToleranceWindow", MAKE_VAR(UINT32, details.totp2FAStepsToleranceWindow)},
                                                {":strengthJSONValidator", MAKE_VAR(STRING, details.strengthJSONValidator)}});
    if (!i || !i->isSuccessful())
        return std::nullopt;

    uint32_t newSlotId = i->getLastInsertRowID();

    _parent->logAuthenticationSlotSecurityEvent(newSlotId, SecurityEventAction::CREATE, "New authentication slot created", performedBy, clientDetails);

    return newSlotId;
}

bool IdentityManager_DB::AuthController_DB::removeAuthenticationSlot(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &slotId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    bool success = _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.authenticationSlots WHERE `slotId`=:slotId;", {{":slotId", MAKE_VAR(UINT32, slotId)}});

    if (success)
    {
        _parent->logAuthenticationSlotSecurityEvent(slotId, SecurityEventAction::DELETE, "Authentication slot removed", performedBy, clientDetails);
    }

    return success;
}

bool IdentityManager_DB::AuthController_DB::updateAuthenticationSlotDetails(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &slotId,
                                                                            const AuthenticationSlotDetails &details)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    // Update...
    bool success = _parent->m_sqlConnector->qExecuteEx("UPDATE iam.authenticationSlots SET "
                                                       "`description` = :description, "
                                                       "`defaultExpirationSeconds` = :defaultExpirationSeconds, "
                                                       "`totp2FAStepsToleranceWindow` = :totp2FAStepsToleranceWindow, "
                                                       "`strengthJSONValidator` = :strengthJSONValidator "
                                                       "WHERE `slotId` = :slotId;",
                                                       {{":slotId", MAKE_VAR(UINT32, slotId)},
                                                        {":description", MAKE_VAR(STRING, details.description)},
                                                        {":defaultExpirationSeconds", MAKE_VAR(UINT32, details.defaultExpirationSeconds)},
                                                        {":totp2FAStepsToleranceWindow", MAKE_VAR(UINT32, details.totp2FAStepsToleranceWindow)},
                                                        {":strengthJSONValidator", MAKE_VAR(STRING, details.strengthJSONValidator)}});

    if (success)
    {
        _parent->logAuthenticationSlotSecurityEvent(slotId, SecurityEventAction::UPDATE, "Authentication slot details updated", performedBy, clientDetails);
    }

    return success;
}

std::map<uint32_t, AuthenticationSlotDetails> IdentityManager_DB::AuthController_DB::listAllAuthenticationSlots()
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);

    std::map<uint32_t, AuthenticationSlotDetails> ret;

    // Temporal Variables to store the results
    Abstract::UINT32 uSlotId;
    Abstract::STRING sDescription;
    Abstract::UINT32 uFunction;
    Abstract::UINT32 uDefaultExpirationSeconds;
    Abstract::STRING sStrengthJSONValidator;
    Abstract::UINT32 uTotp2FAStepsToleranceWindow;

    auto i = _parent->m_sqlConnector->qSelect("SELECT `slotId`, `description`, `function`, `defaultExpirationSeconds`, `strengthJSONValidator`,`totp2FAStepsToleranceWindow` "
                                              "FROM iam.authenticationSlots;",
                                              {}, {&uSlotId, &sDescription, &uFunction, &uDefaultExpirationSeconds, &sStrengthJSONValidator, &uTotp2FAStepsToleranceWindow});

    // Iterate:
    while (i && i->isSuccessful() && i->step())
    {
        // Build AuthenticationSlotDetails and insert it to the maps
        ret.insert({uSlotId.getValue(), AuthenticationSlotDetails(sDescription.getValue(), (HashFunction) uFunction.getValue(), sStrengthJSONValidator.getValue(), uDefaultExpirationSeconds.getValue(),
                                                                  uTotp2FAStepsToleranceWindow.getValue())});
    }

    return ret;
}
