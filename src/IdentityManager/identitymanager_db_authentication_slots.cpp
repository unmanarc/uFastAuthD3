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

std::optional<uint32_t> IdentityManager_DB::AuthController_DB::createAuthenticationSlot(const ClientDetails &clientDetails, const std::string &performedBy, const AuthenticationSlotDetails &details)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    uint32_t newSlotId = 0;
    {
        std::shared_ptr<Query> i = _parent->m_sqlConnector->qExecute(
            "INSERT INTO iam.authenticationSlots (`description`,`function`,`defaultExpirationSeconds`,`strengthJSONValidator`,`totp2FAStepsToleranceWindow`, `canSkipWhenExpired`) "
            "VALUES(:description,:function,:defaultExpirationSeconds,:strengthJSONValidator,:totp2FAStepsToleranceWindow,:canSkipWhenExpired);",
            {
                {":description", MAKE_VAR(STRING, details.description)},
                {":function", MAKE_VAR(UINT32,  details.passwordFunction.has_value()? static_cast<uint8_t>(details.passwordFunction.value()) : 500 )},
                {":defaultExpirationSeconds", MAKE_VAR(UINT32, details.defaultExpirationSeconds)},
                {":totp2FAStepsToleranceWindow", MAKE_VAR(UINT32, details.totp2FAStepsToleranceWindow)},
                {":strengthJSONValidator", MAKE_VAR(STRING, details.strengthJSONValidator.toStyledString())},
                {":canSkipWhenExpired", MAKE_VAR(BOOL, details.canSkipWhenExpired)},
            });
        if (!i || !i->isSuccessful())
        {
            return std::nullopt;
        }

        newSlotId = i->getLastInsertRowID();
    }

    _parent->logSecurityEventOnAuthenticationSlots(newSlotId, SecurityEventAction::CREATE, "New authentication slot created", performedBy, clientDetails);

    return newSlotId;
}

bool IdentityManager_DB::AuthController_DB::removeAuthenticationSlot(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &slotId)
{
    Threads::Sync::Lock_RW lock(_parent->m_mutex);

    bool success = _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.authenticationSlots WHERE `slotId`=:slotId;", {{":slotId", MAKE_VAR(UINT32, slotId)}});

    if (success)
    {
        _parent->logSecurityEventOnAuthenticationSlots(slotId, SecurityEventAction::DELETE, "Authentication slot removed", performedBy, clientDetails);
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
                                                       "`canSkipWhenExpired` = :canSkipWhenExpired, "
                                                       "`strengthJSONValidator` = :strengthJSONValidator "
                                                       "WHERE `slotId` = :slotId;",
                                                       {{":slotId", MAKE_VAR(UINT32, slotId)},
                                                        {":description", MAKE_VAR(STRING, details.description)},
                                                        {":defaultExpirationSeconds", MAKE_VAR(UINT32, details.defaultExpirationSeconds)},
                                                        {":canSkipWhenExpired", MAKE_VAR(BOOL, details.canSkipWhenExpired)},
                                                        {":totp2FAStepsToleranceWindow", MAKE_VAR(UINT32, details.totp2FAStepsToleranceWindow)},
                                                        {":strengthJSONValidator", MAKE_VAR(STRING, details.strengthJSONValidator.toStyledString())}});

    if (success)
    {
        _parent->logSecurityEventOnAuthenticationSlots(slotId, SecurityEventAction::UPDATE, "Authentication slot details updated", performedBy, clientDetails);
    }

    return success;
}

std::map<uint32_t, AuthenticationSlotDetails> IdentityManager_DB::AuthController_DB::listAllAuthenticationSlots()
{
    Threads::Sync::Lock_RD lock(_parent->m_mutex);
    static std::function<Json::Value(const char *)> parse = [](const char *json)
    {
        Json::Value r;
        Json::Reader().parse(json, r);
        return r;
    };

    std::map<uint32_t, AuthenticationSlotDetails> ret;

    // Temporal Variables to store the results
    Abstract::UINT32 uSlotId;
    Abstract::STRING sDescription;
    Abstract::UINT32 uFunction;
    Abstract::UINT32 uDefaultExpirationSeconds;
    Abstract::STRING sStrengthJSONValidator;
    Abstract::UINT32 uTotp2FAStepsToleranceWindow;
    Abstract::BOOL canSkipWhenExpired;

    std::shared_ptr<Query> i = _parent->m_sqlConnector
                                   ->qSelect("SELECT `slotId`, `description`, `function`, `defaultExpirationSeconds`, `strengthJSONValidator`,`totp2FAStepsToleranceWindow`,`canSkipWhenExpired` "
                                             "FROM iam.authenticationSlots;",
                                             {}, {&uSlotId, &sDescription, &uFunction, &uDefaultExpirationSeconds, &sStrengthJSONValidator, &uTotp2FAStepsToleranceWindow, &canSkipWhenExpired});

    // Iterate:
    while (i && i->isSuccessful() && i->step())
    {
        // Build AuthenticationSlotDetails and insert it to the maps
        ret.insert({uSlotId.getValue(), AuthenticationSlotDetails(sDescription.getValue(), (HashFunction) uFunction.getValue(), parse(sStrengthJSONValidator.getValue().c_str()),
                                                                  uDefaultExpirationSeconds.getValue(), uTotp2FAStepsToleranceWindow.getValue(), canSkipWhenExpired.getValue())});
    }

    return ret;
}
