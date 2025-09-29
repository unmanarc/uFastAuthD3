#include "webadmin_methods_authcontroller.h"
#include "../globals.h"
#include "json/value.h"
#include <Mantids30/Program_Logs/applog.h>

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocols;

void WebAdmin_Methods_AuthController::addMethods_AuthController(std::shared_ptr<MethodsHandler> methods)
{
    using SecurityOptions = Mantids30::API::RESTful::MethodsHandler::SecurityOptions;

    methods->addResource(MethodsHandler::GET, "listAuthenticationSlots", &listAuthenticationSlots, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_READ"});
    methods->addResource(MethodsHandler::POST, "addNewAuthenticationSlot", &addNewAuthenticationSlot, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_WRITE"});
    methods->addResource(MethodsHandler::DELETE, "deleteAuthenticationSlot", &deleteAuthenticationSlot, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_DELETE"});
    methods->addResource(MethodsHandler::PATCH, "updateAuthenticationSlot", &updateAuthenticationSlot, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_MODIFY"});

    methods->addResource(MethodsHandler::POST, "addNewAuthenticationScheme", &addNewAuthenticationScheme, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_WRITE"});
    methods->addResource(MethodsHandler::GET, "listAuthenticationSchemes", &listAuthenticationSchemes, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_READ"});
    methods->addResource(MethodsHandler::DELETE, "deleteAuthenticationScheme", &deleteAuthenticationScheme, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_DELETE"});
    methods->addResource(MethodsHandler::PATCH, "updateAuthenticationScheme", &updateAuthenticationScheme, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_DELETE"});

    methods->addResource(MethodsHandler::GET, "listAuthenticationSlotsUsedByScheme", &listAuthenticationSlotsUsedByScheme, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_READ"});
    methods->addResource(MethodsHandler::PATCH, "updateAuthenticationSlotsUsedByScheme", &updateAuthenticationSlotsUsedByScheme, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_MODIFY"});
}

API::APIReturn WebAdmin_Methods_AuthController::addNewAuthenticationScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::optional<uint32_t> r = Globals::getIdentityManager()->authController->addAuthenticationScheme(JSON_ASSTRING(*request.inputJSON,"description",""));
    if (!r.has_value())
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the new authentication scheme");
    }
    (*response.responseJSON()) = *r;
    return response;
}

API::APIReturn WebAdmin_Methods_AuthController::listAuthenticationSchemes(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::map<uint32_t, std::string> slots = Globals::getIdentityManager()->authController->listAuthenticationSchemes();
    json r;
    for (const auto & slot : slots)
    {
        json rSlot;
        rSlot["description"] = slot.second;
        rSlot["id"] = slot.first;
        r.append(rSlot);
    }
    (*response.responseJSON()) = r;
    return response;

}

API::APIReturn WebAdmin_Methods_AuthController::deleteAuthenticationScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    uint32_t schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", 0);

    if (!Globals::getIdentityManager()->authController->removeAuthenticationScheme(schemeId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the new slot.");
    }
    return response;

}

API::APIReturn WebAdmin_Methods_AuthController::updateAuthenticationScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    uint32_t schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", 0);
    std::string description = JSON_ASSTRING(*request.inputJSON, "description", "");

    if (!Globals::getIdentityManager()->authController->updateAuthenticationScheme(schemeId,description))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the authentication scheme");
    }

    return response;
}

API::APIReturn WebAdmin_Methods_AuthController::listAuthenticationSlotsUsedByScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    uint32_t schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", 0);
    std::vector<AuthenticationSchemeUsedSlot> slots = Globals::getIdentityManager()->authController->listAuthenticationSlotsUsedByScheme(schemeId);
    json r;
    r["leftSlots"] = Json::arrayValue;
    r["usedSlots"] = Json::arrayValue;

    std::set<uint32_t> usedSlots;
    for (const auto & slot : slots)
    {
        usedSlots.insert(slot.slotId);

        json rSlot;
        rSlot = slot.toJSON();
        r["usedSlots"].append(rSlot);
    }

    std::map<uint32_t, AuthenticationSlotDetails> allSlots = Globals::getIdentityManager()->authController->listAuthenticationSlots();
    for (const auto & slot : allSlots)
    {
        if ( usedSlots.find(slot.first) == usedSlots.end()  )
        {
            // Not used, add..
            json rSlot;
            rSlot["slotId"] = slot.first;
            rSlot["details"] = slot.second.toJSON();
            r["leftSlots"].append(rSlot);
        }
    }

    (*response.responseJSON()) = r;
    return response;

}

API::APIReturn WebAdmin_Methods_AuthController::updateAuthenticationSlotsUsedByScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    uint32_t schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", 0);

    std::list<AuthenticationSchemeUsedSlot> slotsUsedByScheme;

    for ( const json & jSlot : (*request.inputJSON)["authSchemeSlots"] )
    {
        AuthenticationSchemeUsedSlot slot(0,0,false);
        slot.fromJSON(jSlot);
        slotsUsedByScheme.push_back(slot);
    }

    if (!Globals::getIdentityManager()->authController->updateAuthenticationSlotUsedByScheme(schemeId,slotsUsedByScheme))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the authentication scheme slots");
    }
    return response;

}

API::APIReturn WebAdmin_Methods_AuthController::listAuthenticationSlots(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::map<uint32_t, AuthenticationSlotDetails> slots = Globals::getIdentityManager()->authController->listAuthenticationSlots();
    json r;
    for (const auto & slot : slots)
    {
        json rSlot;
        rSlot = slot.second.toJSON();
        rSlot["id"] = slot.first;
        r.append(rSlot);
    }
    (*response.responseJSON()) = r;
    return response;

}

API::APIReturn WebAdmin_Methods_AuthController::addNewAuthenticationSlot(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    AuthenticationSlotDetails slot;
    slot.fromJSON(*request.inputJSON);
    std::optional<uint32_t> r = Globals::getIdentityManager()->authController->addNewAuthenticationSlot(slot);
    if (!r.has_value())
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the new slot");
    }
    (*response.responseJSON()) = *r;
    return response;

}

API::APIReturn WebAdmin_Methods_AuthController::deleteAuthenticationSlot(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    uint32_t slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);

    if (!Globals::getIdentityManager()->authController->removeAuthenticationSlot(slotId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the new slot.");
    }
    return response;


}

API::APIReturn WebAdmin_Methods_AuthController::updateAuthenticationSlot(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    AuthenticationSlotDetails slotDetails;
    slotDetails.fromJSON(*request.inputJSON);
    uint32_t slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);

    if (!Globals::getIdentityManager()->authController->updateAuthenticationSlotDetails(slotId,slotDetails))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the authentication slot");
    }

    return response;
}
