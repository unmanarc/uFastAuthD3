#include "webadmin_methods_authcontroller.h"
#include "../globals.h"
#include "defs.h"
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

}

void WebAdmin_Methods_AuthController::listAuthenticationSlots(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
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

}

void WebAdmin_Methods_AuthController::addNewAuthenticationSlot(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    AuthenticationSlotDetails slot;
    slot.fromJSON(*request.inputJSON);
    uint32_t r = Globals::getIdentityManager()->authController->addNewAuthenticationSlot(slot);
    if (r == UINT32_MAX)
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the new slot");
    }
    (*response.responseJSON()) = r;
}

void WebAdmin_Methods_AuthController::deleteAuthenticationSlot(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    uint32_t slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);

    if (!Globals::getIdentityManager()->authController->removeAuthenticationSlot(slotId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the new slot.");
    }

}

void WebAdmin_Methods_AuthController::updateAuthenticationSlot(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    AuthenticationSlotDetails slotDetails;
    slotDetails.fromJSON(*request.inputJSON);
    uint32_t slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);

    uint32_t r = Globals::getIdentityManager()->authController->updateAuthenticationSlotDetails(slotId,slotDetails);
    if (r == UINT32_MAX)
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to edit the slot");
    }
    (*response.responseJSON()) = r;

}
