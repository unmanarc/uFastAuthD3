#include "webadmin_methods_authcontroller.h"
#include "../globals.h"
#include "defs.h"
#include <Mantids30/Program_Logs/applog.h>

void WebAdmin_Methods_AuthController::addMethods_AuthController(std::shared_ptr<MethodsHandler> methods)
{
    using SecurityOptions = Mantids30::API::RESTful::MethodsHandler::SecurityOptions;

    methods->addResource(MethodsHandler::GET, "listAuthenticationSlots", &listAuthenticationSlots, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_READ"});

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
