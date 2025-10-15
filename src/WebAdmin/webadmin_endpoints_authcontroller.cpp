#include "webadmin_endpoints_authcontroller.h"
#include "../globals.h"
#include "json/value.h"
#include <Mantids30/Program_Logs/applog.h>
#include <optional>

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocols;

void WebAdmin_Endpoints_AuthController::addEndpoints_AuthController(std::shared_ptr<Endpoints> endpoints)
{
    using SecurityOptions = Mantids30::API::RESTful::Endpoints::SecurityOptions;

    endpoints->addEndpoint(Endpoints::GET,    "listAuthenticationSlots",     SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_READ"},     nullptr, &listAuthenticationSlots);
    endpoints->addEndpoint(Endpoints::POST,   "addNewAuthenticationSlot",    SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_WRITE"},    nullptr, &addNewAuthenticationSlot);
    endpoints->addEndpoint(Endpoints::DELETE, "deleteAuthenticationSlot",    SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_DELETE"},   nullptr, &deleteAuthenticationSlot);
    endpoints->addEndpoint(Endpoints::PATCH,  "updateAuthenticationSlot",    SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_MODIFY"},   nullptr, &updateAuthenticationSlot);

    endpoints->addEndpoint(Endpoints::POST,   "addNewAuthenticationScheme",  SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_WRITE"},    nullptr, &addNewAuthenticationScheme);
    endpoints->addEndpoint(Endpoints::GET,    "listAuthenticationSchemes",   SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_READ"},     nullptr, &listAuthenticationSchemes);
    endpoints->addEndpoint(Endpoints::DELETE, "deleteAuthenticationScheme",  SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_DELETE"},   nullptr, &deleteAuthenticationScheme);
    endpoints->addEndpoint(Endpoints::PATCH,  "updateAuthenticationScheme",  SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_DELETE"},   nullptr, &updateAuthenticationScheme);

    endpoints->addEndpoint(Endpoints::GET,    "listAuthenticationSlotsUsedByScheme", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_READ"},     nullptr, &listAuthenticationSlotsUsedByScheme);
    endpoints->addEndpoint(Endpoints::PATCH,  "updateAuthenticationSlotsUsedByScheme", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_MODIFY"},   nullptr, &updateAuthenticationSlotsUsedByScheme);

    endpoints->addEndpoint(Endpoints::GET,    "getDefaultAuthScheme",        SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_READ"},     nullptr, &getDefaultAuthScheme);
    endpoints->addEndpoint(Endpoints::PATCH,  "updateDefaultAuthScheme",     SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"AUTH_MODIFY"},   nullptr, &updateDefaultAuthScheme);

}
WebAdmin_Endpoints_AuthController::APIReturn WebAdmin_Endpoints_AuthController::updateDefaultAuthScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    auto authController = Globals::getIdentityManager()->authController;

    // Extract the new default authentication scheme ID from the request body
    uint32_t newDefaultSchemeId = JSON_ASUINT(*request.inputJSON,"defaultSchemeId",std::numeric_limits<uint32_t>::max());

    if (newDefaultSchemeId == std::numeric_limits<uint32_t>::max())
    {
        return APIReturn(HTTP::Status::S_400_BAD_REQUEST,"invalid_request", "Missing or invalid 'defaultSchemeId' in request body");
    }

    if (!authController->updateDefaultAuthScheme(newDefaultSchemeId))
    {
        return APIReturn(HTTP::Status::S_500_INTERNAL_SERVER_ERROR,"invalid_request", "Internal server error while updating default authentication slot");
    }

    return APIReturn();
}

WebAdmin_Endpoints_AuthController::APIReturn WebAdmin_Endpoints_AuthController::getDefaultAuthScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    auto authController = Globals::getIdentityManager()->authController;

    // Retrieve the current default authentication slot
    std::optional<uint32_t> defaultScheme = authController->getDefaultAuthScheme();


    if (!defaultScheme.has_value())
    {
        return APIReturn(HTTP::Status::S_500_INTERNAL_SERVER_ERROR,"invalid_request", "Internal server error while retrieving default authentication slot");
    }

    Json::Value response;
    response["defaultSchemeId"] = *defaultScheme;
    return response;
}

API::APIReturn WebAdmin_Endpoints_AuthController::addNewAuthenticationScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
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

API::APIReturn WebAdmin_Endpoints_AuthController::listAuthenticationSchemes(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::map<uint32_t, std::string> slots = Globals::getIdentityManager()->authController->listAuthenticationSchemes();
    json r;

    auto defaultScheme = Globals::getIdentityManager()->authController->getDefaultAuthScheme();

    if (defaultScheme.has_value())
        r["defaultSchemeId"] = *defaultScheme;
    else
        r["defaultSchemeId"] = Json::nullValue;

    r["schemes"] = Json::arrayValue;

    for (const auto & slot : slots)
    {
        json rSlot;
        rSlot["description"] = slot.second;
        rSlot["id"] = slot.first;
        r["schemes"].append(rSlot);
    }

    return r;

}

API::APIReturn WebAdmin_Endpoints_AuthController::deleteAuthenticationScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    uint32_t schemeId = JSON_ASUINT(*request.inputJSON, "schemeId", 0);

    if (!Globals::getIdentityManager()->authController->removeAuthenticationScheme(schemeId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the new slot.");
    }
    return response;

}

API::APIReturn WebAdmin_Endpoints_AuthController::updateAuthenticationScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
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

API::APIReturn WebAdmin_Endpoints_AuthController::listAuthenticationSlotsUsedByScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
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

API::APIReturn WebAdmin_Endpoints_AuthController::updateAuthenticationSlotsUsedByScheme(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
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

API::APIReturn WebAdmin_Endpoints_AuthController::listAuthenticationSlots(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
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

API::APIReturn WebAdmin_Endpoints_AuthController::addNewAuthenticationSlot(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
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

API::APIReturn WebAdmin_Endpoints_AuthController::deleteAuthenticationSlot(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    uint32_t slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);

    if (!Globals::getIdentityManager()->authController->removeAuthenticationSlot(slotId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the new slot.");
    }
    return response;


}

API::APIReturn WebAdmin_Endpoints_AuthController::updateAuthenticationSlot(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
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
