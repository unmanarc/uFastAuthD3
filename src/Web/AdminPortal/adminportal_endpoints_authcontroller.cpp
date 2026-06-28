#include "adminportal_endpoints_authcontroller.h"
#include "globals.h"
#include <Mantids30/Program_Logs/applog.h>
#include <json/value.h>
#include <optional>

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocol;

void AdminPortal_Endpoints_AuthController::addEndpoints_AuthController(const std::shared_ptr<Endpoints> &endpoints)
{
    using SecurityRequirements = API::Security::Requirements;

    endpoints->addEndpoint(HTTP::Method::GET, "listAuthenticationSlots", SecurityRequirements::JWT_COOKIE_AUTH, {"AUTH_READ"}, nullptr, &listAuthenticationSlots);
    endpoints->addEndpoint(HTTP::Method::POST, "createAuthenticationSlot", SecurityRequirements::JWT_COOKIE_AUTH, {"AUTH_WRITE"}, nullptr, &createAuthenticationSlot);
    endpoints->addEndpoint(HTTP::Method::DELETE, "deleteAuthenticationSlot", SecurityRequirements::JWT_COOKIE_AUTH, {"AUTH_DELETE"}, nullptr, &deleteAuthenticationSlot);
    endpoints->addEndpoint(HTTP::Method::PATCH, "updateAuthenticationSlot", SecurityRequirements::JWT_COOKIE_AUTH, {"AUTH_MODIFY"}, nullptr, &updateAuthenticationSlot);
    endpoints->addEndpoint(HTTP::Method::POST, "createAuthenticationScheme", SecurityRequirements::JWT_COOKIE_AUTH, {"AUTH_WRITE"}, nullptr, &createAuthenticationScheme);
    endpoints->addEndpoint(HTTP::Method::GET, "listAuthenticationSchemes", SecurityRequirements::JWT_COOKIE_AUTH, {"AUTH_READ"}, nullptr, &listAuthenticationSchemes);
    endpoints->addEndpoint(HTTP::Method::DELETE, "deleteAuthenticationScheme", SecurityRequirements::JWT_COOKIE_AUTH, {"AUTH_DELETE"}, nullptr, &deleteAuthenticationScheme);
    endpoints->addEndpoint(HTTP::Method::PATCH, "updateAuthenticationScheme", SecurityRequirements::JWT_COOKIE_AUTH, {"AUTH_DELETE"}, nullptr, &updateAuthenticationScheme);
    endpoints->addEndpoint(HTTP::Method::GET, "listAuthenticationSlotsUsedByScheme", SecurityRequirements::JWT_COOKIE_AUTH, {"AUTH_READ"}, nullptr, &listAuthenticationSlotsUsedByScheme);
    endpoints->addEndpoint(HTTP::Method::PATCH, "updateAuthenticationSlotsUsedByScheme", SecurityRequirements::JWT_COOKIE_AUTH, {"AUTH_MODIFY"}, nullptr, &updateAuthenticationSlotsUsedByScheme);
    endpoints->addEndpoint(HTTP::Method::GET, "getDefaultAuthScheme", SecurityRequirements::JWT_COOKIE_AUTH, {"AUTH_READ"}, nullptr, &getDefaultAuthScheme);
    endpoints->addEndpoint(HTTP::Method::PATCH, "updateDefaultAuthScheme", SecurityRequirements::JWT_COOKIE_AUTH, {"AUTH_MODIFY"}, nullptr, &updateDefaultAuthScheme);


}
AdminPortal_Endpoints_AuthController::APIReturn AdminPortal_Endpoints_AuthController::updateDefaultAuthScheme(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    // Extract the new default authentication scheme ID from the request body
    uint32_t newDefaultSchemeId = Helpers::JSON::ASUINT(*request.inputJSON, "defaultSchemeId", std::numeric_limits<uint32_t>::max());

    if (newDefaultSchemeId == std::numeric_limits<uint32_t>::max())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Missing or invalid 'defaultSchemeId' in request body"};
    }

    if (!Globals::getIdentityManager()->authController->updateDefaultAuthScheme(authClientDetails, request.jwtToken->getSubject(), newDefaultSchemeId))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "invalid_request", "Internal server error while updating default authentication slot"};
    }

    return {};
}

AdminPortal_Endpoints_AuthController::APIReturn AdminPortal_Endpoints_AuthController::getDefaultAuthScheme(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    // Retrieve the current default authentication slot
    std::optional<uint32_t> defaultScheme = Globals::getIdentityManager()->authController->getDefaultAuthScheme();

    if (!defaultScheme.has_value())
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "invalid_request", "Internal server error while retrieving default authentication slot"};
    }

    Json::Value response;
    response["defaultSchemeId"] = *defaultScheme;
    return response;
}

API::APIReturn AdminPortal_Endpoints_AuthController::createAuthenticationScheme(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::optional<uint32_t> r = Globals::getIdentityManager()->authController->createAuthenticationScheme(authClientDetails, request.jwtToken->getSubject(),
                                                                                                       Helpers::JSON::ASSTRING(*request.inputJSON, "description", ""));
    if (!r.has_value())
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the new authentication scheme"};
    }
    (*response.responseJSON()) = *r;
    return response;
}

API::APIReturn AdminPortal_Endpoints_AuthController::listAuthenticationSchemes(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::map<uint32_t, std::string> slots = Globals::getIdentityManager()->authController->listAuthenticationSchemes();
    Json::Value r;

    std::optional<uint32_t> defaultScheme = Globals::getIdentityManager()->authController->getDefaultAuthScheme();

    if (defaultScheme.has_value())
    {
        r["defaultSchemeId"] = *defaultScheme;
    }
    else
    {
        r["defaultSchemeId"] = Json::nullValue;
    }

    r["schemes"] = Json::arrayValue;

    for (const auto &slot : slots)
    {
        Json::Value rSlot;
        rSlot["description"] = slot.second;
        rSlot["id"] = slot.first;
        r["schemes"].append(rSlot);
    }

    return r;
}

API::APIReturn AdminPortal_Endpoints_AuthController::deleteAuthenticationScheme(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    uint32_t schemeId = Helpers::JSON::ASUINT(*request.inputJSON, "schemeId", 0);

    if (!Globals::getIdentityManager()->authController->removeAuthenticationScheme(authClientDetails, request.jwtToken->getSubject(), schemeId))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the new slot."};
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_AuthController::updateAuthenticationScheme(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    uint32_t schemeId = Helpers::JSON::ASUINT(*request.inputJSON, "schemeId", 0);
    std::string description = Helpers::JSON::ASSTRING(*request.inputJSON, "description", "");

    if (!Globals::getIdentityManager()->authController->updateAuthenticationScheme(authClientDetails, request.jwtToken->getSubject(), schemeId, description))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the authentication scheme"};
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_AuthController::listAuthenticationSlotsUsedByScheme(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    uint32_t schemeId = Helpers::JSON::ASUINT(*request.inputJSON, "schemeId", 0);
    std::vector<AuthenticationSchemeUsedSlot> slots = Globals::getIdentityManager()->authController->listAuthenticationSlotsUsedByScheme(schemeId);
    Json::Value r;
    r["leftSlots"] = Json::arrayValue;
    r["usedSlots"] = Json::arrayValue;

    std::set<uint32_t> usedSlots;
    for (const AuthenticationSchemeUsedSlot &slot : slots)
    {
        usedSlots.insert(slot.slotId);

        Json::Value rSlot;
        rSlot = slot.toJSON();
        r["usedSlots"].append(rSlot);
    }

    std::map<uint32_t, AuthenticationSlotDetails> allSlots = Globals::getIdentityManager()->authController->listAllAuthenticationSlots();
    for (const auto &slot : allSlots)
    {
        if (usedSlots.find(slot.first) == usedSlots.end())
        {
            // Not used, add..
            Json::Value rSlot;
            rSlot["slotId"] = slot.first;
            rSlot["details"] = slot.second.toJSON();
            r["leftSlots"].append(rSlot);
        }
    }

    (*response.responseJSON()) = r;
    return response;
}

API::APIReturn AdminPortal_Endpoints_AuthController::updateAuthenticationSlotsUsedByScheme(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    uint32_t schemeId = Helpers::JSON::ASUINT(*request.inputJSON, "schemeId", 0);

    std::list<AuthenticationSchemeUsedSlot> slotsUsedByScheme;

    for (const Json::Value &jSlot : (*request.inputJSON)["authSchemeSlots"])
    {
        AuthenticationSchemeUsedSlot slot(0, 0, false);
        slot.fromJSON(jSlot);
        slotsUsedByScheme.push_back(slot);
    }

    if (!Globals::getIdentityManager()->authController->updateAuthenticationSlotUsedByScheme(authClientDetails, request.jwtToken->getSubject(), schemeId, slotsUsedByScheme))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the authentication scheme slots"};
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_AuthController::listAuthenticationSlots(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::map<uint32_t, AuthenticationSlotDetails> slots = Globals::getIdentityManager()->authController->listAllAuthenticationSlots();
    Json::Value r;
    for (const auto &slot : slots)
    {
        Json::Value rSlot;
        rSlot = slot.second.toJSON();
        rSlot["id"] = slot.first;
        r.append(rSlot);
    }
    (*response.responseJSON()) = r;
    return response;
}

API::APIReturn AdminPortal_Endpoints_AuthController::createAuthenticationSlot(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    AuthenticationSlotDetails slot;
    slot.fromJSON(*request.inputJSON);
    std::optional<uint32_t> r = Globals::getIdentityManager()->authController->createAuthenticationSlot(authClientDetails, request.jwtToken->getSubject(), slot);
    if (!r.has_value())
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the new slot"};
    }
    (*response.responseJSON()) = *r;
    return response;
}

API::APIReturn AdminPortal_Endpoints_AuthController::deleteAuthenticationSlot(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    uint32_t slotId = Helpers::JSON::ASUINT(*request.inputJSON, "slotId", 0);

    if (!Globals::getIdentityManager()->authController->removeAuthenticationSlot(authClientDetails, request.jwtToken->getSubject(), slotId))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the new slot."};
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_AuthController::updateAuthenticationSlot(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    AuthenticationSlotDetails slotDetails;
    slotDetails.fromJSON(*request.inputJSON);
    uint32_t slotId = Helpers::JSON::ASUINT(*request.inputJSON, "slotId", 0);

    if (!Globals::getIdentityManager()->authController->updateAuthenticationSlotDetails(authClientDetails, request.jwtToken->getSubject(), slotId, slotDetails))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update the authentication slot"};
    }

    return response;
}
