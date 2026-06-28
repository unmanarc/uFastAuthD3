#include "adminportal_endpoints_account_credentials.h"

#include "globals.h"
#include <Mantids30/Program_Logs/applog.h>
#include <json/value.h>
#include <utility>

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocol;

void AdminPortal_Endpoints_AccountCredentials::addEndpoints_AccountCredentials(const std::shared_ptr<Endpoints> &endpoints)
{
    using SecurityRequirements = API::Security::Requirements;

    // Account Credential Slots:
    endpoints->addEndpoint(HTTP::Method::GET, "getAccountCredentialSlots", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_READ"}, nullptr, &getAccountCredentialSlots);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeAccountCredentialSlot", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &removeAccountCredentialSlot);
    endpoints->addEndpoint(HTTP::Method::PUT, "setAccountCredentialLockedStatus", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &setAccountCredentialLockedStatus);
    endpoints->addEndpoint(HTTP::Method::PUT, "setMustChangeCredential", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &setMustChangeCredential);
    endpoints->addEndpoint(HTTP::Method::POST, "generateMasterPassword", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &generateMasterPassword);
}

API::APIReturn AdminPortal_Endpoints_AccountCredentials::getAccountCredentialSlots(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    json jResponse;

    // Extract and validate input
    std::string accountUUID = Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", "");

    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    // Get credential slots for the account
    std::map<uint32_t, AuthenticationSlotDetails> allSlots = Globals::getIdentityManager()->authController->listAllAuthenticationSlots();

    // Get account credential data
    std::map<uint32_t, Credential> accountCredentialsPublicData = Globals::getIdentityManager()->authController->getAccountAllCredentialsPublicData(accountUUID);

    jResponse["slots"] = Json::arrayValue;
    jResponse["currentAuthPolicy"] = Json::nullValue;

    for (const auto &slot : allSlots)
    {
        json rSlot;
        rSlot["slotId"] = slot.first;
        rSlot["slotInfo"] = slot.second.toJSON();
        rSlot["slotData"] = Json::nullValue;
        if (accountCredentialsPublicData.find(slot.first) != accountCredentialsPublicData.end())
        {
            Credential slotData = accountCredentialsPublicData[slot.first];
            rSlot["slotData"] = slotData.toJSON(slotData.currentAuthPolicy);
            jResponse["currentAuthPolicy"] = slotData.currentAuthPolicy.toJSON();
        }

        jResponse["slots"].append(rSlot);
    }

    return jResponse;
}

API::APIReturn AdminPortal_Endpoints_AccountCredentials::removeAccountCredentialSlot(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    // Extract and validate input
    std::string accountUUID = Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", "");
    uint32_t slotId = Helpers::JSON::ASUINT(*request.inputJSON, "slotId", 0);

    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    if (slotId == 0)
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Slot ID is required"};
    }

    if (slotId == 1)
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Can´t remove the credential slot 1 (Master Password)"};
    }

    // Delete the credential slot for the account
    if (!Globals::getIdentityManager()->authController->removeAccountCredential(authClientDetails, request.jwtToken->getSubject(), accountUUID, slotId))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to delete the credential slot"};
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_AccountCredentials::setAccountCredentialLockedStatus(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    // Extract and validate input
    std::string accountUUID = Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", "");
    uint32_t slotId = Helpers::JSON::ASUINT(*request.inputJSON, "slotId", 0);
    bool lockedStatus = Helpers::JSON::ASBOOL(*request.inputJSON, "lockedStatus", false);

    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    if (slotId == 0)
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Slot ID is required"};
    }

    // Block the credential slot for the account
    if (!Globals::getIdentityManager()->authController->setAccountCredentialLockedStatus(authClientDetails, request.jwtToken->getSubject(), accountUUID, slotId, lockedStatus))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to set the lock state on the credential slot"};
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_AccountCredentials::setMustChangeCredential(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    // Extract and validate input
    std::string accountUUID = Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", "");
    uint32_t slotId = Helpers::JSON::ASUINT(*request.inputJSON, "slotId", 0);
    bool mustChange = Helpers::JSON::ASBOOL(*request.inputJSON, "mustChange", true);

    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    if (slotId == 0)
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Slot ID is required"};
    }

    // Force credential expiration for the account slot
    if (!Globals::getIdentityManager()->authController->setAccountCredentialMustChange(authClientDetails, request.jwtToken->getSubject(), accountUUID, slotId, mustChange))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to change credential flag to change"};
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_AccountCredentials::generateMasterPassword(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    // Extract and validate input
    std::string accountUUID = Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", "");

    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    // Generate a new master password for the account
    std::string newTempPassword;
    bool ok = Globals::getIdentityManager()->authController->recoverAccountMasterCredential(authClientDetails, request.jwtToken->getSubject(), accountUUID, &newTempPassword);

    if (!ok)
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to generate new master password"};
    }

    (*response.responseJSON())["password"] = newTempPassword;
    return response;
}
