#include "adminportal_endpoints_account_credentials.h"

#include "globals.h"
#include <Mantids30/Program_Logs/applog.h>
#include <json/value.h>
#include <utility>

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocol;

void AdminPortal_Endpoints_AccountCredentials::addEndpoints_AccountCredentials(const std::shared_ptr<Endpoints>& endpoints)
{
    using SecurityRequirements = API::Security::Requirements;

    // Account Credential Slots:
    endpoints->addEndpoint(HTTP::Method::GET, "getAccountCredentialSlots", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_READ"}, nullptr, &getAccountCredentialSlots);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeAccountCredentialSlot", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &removeAccountCredentialSlot);
    endpoints->addEndpoint(HTTP::Method::PUT, "setCredentialLockedStatus", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &setCredentialLockedStatus);
    endpoints->addEndpoint(HTTP::Method::PUT, "setMustChangeCredential", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &setMustChangeCredential);
    endpoints->addEndpoint(HTTP::Method::POST, "generateMasterPassword", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &generateMasterPassword);
}

API::APIReturn AdminPortal_Endpoints_AccountCredentials::getAccountCredentialSlots(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    json jResponse;

    // Extract and validate input
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (accountName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return response;
    }

    // Get credential slots for the account
    std::map<uint32_t, AuthenticationSlotDetails> allSlots = Globals::getIdentityManager()->authController->listAllAuthenticationSlots();

    // Get account credential data
    std::map<uint32_t, Credential> accountCredentialsPublicData = Globals::getIdentityManager()->authController->getAccountAllCredentialsPublicData(accountName);

    jResponse["slots"] = Json::arrayValue;
    jResponse["currentAuthPolicy"] = Json::nullValue;

    for (const std::pair<uint32_t, AuthenticationSlotDetails> &slot : allSlots)
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

API::APIReturn AdminPortal_Endpoints_AccountCredentials::removeAccountCredentialSlot(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    // Extract and validate input
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");
    uint32_t slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);

    if (accountName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return response;
    }

    if (slotId == 0)
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Slot ID is required");
        return response;
    }

    if (slotId == 1)
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Can´t remove the credential slot 1 (Master Password)");
        return response;
    }

    // Delete the credential slot for the account
    if (!Globals::getIdentityManager()->authController->removeAccountCredential(authClientDetails, request.jwtToken->getSubject(), accountName, slotId))
    {
        response.setError(HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to delete the credential slot");
        return response;
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_AccountCredentials::setCredentialLockedStatus(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    // Extract and validate input
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");
    uint32_t slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);
    bool lockedStatus = JSON_ASBOOL(*request.inputJSON, "lockedStatus", false);

    if (accountName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return response;
    }

    if (slotId == 0)
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Slot ID is required");
        return response;
    }

    // Block the credential slot for the account
    if (!Globals::getIdentityManager()->authController->setCredentialLockedStatus(authClientDetails, request.jwtToken->getSubject(), accountName, slotId, lockedStatus))
    {
        response.setError(HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to set the lock state on the credential slot");
        return response;
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_AccountCredentials::setMustChangeCredential(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    // Extract and validate input
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");
    uint32_t slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);
    bool mustChange = JSON_ASBOOL(*request.inputJSON, "mustChange", true);

    if (accountName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return response;
    }

    if (slotId == 0)
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Slot ID is required");
        return response;
    }

    // Force credential expiration for the account slot
    if (!Globals::getIdentityManager()->authController->setCredentialMustChange(authClientDetails, request.jwtToken->getSubject(), accountName, slotId, mustChange))
    {
        response.setError(HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to change credential flag to change");
        return response;
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_AccountCredentials::generateMasterPassword(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    // Extract and validate input
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (accountName.empty())
    {
        response.setError(HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return response;
    }

    // Generate a new master password for the account
    std::string newTempPassword;
    bool ok = Globals::getIdentityManager()->authController->recoverAccountMasterCredential(authClientDetails, request.jwtToken->getSubject(), accountName, &newTempPassword);

    if (!ok)
    {
        response.setError(HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to generate new master password");
        return response;
    }

    (*response.responseJSON())["password"] = newTempPassword;
    return response;
}
