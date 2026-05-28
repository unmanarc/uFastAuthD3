#include "Mantids30/Protocol_HTTP/api_return.h"
#include "loginportal_endpoints.h"

#include "globals.h"

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols;

API::APIReturn LoginPortal_Endpoints::changeCredential(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    // INPUTS:
    uint32_t slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);
    Credential newCredential = Credential::createFromJSON((*request.inputJSON)["newCredential"]);

    // Get the identity manager from global settings to handle authentication.
    IdentityManager *identityManager = Globals::getIdentityManager();

    std::shared_ptr<TransientAuthenticationContext> authContext = std::make_shared<TransientAuthenticationContext>();
    JWT::Token transientAuthToken;
    std::string accountName;
    std::string transientAuthTokenStr = request.clientRequest->getAuthorizationBearer();

    // Decode the bearer transient token... (and get the Account Name)
    if (!authContext->validateAndDecodeTransientAuthToken(transientAuthTokenStr, request.inputJSON, &transientAuthToken, request.jwtValidator, &accountName))
    {
        response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                          authResultToString(AuthenticationResult::UNAUTHENTICATED));
        return response;
    }

    // check if the slot id belongs to the change list.
    if (authContext->mustChangeSlots.find(slotId) == authContext->mustChangeSlots.end() || authContext->authenticatedSlots.find(slotId) == authContext->authenticatedSlots.end())
    {
        // TODO: log, trying to change an unauthorized slot credential!!!
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::AUTHENTICATION_FAILED)),
                          authResultToString(AuthenticationResult::AUTHENTICATION_FAILED));
        return response;
    }

    if (!identityManager->authController->changeAccountCredential(authClientDetails, accountName, accountName, newCredential, slotId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error: Failed to change the credential.");
    }
    else
    {
        // Excellent! give the new transient token again..

        std::vector<AuthenticationSchemeUsedSlot> requiredAuthSlots;
        JWT::Token accessToken;
        if (!decodeAndValidateAccessTokenIfExist(request, response, &accessToken, accountName, authContext))
        {
            // Invalid Access Token. (Relogin)
            return response;
        }
        if (!calculateRequiredAuthSlotsLeftForTheNewTransientAuthToken(authContext, accountName, &response, &requiredAuthSlots, accessToken))
        {
            return response;
        }

        // It's already authenticated and in must change list (checked before).
        authContext->currentSlotId = slotId;

        setupNewTransientAuthToken(request, response, identityManager, authContext, requiredAuthSlots, transientAuthToken.getExpirationTime(), accountName, false);
    }

    return response;
}
