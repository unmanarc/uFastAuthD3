#include "Mantids30/Protocol_HTTP/api_return.h"
#include "loginportal_endpoints.h"
//#include "Tokens/tokensmanager.h"

#include "globals.h"

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols;

API::APIReturn LoginPortal_Endpoints::changeCredential(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    // Get the identity manager from global settings to handle authentication.
    IdentityManager *identityManager = Globals::getIdentityManager();

    // INPUTS:
    uint32_t slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);
    Credential newCredential = Credential::createFromJSON((*request.inputJSON)["newCredential"]);

    // Set the expiration timestamp automatically on authController->changeAccountCredential
    newCredential.setExpirationTimeAutomatically();

    // LOCAL CONTEXT:
    std::shared_ptr<TransientAuthenticationContext> authContext = std::make_shared<TransientAuthenticationContext>();
    std::string transientAuthTokenStr = request.clientRequest->getAuthorizationBearer();
  //  Json::Value *jResponse = response.responseJSON();

    // Decode the bearer transient token... (and get the Account Name)
    if (!authContext->validateAndMerge_TransientAuthTokenIfExist(transientAuthTokenStr, request.inputJSON, request.jwtValidator))
    {
        response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                          authResultToString(AuthenticationResult::UNAUTHENTICATED));
        return response;
    }

    //if (authContext->mustChangeSlots.find(slotId) == authContext->mustChangeSlots.end() ||
    if (authContext->authenticatedSlots.find(slotId) == authContext->authenticatedSlots.end())
    {
        // TODO: log, trying to change an unauthorized slot credential!!!
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::AUTHENTICATION_FAILED)),
                          authResultToString(AuthenticationResult::AUTHENTICATION_FAILED));
        return response;
    }

    if (!identityManager->authController->changeAccountCredential(authClientDetails, authContext->accountName, authContext->accountName, newCredential, slotId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error: Failed to change the credential.");
    }

    return response;
}
