#include "Mantids30/Protocol_HTTP/api_return.h"
#include "loginportal_add_endpoints.h"

#include "globals.h"


using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols;

LoginPortal_AuthMethods::APIReturn LoginPortal_AuthMethods::getSessionInfo(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    json r;
    r["user"] = request.jwtToken->getSubject();
    r["clientData"] = authClientDetails.toJSON();
    return r;
}

API::APIReturn LoginPortal_AuthMethods::accountCredentialPublicData(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    IdentityManager *identityManager = Globals::getIdentityManager();
    auto accountName = request.jwtToken->getSubject();
    auto slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);

    if (identityManager->applications->validateApplicationAccount(JSON_ASSTRING_D(request.jwtToken->getClaim("app"), ""), accountName))
    {
        auto v = identityManager->authController->getAccountCredentialPublicData(accountName, slotId);
        (*response.responseJSON()) = v.toJSON(identityManager->authController->getAuthenticationPolicy());
    }
    return response;
}

API::APIReturn LoginPortal_AuthMethods::listCredentials(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    IdentityManager *identityManager = Globals::getIdentityManager();

    // JWT INPUTS:
    std::string jwtAccountName = request.jwtToken->getSubject();
    std::string app = JSON_ASSTRING_D(request.jwtToken->getClaim("app"), "");
    std::map<uint32_t, Credential> r;

    if (identityManager->applications->validateApplicationAccount(app, jwtAccountName))
    {
        // PROCESS DATA:
        r = identityManager->authController->getAccountAllCredentialsPublicData(jwtAccountName);
        for (const auto &publicData : r)
        {
            (*response.responseJSON())[std::to_string(publicData.first)] = publicData.second.toJSON(identityManager->authController->getAuthenticationPolicy());
        }
    }

    if (r.empty())
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "no_credentials", "No detected credentials for this user.");

    return response;
}

API::APIReturn LoginPortal_AuthMethods::changeCredential(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    // INPUTS:
    uint32_t slotId = JSON_ASUINT(*request.inputJSON, "slotId", 0);
    Credential newCredential = Credential::createFromJSON((*request.inputJSON)["newCredential"]);

    // Get the identity manager from global settings to handle authentication.
    IdentityManager *identityManager = Globals::getIdentityManager();

    std::shared_ptr<AppAuthExtras> authContext = std::make_shared<AppAuthExtras>();
    JWT::Token oldIntermediateAuthToken;
    std::string accountName;

    // Decode the bearer intermediate token... (and get the Account Name)
    if (!authContext->validateAndDecodeBearerAccessTokenProperties(request.clientRequest->getAuthorizationBearer(), request.inputJSON, &oldIntermediateAuthToken, request.jwtValidator, &accountName))
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
        // Excellent! give the new intermediate token again..

        std::vector<AuthenticationSchemeUsedSlot> requiredAuthSlots;
        JWT::Token accessToken;
        if (!decodeAndValidateAccessTokenIfExist(request, response, &accessToken, accountName, authContext))
        {
            // Invalid Access Token. (Relogin)
            return response;
        }
        if (!calculateRequiredAuthSlotsLeftForTheNewIntermediateAuthToken(authContext, accountName, &response, &requiredAuthSlots, accessToken))
        {
            return response;
        }

        // It's already authenticated and in must change list (checked before).
        authContext->currentSlotId = slotId;

        setupNewIntermediateAuthToken(request, response, identityManager, authContext, requiredAuthSlots, oldIntermediateAuthToken.getExpirationTime(), accountName, false);
    }

    return response;
}
