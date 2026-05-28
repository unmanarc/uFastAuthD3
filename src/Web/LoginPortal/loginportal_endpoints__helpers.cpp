#include "IdentityManager/ds_authentication.h"
#include "Mantids30/Protocol_HTTP/api_return.h"
#include "Tokens/tokensmanager.h"
#include "loginportal_endpoints.h"
#include "json/value.h"
#include <Mantids30/Helpers/json.h>

#include "globals.h"

#include <cstdint>
#include <json/config.h>
#include <memory>
#include <optional>
#include <string>

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols;
using namespace Mantids30::DataFormat;

std::vector<AuthenticationSchemeUsedSlot> LoginPortal_Endpoints::calculateRequiredAuthSlotsLeftForTheNewTransientAuthToken(std::shared_ptr<TransientAuthenticationContext> authContext, API::APIReturn *response)
{
    std::vector<AuthenticationSchemeUsedSlot> requiredAuthSlotsOnScheme;

    // Get the identity manager from global settings to handle authentication.
    IdentityManager *identityManager = Globals::getIdentityManager();

    requiredAuthSlotsOnScheme = identityManager->authController->listAuthenticationSlotsUsedByScheme(authContext->schemeId);
    std::set<uint32_t> usedAuthSlotsOnAccount = identityManager->authController->listUsedAuthenticationSlotsOnAccount(authContext->accountName);

    // Remove unused requiredAuthSlots if they are optional (eg. requiredAuthSlots[0].optional) and don't exist in usedAuthSlotsOnAccount
    std::vector<AuthenticationSchemeUsedSlot> filteredAuthSlots;
    for (const auto &slot : requiredAuthSlotsOnScheme)
    {
        // Skip slots that are optional and not used by the account
        if (!slot.optional || usedAuthSlotsOnAccount.find(slot.slotId) != usedAuthSlotsOnAccount.end())
        {
            // Skip slots that are already authenticated (present in authContext->authSlots)
            if (authContext->authenticatedSlots.find(slot.slotId) == authContext->authenticatedSlots.end())
            {
                filteredAuthSlots.push_back(slot);
            }
        }
    }

    return filteredAuthSlots;
}
/*
bool LoginPortal_Endpoints::validateAndMerge_AccessTokenIfExist(const RequestParameters &request, LoginPortal_Endpoints::APIReturn &response, std::shared_ptr<TransientAuthenticationContext> authContext)
{
    JWT::Token accessToken;
    std::string cookieAccessTokenStr = request.clientRequest->getCookie("AccessToken");

    if (!cookieAccessTokenStr.empty())
    {
        if (!request.jwtValidator->verify(cookieAccessTokenStr, &accessToken))
        {
            // Failed to load the intermediary...
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                              authResultToString(AuthenticationResult::UNAUTHENTICATED));
            return false;
        }
        if (accessToken.getClaim("app") != IAM_LOGINPORTAL_APPNAME || accessToken.getClaim("type") != "access")
        {
            // This Token is not for this cookie...
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                              authResultToString(AuthenticationResult::UNAUTHENTICATED));
            return false;
        }
        if (accessToken.getSubject() != authContext->accountName)
        {
            // This Token is not for this cookie... (other username... logout first please!)
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                              authResultToString(AuthenticationResult::UNAUTHENTICATED));
            return false;
        }

        // We have an access token!
        std::set<uint32_t> authenticatedSlotsOnAccessToken = Mantids30::Helpers::jsonToUInt32Set(accessToken.getClaim("slotIds"));
        // Merge.
        for (const auto &i : authenticatedSlotsOnAccessToken)
        {
            authContext->authenticatedSlots.insert(i);
        }
    }

    return true;
}*/

void LoginPortal_Endpoints::issueTransientAuthTokenResponse(const RequestParameters &request, Mantids30::API::APIReturn &response, IdentityManager *identityManager,
                                                            std::shared_ptr<TransientAuthenticationContext> authContext, const std::vector<AuthenticationSchemeUsedSlot> &requiredAuthSlots,
                                                            bool mustChange)
{
    // Retrieve configuration parameters from global settings.
    auto config = Globals::pConfig;
    uint32_t loginAuthenticationTimeout = config.get<uint32_t>("LoginPortal.AuthenticationTimeout", 300);
    Json::Value *jResponse = response.responseJSON();

    // There is a new authenticated current slot:
    if (authContext->currentSlotId.has_value())
        authContext->authenticatedSlots.insert(authContext->currentSlotId.value());

    // This current slot must be changed immediatly:
    if (mustChange)
        authContext->mustChangeSlots.insert(authContext->currentSlotId.value());

    std::optional<uint32_t> nextSlotId = std::nullopt;
    if (!requiredAuthSlots.empty())
    {
        nextSlotId = requiredAuthSlots.begin()->slotId;
    }

    (*jResponse)["changeCredential"] = mustChange;
    (*jResponse)["transientToken"] = authContext->issueSignedTransientTokenFromValues(loginAuthenticationTimeout, nextSlotId, request.jwtSigner);

    if (requiredAuthSlots.empty())
    {
        if (authContext->mustChangeSlots.empty())
        {
            // Set the IAM Access Token into the Cookie ONLY if mustchangeslots is empty (to avoid login if not changed)...
            TokensManager::issueAccessTokenCookie(response, request, authContext);
        }
        (*jResponse)["nextSlot"] = Json::nullValue; // No new slots to be tested.
    }
    else
    {
        // We can give the credential public data for the next credential:
        Credential credentialPublicData = identityManager->authController->getAccountCredentialPublicData(authContext->accountName, nextSlotId.value());

        json nextSlot;
        nextSlot["slotId"] = nextSlotId.value();
        nextSlot["details"] = credentialPublicData.slotDetails.toJSON();

        (*jResponse)["nextSlot"] = nextSlot;
        (*jResponse)["publicData"] = credentialPublicData.toJSON(identityManager->authController->getAuthenticationPolicy());
        (*jResponse)["publicData"].removeMember("slotDetails");
    }
}

void LoginPortal_Endpoints::prepareLogoutResponse(void *, const RequestParameters &request, ClientDetails &, APIReturn *response)
{
    if (request.clientRequest->headers.getOptionValueStringByName("X-Logout") != "1")
    {
        return;
    }

    response->cookiesMap["AccessToken"] = HTTP::Headers::Cookie();
    response->cookiesMap["AccessToken"].deleteCookie();

    response->cookiesMap["loggedIn"] = HTTP::Headers::Cookie();
    response->cookiesMap["loggedIn"].deleteCookie();
    response->cookiesMap["loggedIn"].path = "/";
}
