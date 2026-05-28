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


bool LoginPortal_Endpoints::calculateRequiredAuthSlotsLeftForTheNewTransientAuthToken(std::shared_ptr<TransientAuthenticationContext> authContext,
    std::string accountName,
    API::APIReturn *response,
    std::vector<AuthenticationSchemeUsedSlot> *requiredAuthSlotsOnScheme,
    const JWT::Token & accessToken
    )
{
    // Get the identity manager from global settings to handle authentication.
    IdentityManager *identityManager = Globals::getIdentityManager();

    *requiredAuthSlotsOnScheme = identityManager->authController->listAuthenticationSlotsUsedByScheme(authContext->schemeId);
    std::set<uint32_t> usedAuthSlotsOnAccount = identityManager->authController->listUsedAuthenticationSlotsOnAccount(accountName);

    // Remove unused requiredAuthSlots if they are optional (eg. requiredAuthSlots[0].optional) and don't exist in usedAuthSlotsOnAccount
    std::vector<AuthenticationSchemeUsedSlot> filteredAuthSlots;
    for (const auto &slot : *requiredAuthSlotsOnScheme)
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

    *requiredAuthSlotsOnScheme = filteredAuthSlots;


    return true;
}

bool LoginPortal_Endpoints::decodeAndValidateAccessTokenIfExist(const RequestParameters &request, LoginPortal_Endpoints::APIReturn &response, JWT::Token *token, const std::string &currentAccountName,std::shared_ptr<TransientAuthenticationContext> authContext)
{
    std::string cookieAccessTokenStr = request.clientRequest->getCookie("AccessToken");

    if (!cookieAccessTokenStr.empty())
    {
        if (!request.jwtValidator->verify(cookieAccessTokenStr, token))
        {
            // Failed to load the intermediary...
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                              authResultToString(AuthenticationResult::UNAUTHENTICATED));
            return false;
        }
        if (token->getClaim("app") != IAM_LOGINPORTAL_APPNAME || token->getClaim("type") != "access")
        {
            // This Token is not for this cookie...
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                              authResultToString(AuthenticationResult::UNAUTHENTICATED));
            return false;
        }
        if (token->getSubject() != currentAccountName)
        {
            // This Token is not for this cookie... (other username... logout first please!)
            response.setError(HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                              authResultToString(AuthenticationResult::UNAUTHENTICATED));
            return false;
        }

        // We have an access token!
        std::set<uint32_t> authenticatedSlotsOnAccessToken = Mantids30::Helpers::jsonToUInt32Set( token->getClaim("slotIds") );
        // Merge.
        for (const auto & i  : authenticatedSlotsOnAccessToken)
        {
            authContext->authenticatedSlots.insert(i);
        }
    }

    return true;
}


void LoginPortal_Endpoints::setupNewTransientAuthToken(const RequestParameters &request, Mantids30::API::APIReturn &response, IdentityManager *identityManager, std::shared_ptr<TransientAuthenticationContext> authContext,
                                                       const std::vector<AuthenticationSchemeUsedSlot> &requiredAuthSlots, const time_t &oldTransientTokenExpirationTime, const std::string &accountName,
                                                       bool mustChange)
{
    // Retrieve configuration parameters from global settings.
    auto config = Globals::pConfig;
    uint32_t loginAuthenticationTimeout = config.get<uint32_t>("LoginPortal.AuthenticationTimeout", 300);
    JWT::Token newTransientAuthToken;
    Json::Value * jResponse = response.responseJSON();

    if (authContext->firstAuth)
    {
        newTransientAuthToken.setJwtId(Mantids30::Helpers::Random::createRandomString(16));
        newTransientAuthToken.setExpirationTime(time(nullptr) + loginAuthenticationTimeout);
    }
    else
    {
        newTransientAuthToken.setExpirationTime(oldTransientTokenExpirationTime);
    }

    newTransientAuthToken.setIssuedAt(time(nullptr));
    newTransientAuthToken.setNotBefore(time(nullptr) - 30);
    newTransientAuthToken.addClaim("app", authContext->appName);
    newTransientAuthToken.addClaim("preAuthUser", accountName);
    newTransientAuthToken.addClaim("slotSchemeHash", authContext->slotSchemeHash);
    newTransientAuthToken.addClaim("schemeId", authContext->schemeId);
    newTransientAuthToken.addClaim("keepAuthenticated", authContext->keepAuthenticated);
    newTransientAuthToken.addClaim("type", "transient");

    std::set<uint32_t> authSlots = authContext->authenticatedSlots;
    if (authContext->currentSlotId.has_value())
        authSlots.insert(authContext->currentSlotId.value());
    newTransientAuthToken.addClaim("authenticatedSlots", Mantids30::Helpers::setToJSON(authSlots));

    std::set<uint32_t> currentMustChangeSlots = authContext->mustChangeSlots;
    if (mustChange)
        currentMustChangeSlots.insert(authContext->currentSlotId.value());
    else
        currentMustChangeSlots.erase(authContext->currentSlotId.value());

    newTransientAuthToken.addClaim("mustChangeSlots", Mantids30::Helpers::setToJSON(currentMustChangeSlots));

    (*jResponse)["changeCredential"] = mustChange;

    if (requiredAuthSlots.empty())
    {
        if (currentMustChangeSlots.empty())
        {
            // Set the IAM Access Token into the Cookie ONLY if mustchangeslots is empty...
            TokensManager::setIAMAccessTokenCookie(response, request, newTransientAuthToken,
                                                   authContext->keepAuthenticated,              // Keep authenticated will use the current authentication proccess
                                                   newTransientAuthToken.getExpirationTime() // Get current JWT expiration time (if keep autneticated is false)
                                                   );
        }

        // DONE!
        (*jResponse)["nextSlot"] = Json::nullValue;
        (*jResponse)["transientToken"] = request.jwtSigner->signFromToken(newTransientAuthToken, false);
    }
    else
    {
        auto nextSlotId = requiredAuthSlots.begin()->slotId;
        newTransientAuthToken.addClaim("currentSlotId", nextSlotId); // Enforce this with authentication.

        // We can give the credential public data for the next credential:
        Credential credentialPublicData = identityManager->authController->getAccountCredentialPublicData(accountName, nextSlotId);

        json nextSlot;
        nextSlot["slotId"] = nextSlotId;
        nextSlot["details"] = credentialPublicData.slotDetails.toJSON();
        (*jResponse)["nextSlot"] = nextSlot;
        (*jResponse)["publicData"] = credentialPublicData.toJSON(identityManager->authController->getAuthenticationPolicy());
        (*jResponse)["publicData"].removeMember("slotDetails");
        (*jResponse)["transientToken"] = request.jwtSigner->signFromToken(newTransientAuthToken, false);
    }
}


void LoginPortal_Endpoints::prepareLogoutResponse(void *, const RequestParameters &request, ClientDetails &, APIReturn * response)
{
    if ( request.clientRequest->headers.getOptionValueStringByName("X-Logout") != "1" )
    {
        return;
    }

    response->cookiesMap["AccessToken"] = HTTP::Headers::Cookie();
    response->cookiesMap["AccessToken"].deleteCookie();

    response->cookiesMap["loggedIn"] = HTTP::Headers::Cookie();
    response->cookiesMap["loggedIn"].deleteCookie();
    response->cookiesMap["loggedIn"].path = "/";
}

