#include "IdentityManager/ds_authentication.h"
#include "Mantids30/Protocol_HTTP/api_return.h"
#include "loginportal_endpoints.h"
#include <Mantids30/Helpers/json.h>

#include "globals.h"

#include <cstdint>
#include <json/config.h>
#include <memory>
#include <string>

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocol;
using namespace Mantids30::DataFormat;

std::vector<AuthenticationSchemeUsedSlot> LoginPortal_Endpoints::calculateRequiredAuthSlotsLeftForTheNewTransientAuthToken(std::shared_ptr<TransientAuthenticationContext> authContext,
                                                                                                                           API::APIReturn *response)
{
    std::vector<AuthenticationSchemeUsedSlot> requiredAuthSlotsOnScheme;

    // Get the identity manager from global settings to handle authentication.
    IdentityManager *identityManager = Globals::getIdentityManager();

    requiredAuthSlotsOnScheme = identityManager->authController->listAuthenticationSlotsUsedByScheme(authContext->schemeId);
    std::set<uint32_t> usedAuthSlotsOnAccount = identityManager->authController->listUsedAuthenticationSlotsOnAccount(authContext->accountName);

    // Remove unused requiredAuthSlots if they are optional (eg. requiredAuthSlots[0].optional) and don't exist in usedAuthSlotsOnAccount
    std::vector<AuthenticationSchemeUsedSlot> filteredAuthSlots;
    for (const AuthenticationSchemeUsedSlot &slot : requiredAuthSlotsOnScheme)
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

void LoginPortal_Endpoints::deleteLoginCookies(void *, const RequestParameters &request, ClientDetails &, APIReturn *response)
{
    if (request.clientRequest->headers.getOptionValueStringByName("X-Logout") != "1")
    {
        return;
    }

    response->cookiesMap["LPToken"] = HTTP::Headers::Cookie();
    response->cookiesMap["LPToken"].deleteCookie();

    response->cookiesMap["loggedIn"] = HTTP::Headers::Cookie();
    response->cookiesMap["loggedIn"].deleteCookie();
    response->cookiesMap["loggedIn"].path = "/";
}
