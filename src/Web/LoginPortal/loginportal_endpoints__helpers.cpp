#include "IdentityManager/ds_authentication.h"
#include <Mantids30/Protocol/HTTP/api_return.h>
#include "loginportal_endpoints.h"
#include <Mantids30/DataFormat/JSON/json.h>

#include "globals.h"

#include <cstdint>
#include <Mantids30/DataFormat/JSON/json.h>
#include <memory>
#include <string>

using namespace Mantids30;
using namespace Mantids30::Protocol::HTTP;
using namespace Mantids30::Runtime;
using namespace Mantids30::Server::WebRESTFul::RESTful;
using namespace Mantids30::Protocol;
using namespace Mantids30::DataFormat;

std::vector<AuthenticationSchemeUsedSlot> LoginPortal_Endpoints::calculateRequiredAuthSlotsLeftForTheNewTransientAuthToken(const std::shared_ptr<TransientAuthenticationContext> &authContext,
                                                                                                                           APIReturn *response)
{
    std::vector<AuthenticationSchemeUsedSlot> requiredAuthSlotsOnScheme;

    // Get the identity manager from global settings to handle authentication.
    IdentityManager *identityManager = Globals::getIdentityManager();

    requiredAuthSlotsOnScheme = identityManager->authController->listAuthenticationSlotsUsedByScheme(authContext->schemeId);
    std::set<uint32_t> usedAuthSlotsOnAccount = identityManager->authController->listUsedAuthenticationSlotsOnAccount(authContext->accountUUID);

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

void LoginPortal_Endpoints::deleteLoginCookies(void *, const RequestContext &request, ClientDetails &, APIReturn *response)
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
