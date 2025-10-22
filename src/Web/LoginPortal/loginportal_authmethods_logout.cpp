#include "loginportal_add_endpoints.h"
#include <Mantids30/Helpers/json.h>

using namespace Mantids30;
using namespace API::RESTful;
using namespace Network::Protocols;

// Get the application token...

API::APIReturn LoginPortal_AuthMethods::logout(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    doLogoutInResponse(context,request,authClientDetails,&response);
    return response;
}

void LoginPortal_AuthMethods::doLogoutInResponse(void *, const RequestParameters &request, ClientDetails &, APIReturn * response)
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
