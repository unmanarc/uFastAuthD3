#include "weblogin_add_endpoints.h"
#include <Mantids30/Helpers/json.h>

using namespace Mantids30;
using namespace API::RESTful;
using namespace Network::Protocols;

// Get the application token...

API::APIReturn WebLogin_AuthMethods::logout(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    doLogoutInResponse(context,request,authClientDetails,&response);
    return response;
}

void WebLogin_AuthMethods::doLogoutInResponse(void *, const RequestParameters &request, ClientDetails &, APIReturn * response)
{
    if ( request.clientRequest->headers.getOptionValueStringByName("X-Logout") != "1" )
    {
        return;
    }

    response->cookiesMap["AccessToken"] = HTTP::Headers::Cookie();
    response->cookiesMap["AccessToken"].setAsTransientCookie();
    response->cookiesMap["AccessToken"].value = "";

    response->cookiesMap["loggedIn"] = HTTP::Headers::Cookie();
    response->cookiesMap["loggedIn"].setAsTransientCookie();
    response->cookiesMap["loggedIn"].path = "/";
    response->cookiesMap["loggedIn"].value = "";
}
