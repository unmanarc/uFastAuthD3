#include "loginportal_endpoints.h"
#include <Mantids30/Helpers/json.h>

using namespace Mantids30;
using namespace API::RESTful;
using namespace Network::Protocols;

// Get the application token...

API::APIReturn LoginPortal_Endpoints::logout(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    prepareLogoutResponse(context,request,authClientDetails,&response);
    return response;
}

