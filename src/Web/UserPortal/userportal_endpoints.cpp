#include "userportal_endpoints.h"
#include "globals.h"

#include <ctime>

using namespace Mantids30;
using namespace Mantids30::Program;
using namespace Mantids30::API::RESTful;
using namespace Mantids30::Network::Protocols;
using namespace Mantids30::DataFormat;

void UserPortal_Endpoints::addEndpoints(std::shared_ptr<Endpoints> endpoints)
{
    using SecurityOptions = Mantids30::API::RESTful::Endpoints::SecurityOptions;

    endpoints->addEndpoint(Endpoints::GET, "getLastLogin", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &getLastLogin);
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::getLastLogin(void *context, const RequestParameters &request, ClientDetails &clientDetails)
{
    std::string accountName = request.jwtToken->getSubject();
    std::optional<time_t> lastLoginOpt = Globals::getIdentityManager()->authController->getAccountLastAccess(accountName);

    Json::Value result;

    if (lastLoginOpt)
    {
        time_t lastLogin = lastLoginOpt.value();
        result["lastLogin"] = (Json::Int64) lastLogin;
    }
    else
    {
        result["lastLogin"] = Json::Value::null;
    }

    return result;
}
