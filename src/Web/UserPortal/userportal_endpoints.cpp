#include "userportal_endpoints.h"
#include "IdentityManager/ds_authentication.h"
#include "globals.h"

#include "json/value.h"
#include <ctime>
#include <inttypes.h>

using namespace Mantids30;
using namespace Mantids30::Program;
using namespace Mantids30::API::RESTful;
using namespace Mantids30::Network::Protocols;
using namespace Mantids30::DataFormat;

void UserPortal_Endpoints::addEndpoints(std::shared_ptr<Endpoints> endpoints)
{
    using SecurityOptions = Mantids30::API::RESTful::Endpoints::SecurityOptions;

    // TODO: assign permissions.
    // TODO: log password change/delete
    endpoints->addEndpoint(Endpoints::GET, "getLastLogin", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &getLastLogin);
    endpoints->addEndpoint(Endpoints::GET, "getDashboardData", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &getDashboardData);
    endpoints->addEndpoint(Endpoints::GET, "searchAccountSessions", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &searchAccountSessions);
    endpoints->addEndpoint(Endpoints::GET, "searchAccountCredentialsActivity", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &searchAccountCredentialsActivity);
    endpoints->addEndpoint(Endpoints::GET, "getAccountDetailFieldsValues", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &getAccountDetailFieldsValues);
    endpoints->addEndpoint(Endpoints::PUT, "updateAccountDetailFieldsValues", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &updateAccountDetailFieldsValues);
    endpoints->addEndpoint(Endpoints::GET, "listAccountApplicationsFullInfo", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &listAccountApplicationsFullInfo);
    endpoints->addEndpoint(Endpoints::GET, "listAllAuthCredentialSlotsPublicData", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &listAllAuthCredentialSlotsPublicData);
    endpoints->addEndpoint(Endpoints::POST, "activateCredential", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &activateCredential);
    endpoints->addEndpoint(Endpoints::POST, "activateOTPCredential", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &activateOTP);
    endpoints->addEndpoint(Endpoints::DELETE, "removeCredential", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &removeCredential);
    endpoints->addEndpoint(Endpoints::POST, "createChallengeToken", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &createChallengeToken);
    endpoints->addEndpoint(Endpoints::POST, "changeCredential", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &changeCredential);
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::changeCredential(void *context, const RequestParameters &request, ClientDetails &clientDetails)
{
    API::APIReturn response;
    std::string challengeTokenSignedStr = request.clientRequest->getCookie("ChallengeToken");
    JWT::Token challengeToken;
    bool tokenVerified = request.jwtValidator->verify(challengeTokenSignedStr, &challengeToken);
    bool appMatches = challengeToken.getClaim("app") == request.jwtToken->getClaim("app");
    bool typeIsChallenge = challengeToken.getClaim("type") == "challenge";

    if (!tokenVerified || !appMatches || !typeIsChallenge)
    {
        if (!tokenVerified)
        {
            response.setError(HTTP::Status::S_401_UNAUTHORIZED, "auth_failed", "Invalid Challenge Token: Verification failed");
        }
        else if (!appMatches)
        {
            response.setError(HTTP::Status::S_401_UNAUTHORIZED, "auth_failed", "Invalid Challenge Token: App mismatch");
        }
        else if (!typeIsChallenge)
        {
            response.setError(HTTP::Status::S_401_UNAUTHORIZED, "auth_failed", "Invalid Challenge Token: Type is not 'challenge'");
        }
        return response;
    }

    if (JSON_ASSTRING(challengeToken.getClaim("details"),"operation", "") != "changeCredential")
    {
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "auth_failed", "Invalid Operation for Challenge Token");
        return response;
    }

    std::string accountName = challengeToken.getSubject();
    uint32_t slotId = JSON_ASUINT_D(challengeToken.getClaim("slotId"),0);

    Credential cred;
    cred.fromJSON((*request.inputJSON)["credential"]);
    cred.expirationTimestamp = 1; // Default expiration timestamp.

    if (!Globals::getIdentityManager()->authController->changeAccountCredential(clientDetails,accountName, accountName, cred, slotId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "change_credential_failed", "Failed to change credential");
    }

    return response;
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::createChallengeToken(void *context, const RequestParameters &request, ClientDetails &clientDetails)
{
    API::APIReturn response;

    std::string accountName = request.jwtToken->getSubject();

    // Parse input parameters
    if (!request.inputJSON->isMember("slotId") || !request.inputJSON->isMember("verification") ||  !request.inputJSON->isMember("details"))
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "missing_fields", "slotId + verification + details are required");
        return response;
    }

    uint32_t slotId = JSON_ASUINT((*request.inputJSON), "slotId", 0);
    std::string verification = JSON_ASSTRING((*request.inputJSON), "verification", "");
    AuthenticationResult authResult = Globals::getIdentityManager()->authController->authenticateCredential(clientDetails, accountName, verification, slotId);


    // Log the authentication result
    LOG_APP->log2(__func__, accountName, clientDetails.ipAddress,
                  authResult != AuthenticationResult::AUTHENTICATED ? Logs::LEVEL_SECURITY_ALERT : Logs::LEVEL_INFO,
                  "Account Authorization Result: %" PRIu16 " - %s, for application '%s', and slotId = '%" PRIu32 "'",
                  (uint16_t)authResult,
                  authResultToString(authResult),
                  request.jwtToken->getClaim("app").asString().c_str(),
                  slotId);

    if (!IS_AUTH_SUCCESSFUL(authResult))
    {
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "auth_failed", authResultToString(authResult));
        return response;
    }

    JWT::Token token;
    token.setExpirationTime(time(nullptr)+120); // 2 min token.
    token.setSubject(request.jwtToken->getSubject());
    token.addClaim("type","challenge");
    token.addClaim("app",request.jwtToken->getClaim("app"));
    token.addClaim("parentTokenId", request.jwtToken->getJwtId());
    token.addClaim("slotId", slotId);
    token.addClaim("details", (*request.inputJSON)["details"]);

    HTTP::Headers::Cookie cookie = HTTP::Headers::Cookie();
    cookie.value = request.jwtSigner->signFromToken(token,false);
    cookie.expires = HTTP::Date(token.getExpirationTime());

    response.cookiesMap["ChallengeToken"] = cookie;
    return response;
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::listAllAuthCredentialSlotsPublicData(void *context, const RequestParameters &request, ClientDetails &clientDetails)
{
    Json::Value result(Json::arrayValue);
    std::string accountName = request.jwtToken->getSubject();
    std::map<uint32_t,std::pair<bool,Credential>> creds = Globals::getIdentityManager()->authController->listAllAuthCredentialSlotsPublicDataForAccount(accountName);
    const AuthenticationPolicy &authPolicy = Globals::getIdentityManager()->authController->getAuthenticationPolicy();

    for (const auto &credEntry : creds)
    {
        Json::Value entry;
        entry["slotId"] = credEntry.first;
        entry["isActive"] = credEntry.second.first;
        entry["credential"] = credEntry.second.second.toJSON(authPolicy);
        result.append(entry);
    }

    return result;
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::listAccountApplicationsFullInfo(void *context, const RequestParameters &request, ClientDetails &clientDetails)
{
    Json::Value result(Json::arrayValue);
    std::string accountName = request.jwtToken->getSubject();

    for (const auto &appInfo : Globals::getIdentityManager()->applications->listAccountApplicationsFullInfo(accountName))
    {
        result.append(appInfo.toJSON());
    }

    return result;
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::updateAccountDetailFieldsValues(void *context, const RequestParameters &request, ClientDetails &clientDetails)
{
    API::APIReturn response;

    std::string accountName = request.jwtToken->getSubject();

    // Get the list of field values from input
    Json::Value fieldValuesArray = (*request.inputJSON)["fieldValues"];
    if (!fieldValuesArray.isArray())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Field values must be an array");
        return response;
    }

    std::list<AccountDetailFieldValue> fieldValues;

    // Process each field value in the array
    for (Json::ArrayIndex i = 0; i < fieldValuesArray.size(); ++i)
    {
        AccountDetailFieldValue fieldValue;
        fieldValue.fromJSON(fieldValuesArray[i]);
        fieldValues.push_back(fieldValue);
    }

    // Update account detail fields values
    if (!Globals::getIdentityManager()->accounts->updateAccountDetailFieldValues(clientDetails,accountName,accountName, fieldValues, false))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update account detail fields values");
        return response;
    }
    // Return 200.

    return response;
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::getAccountDetailFieldsValues(void *context, const RequestParameters &request, ClientDetails &clientDetails)
{
    API::APIReturn response;

    std::string accountName = request.jwtToken->getSubject();

    std::map<std::string, AccountDetailFieldValue> fieldValues = Globals::getIdentityManager()->accounts->getAccountDetailFieldValues(accountName);

    Json::Value result(Json::arrayValue);
    for (const auto &fieldValue : fieldValues)
    {
        result.append(fieldValue.second.toJSON());
    }

    return result;
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::searchAccountCredentialsActivity(void *context, const RequestParameters &request, ClientDetails &clientDetails)
{
    std::string accountName = request.jwtToken->getSubject();
    return Globals::getIdentityManager()->authController->searchAccountCredentialsActivity(accountName, *request.inputJSON);
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::searchAccountSessions(void *context, const RequestParameters &request, ClientDetails &clientDetails)
{
    std::string accountName = request.jwtToken->getSubject();
    return Globals::getIdentityManager()->authController->searchAccountSessions(accountName, *request.inputJSON);
}

json getLastLoginJSON(const RequestParameters &request)
{
    Json::Value result;

    std::string accountName = request.jwtToken->getSubject();
    std::optional<std::pair<time_t, std::string>> lastLoginOpt = Globals::getIdentityManager()->authController->getAccountLastAccess(accountName);

    if (lastLoginOpt)
    {
        result["timestamp"] = (Json::Int64)(lastLoginOpt.value().first);
        result["appName"] = (lastLoginOpt.value().second);
    }
    else
    {
        result["timestamp"] = Json::Value::null;
    }

    return result;
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::getDashboardData(void *context, const RequestParameters &request, ClientDetails &clientDetails)
{
    Json::Value result;

    result["lastLogin"] = getLastLoginJSON(request);

    std::string accountName = request.jwtToken->getSubject();
    uint32_t activeSessionsCount = Globals::getIdentityManager()->authController->getAccountActiveSessionsCount(accountName);
    std::pair<uint32_t, uint32_t> activePasswordSlots = Globals::getIdentityManager()->authController->getAccountActiveCredentialsCount(accountName);

    result["activeSessionsCount"] = activeSessionsCount;
    result["activePasswordSlots"] = Json::Value(Json::objectValue);
    result["activePasswordSlots"]["used"] = activePasswordSlots.second;
    result["activePasswordSlots"]["total"] = activePasswordSlots.first;

    std::set<std::string> applications = Globals::getIdentityManager()->applications->listAccountApplications(accountName);

    result["applicationsCount"] = applications.size();

    return result;
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::getLastLogin(void *context, const RequestParameters &request, ClientDetails &clientDetails)
{
    return getLastLoginJSON(request);
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::activateCredential(void *context, const RequestParameters &request, ClientDetails &clientDetails)
{
    API::APIReturn response;

    std::string accountName = request.jwtToken->getSubject();

    // Parse input parameters
    if (!request.inputJSON->isMember("slotId") || !request.inputJSON->isMember("hash") || !request.inputJSON->isMember("ssalt"))
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "missing_fields", "slotId, hash, and ssalt are required");
        return response;
    }

    uint32_t slotId =  JSON_ASUINT((*request.inputJSON),"slotId",0);
    std::string hash = JSON_ASSTRING((*request.inputJSON),"hash","");
    std::string ssalt = JSON_ASSTRING((*request.inputJSON),"ssalt","");

    // Check if credential already exists using the new function
    if (Globals::getIdentityManager()->authController->doesCredentialSlotExistOnAccount(accountName, slotId))
    {
        response.setError(HTTP::Status::S_409_CONFLICT, "activation_failed", "Credential is already activated");
        return response;
    }

    if (!Globals::getIdentityManager()->authController->activateAccountCredential(clientDetails,accountName,accountName, slotId, hash, ssalt))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "activation_failed", "Failed to activate credential");
        return response;
    }

    return response;
}


UserPortal_Endpoints::APIReturn UserPortal_Endpoints::activateOTP(void *context, const RequestParameters &request, ClientDetails &clientDetails)
{
    API::APIReturn response;

    std::string accountName = request.jwtToken->getSubject();

    if (!request.inputJSON->isMember("slotId") || !request.inputJSON->isMember("seed"))
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "missing_fields", "slotId and seed are required");
        return response;
    }

    uint32_t slotId =  JSON_ASUINT((*request.inputJSON),"slotId",0);
    std::string seed = JSON_ASSTRING((*request.inputJSON),"seed","");

    if (Globals::getIdentityManager()->authController->doesCredentialSlotExistOnAccount(accountName, slotId))
    {
        response.setError(HTTP::Status::S_409_CONFLICT, "activation_failed", "OTP credential is already activated");
        return response;
    }

    if (!Globals::getIdentityManager()->authController->activateAccountCredential(clientDetails,accountName,accountName, slotId, seed, ""))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "activation_failed", "Failed to activate OTP credential");
        return response;
    }

    return response;
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::removeCredential(void *context, const RequestParameters &request, ClientDetails &clientDetails)
{
    API::APIReturn response;

    std::string accountName = request.jwtToken->getSubject();

    // Parse input parameters
    if (!request.inputJSON->isMember("slotId") || !request.inputJSON->isMember("verification")) {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "missing_fields", "slotId and verification is required");
        return response;
    }

    uint32_t slotId = JSON_ASUINT((*request.inputJSON), "slotId", 0);
    std::string verification = JSON_ASSTRING((*request.inputJSON), "verification", "");

    auto authResult = Globals::getIdentityManager()->authController->authenticateCredential(clientDetails,accountName, verification,slotId);

    // Log the authentication result
    LOG_APP->log2(__func__, accountName, clientDetails.ipAddress,
                  authResult != AuthenticationResult::AUTHENTICATED ? Logs::LEVEL_SECURITY_ALERT : Logs::LEVEL_INFO,
                  "Account Authorization Result: %" PRIu16 " - %s, for application '%s', and slotId = '%" PRIu32 "'",
                  (uint16_t)authResult,
                  authResultToString(authResult),
                  request.jwtToken->getClaim("app").asString().c_str(),
                  slotId);

    if (!IS_AUTH_SUCCESSFUL(authResult))
    {
        response.setError(HTTP::Status::S_401_UNAUTHORIZED, "deletion_failed", authResultToString(authResult));
        return response;
    }

    if (!Globals::getIdentityManager()->authController->removeAccountCredential(clientDetails,accountName,accountName, slotId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "deletion_failed", "Failed to delete credential");
        return response;
    }

    return response;
}

