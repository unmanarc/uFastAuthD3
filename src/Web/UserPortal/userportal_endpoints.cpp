#include "userportal_endpoints.h"
#include "IdentityManager/ds_authentication.h"
#include "globals.h"

#include <algorithm>
#include <boost/algorithm/string/join.hpp>
#include <cinttypes>
#include <ctime>
#include <json/value.h>

using namespace Mantids30;
using namespace Mantids30::Program;
using namespace Mantids30::API::RESTful;
using namespace Mantids30::Network::Protocol;
using namespace Mantids30::DataFormat;

void UserPortal_Endpoints::addEndpoints(const std::shared_ptr<Endpoints> &endpoints)
{
    using SecurityRequirements = API::Security::Requirements;

    // TODO: assign permissions.
    // TODO: log password change/delete
    endpoints->addEndpoint(HTTP::Method::GET, "getLastLogin", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &getLastLogin);
    endpoints->addEndpoint(HTTP::Method::GET, "getDashboardData", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &getDashboardData);
    endpoints->addEndpoint(HTTP::Method::GET, "searchAccountSessions", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &searchAccountSessions);
    endpoints->addEndpoint(HTTP::Method::GET, "searchAccountCredentialsActivity", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &searchAccountCredentialsActivity);
    endpoints->addEndpoint(HTTP::Method::GET, "getAccountDetailFieldsValues", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &getAccountDetailFieldsValues);
    endpoints->addEndpoint(HTTP::Method::PUT, "updateAccountDetailFieldsValues", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &updateAccountDetailFieldsValues);
    endpoints->addEndpoint(HTTP::Method::GET, "listAccountApplicationsFullInfo", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &listAccountApplicationsFullInfo);
    endpoints->addEndpoint(HTTP::Method::GET, "listAllAuthCredentialSlotsPublicData", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &listAllAuthCredentialSlotsPublicData);
    endpoints->addEndpoint(HTTP::Method::POST, "activateCredential", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &activateCredential);
    endpoints->addEndpoint(HTTP::Method::POST, "activateOTPCredential", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &activateOTP);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeCredential", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &removeCredential);
    endpoints->addEndpoint(HTTP::Method::POST, "createChallengeToken", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &createChallengeToken);
    endpoints->addEndpoint(HTTP::Method::POST, "changeCredential", SecurityRequirements::JWT_COOKIE_AUTH, {}, nullptr, &changeCredential);
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::changeCredential(void *context, const RequestContext &request, ClientDetails &clientDetails)
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
            return {HTTP::Status::Code::S_401_UNAUTHORIZED, "change_credential_failed", "Challenge Token Expired or Invalid, Try Again."};
        }
        else if (!appMatches)
        {
            return {HTTP::Status::Code::S_401_UNAUTHORIZED, "change_credential_failed", "Invalid Challenge Token: App mismatch"};
        }
        else if (!typeIsChallenge)
        {
            return {HTTP::Status::Code::S_401_UNAUTHORIZED, "change_credential_failed", "Invalid Challenge Token: Type is not 'challenge'"};
        }
    }

    if (Helpers::JSON::ASSTRING(challengeToken.getClaim("details"), "operation", "") != "changeCredential")
    {
        return {HTTP::Status::Code::S_401_UNAUTHORIZED, "change_credential_failed", "Invalid Operation for Challenge Token"};
    }

    std::string accountUUID = challengeToken.getSubject();
    uint32_t slotId = Helpers::JSON::ASUINT_D(challengeToken.getClaim("slotId"), 0);

    Credential cred;
    cred.fromJSON((*request.inputJSON)["credential"]);
    cred.setExpirationTimeAutomatically();

    if (!Globals::getIdentityManager()->authController->changeAccountCredential(clientDetails, accountUUID, accountUUID, cred, slotId))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "change_credential_failed", "Failed to change credential"};
    }

    return response;
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::createChallengeToken(void *context, const RequestContext &request, ClientDetails &clientDetails)
{
    API::APIReturn response;

    std::string accountUUID = request.jwtToken->getSubject();

    // Parse input parameters
    if (!request.inputJSON->isMember("slotId") || !request.inputJSON->isMember("verification") || !request.inputJSON->isMember("details"))
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "missing_fields", "slotId + verification + details are required"};
    }

    uint32_t slotId = Helpers::JSON::ASUINT((*request.inputJSON), "slotId", 0);
    std::string verification = Helpers::JSON::ASSTRING((*request.inputJSON), "verification", "");
    AuthenticationResult authResult = Globals::getIdentityManager()->authController->authenticateCredential(clientDetails, accountUUID, verification, slotId);

    // Log the authentication result
    LOG_APP->log2(__func__,
                  accountUUID,
                  clientDetails.ipAddress,
                  authResult != AuthenticationResult::AUTHENTICATED ? Logs::LogLevel::SECURITY_ALERT : Logs::LogLevel::INFO,
                  "Account Authorization Result: %" PRIu16 " - %s, for application '%s', and slotId = '%" PRIu32 "'",
                  static_cast<uint16_t>(authResult),
                  authResultToString(authResult),
                  request.jwtToken->getClaim("app").asString().c_str(),
                  slotId);

    if (!IS_CREDENTIAL_AUTHENTICATED(authResult))
    {
        return {HTTP::Status::Code::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(authResult)), authResultToString(authResult)};
    }

    JWT::Token token;
    token.setExpirationTime(time(nullptr) + 120); // 2 min token.
    token.setSubject(request.jwtToken->getSubject());
    token.setClaim("type", "challenge");
    token.setClaim("app", request.jwtToken->getClaim("app"));
    token.setClaim("parentTokenId", request.jwtToken->getJwtId());
    token.setClaim("slotId", slotId);
    token.setClaim("details", (*request.inputJSON)["details"]);

    HTTP::Headers::Cookie cookie = HTTP::Headers::Cookie();
    cookie.value = request.jwtSigner->signFromToken(token, false);
    cookie.expires = HTTP::Date(token.getExpirationTime());
    response.cookiesMap["ChallengeToken"] = cookie;
    return response;
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::listAllAuthCredentialSlotsPublicData(void *context, const RequestContext &request, ClientDetails &clientDetails)
{
    Json::Value result(Json::arrayValue);
    std::string accountUUID = request.jwtToken->getSubject();
    std::map<uint32_t, std::pair<bool, Credential>> creds = Globals::getIdentityManager()->authController->listAllAuthCredentialSlotsPublicDataForAccount(accountUUID);
    const AuthenticationPolicy &authPolicy = Globals::getIdentityManager()->authController->getGlobalAuthenticationPolicy();

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

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::listAccountApplicationsFullInfo(void *context, const RequestContext &request, ClientDetails &clientDetails)
{
    Json::Value result(Json::arrayValue);
    std::string accountUUID = request.jwtToken->getSubject();

    for (const AccountApplicationInfo &appInfo : Globals::getIdentityManager()->applications->listAccountApplicationsFullInfo(accountUUID))
    {
        result.append(appInfo.toJSON());
    }

    return result;
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::updateAccountDetailFieldsValues(void *context, const RequestContext &request, ClientDetails &clientDetails)
{
    API::APIReturn response;

    std::string accountUUID = request.jwtToken->getSubject();

    // Get the list of field values from input
    Json::Value fieldValuesArray = (*request.inputJSON)["fieldValues"];
    if (!fieldValuesArray.isArray())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Field values must be an array"};
    }

    std::map<std::string, std::string> fieldValues;

    // Process each field value in the array
    for (const auto &i : fieldValuesArray)
    {
        std::string fieldName = Helpers::JSON::ASSTRING(i, "name", "");
        std::string fieldValue = Helpers::JSON::ASSTRING(i, "value", "");
        if (!fieldName.empty())
        {
            fieldValues[fieldName] = fieldValue;
        }
    }

    // Update account detail fields values
    UpdateAccountDetailFieldValuesResult result = Globals::getIdentityManager()->accounts->updateAccountDetailFieldValues(clientDetails, accountUUID, accountUUID, fieldValues, false);

    switch (result.status)
    {
    case UpdateAccountDetailFieldValuesResult::Status::SUCCESS:
        return response;

    case UpdateAccountDetailFieldValuesResult::Status::INVALID_FIELD:
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_field", "One or more field names do not exist: " + boost::algorithm::join(result.duplicateFields, ", ")};

    case UpdateAccountDetailFieldValuesResult::Status::PERMISSION_DENIED:
        return {HTTP::Status::Code::S_403_FORBIDDEN, "permission_denied", "User lacks permission to edit one or more fields"};

    case UpdateAccountDetailFieldValuesResult::Status::REGEX_VALIDATION_FAILED:
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "regex_validation_failed", "One or more values failed regex validation: " + boost::algorithm::join(result.regexInvalidFields, ", ")};

    case UpdateAccountDetailFieldValuesResult::Status::DUPLICATE_LOGIN_IDENTIFIER:
        return {HTTP::Status::Code::S_409_CONFLICT, "duplicate_login_identifier", "Login identifier conflict for fields: " + boost::algorithm::join(result.duplicateFields, ", ")};

    case UpdateAccountDetailFieldValuesResult::Status::DUPLICATE_UNIQUE_FIELD:
        return {HTTP::Status::Code::S_409_CONFLICT, "duplicate_unique_field", "Unique field conflict for fields: " + boost::algorithm::join(result.uniqueInvalidFields, ", ")};

    case UpdateAccountDetailFieldValuesResult::Status::DB_ERROR:
    default:
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "db_error", "Database error while updating account detail fields values"};
    }
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::getAccountDetailFieldsValues(void *context, const RequestContext &request, ClientDetails &clientDetails)
{
    API::APIReturn response;

    std::string accountUUID = request.jwtToken->getSubject();

    std::map<std::string, AccountDetailFieldValue> fieldValues = Globals::getIdentityManager()->accounts->getAccountDetailFieldValues(accountUUID);

    std::vector<std::pair<std::string, AccountDetailFieldValue>> sortedFieldValues(fieldValues.begin(), fieldValues.end());
    std::sort(sortedFieldValues.begin(),
              sortedFieldValues.end(),
              [](const std::pair<std::string, AccountDetailFieldValue> &a, const std::pair<std::string, AccountDetailFieldValue> &b) { return a.second.orderPriority < b.second.orderPriority; });

    Json::Value result(Json::arrayValue);
    for (const auto &fieldValue : sortedFieldValues)
    {
        result.append(fieldValue.second.toJSON());
    }

    return result;
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::searchAccountCredentialsActivity(void *context, const RequestContext &request, ClientDetails &clientDetails)
{
    std::string accountUUID = request.jwtToken->getSubject();
    return Globals::getIdentityManager()->authController->searchAccountCredentialsActivity(accountUUID, *request.inputJSON);
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::searchAccountSessions(void *context, const RequestContext &request, ClientDetails &clientDetails)
{
    std::string accountUUID = request.jwtToken->getSubject();
    return Globals::getIdentityManager()->authController->searchAccountSessions(accountUUID, *request.inputJSON);
}

Json::Value getLastLoginJSON(const RequestContext &request)
{
    Json::Value result;

    std::string accountUUID = request.jwtToken->getSubject();
    IdentityManager::LastAccountAccessResult lastLoginOpt = Globals::getIdentityManager()->authController->getAccountLastAccess(accountUUID);

    if (lastLoginOpt.lastAccess)
    {
        result["timestamp"] = static_cast<Json::Int64>(lastLoginOpt.lastAccess.value().time);
        result["appName"] = lastLoginOpt.lastAccess.value().app;
    }
    else
    {
        result["timestamp"] = Json::Value::null;
    }

    return result;
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::getDashboardData(void *context, const RequestContext &request, ClientDetails &clientDetails)
{
    Json::Value result;

    result["lastLogin"] = getLastLoginJSON(request);

    std::string accountUUID = request.jwtToken->getSubject();
    uint32_t activeSessionsCount = Globals::getIdentityManager()->authController->getAccountActiveSessionsCount(accountUUID);
    std::pair<uint32_t, uint32_t> activePasswordSlots = Globals::getIdentityManager()->authController->getAccountActiveCredentialsCount(accountUUID);

    result["activeSessionsCount"] = activeSessionsCount;
    result["activePasswordSlots"] = Json::Value(Json::objectValue);
    result["activePasswordSlots"]["used"] = activePasswordSlots.second;
    result["activePasswordSlots"]["total"] = activePasswordSlots.first;

    std::set<std::string> applications = Globals::getIdentityManager()->applications->listAccountApplications(accountUUID);

    result["applicationsCount"] = applications.size();

    return result;
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::getLastLogin(void *context, const RequestContext &request, ClientDetails &clientDetails)
{
    return getLastLoginJSON(request);
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::activateCredential(void *context, const RequestContext &request, ClientDetails &clientDetails)
{
    API::APIReturn response;

    std::string accountUUID = request.jwtToken->getSubject();

    // Parse input parameters
    if (!request.inputJSON->isMember("slotId") || !request.inputJSON->isMember("hash") || !request.inputJSON->isMember("ssalt"))
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "missing_fields", "slotId, hash, and ssalt are required"};
    }

    uint32_t slotId = Helpers::JSON::ASUINT((*request.inputJSON), "slotId", 0);
    std::string hash = Helpers::JSON::ASSTRING((*request.inputJSON), "hash", "");
    std::string ssalt = Helpers::JSON::ASSTRING((*request.inputJSON), "ssalt", "");

    // Check if credential already exists using the new function
    if (Globals::getIdentityManager()->authController->doesCredentialSlotExistOnAccount(accountUUID, slotId))
    {
        return {HTTP::Status::Code::S_409_CONFLICT, "activation_failed", "Credential is already activated"};
    }

    if (!Globals::getIdentityManager()->authController->activateAccountCredential(clientDetails, accountUUID, accountUUID, slotId, hash, ssalt))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "activation_failed", "Failed to activate credential"};
    }

    return response;
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::activateOTP(void *context, const RequestContext &request, ClientDetails &clientDetails)
{
    API::APIReturn response;

    std::string accountUUID = request.jwtToken->getSubject();

    if (!request.inputJSON->isMember("slotId") || !request.inputJSON->isMember("seed"))
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "missing_fields", "slotId and seed are required"};
    }

    uint32_t slotId = Helpers::JSON::ASUINT((*request.inputJSON), "slotId", 0);
    std::string seed = Helpers::JSON::ASSTRING((*request.inputJSON), "seed", "");

    if (Globals::getIdentityManager()->authController->doesCredentialSlotExistOnAccount(accountUUID, slotId))
    {
        return {HTTP::Status::Code::S_409_CONFLICT, "activation_failed", "OTP credential is already activated"};
    }

    if (!Globals::getIdentityManager()->authController->activateAccountCredential(clientDetails, accountUUID, accountUUID, slotId, seed, ""))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "activation_failed", "Failed to activate OTP credential"};
    }

    return response;
}

UserPortal_Endpoints::APIReturn UserPortal_Endpoints::removeCredential(void *context, const RequestContext &request, ClientDetails &clientDetails)
{
    API::APIReturn response;

    std::string accountUUID = request.jwtToken->getSubject();

    // Parse input parameters
    if (!request.inputJSON->isMember("slotId") || !request.inputJSON->isMember("verification"))
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "missing_fields", "slotId and verification is required"};
    }

    uint32_t slotId = Helpers::JSON::ASUINT((*request.inputJSON), "slotId", 0);
    std::string verification = Helpers::JSON::ASSTRING((*request.inputJSON), "verification", "");

    AuthenticationResult authResult = Globals::getIdentityManager()->authController->authenticateCredential(clientDetails, accountUUID, verification, slotId);

    // Log the authentication result
    LOG_APP->log2(__func__,
                  accountUUID,
                  clientDetails.ipAddress,
                  authResult != AuthenticationResult::AUTHENTICATED ? Logs::LogLevel::SECURITY_ALERT : Logs::LogLevel::INFO,
                  "Account Authorization Result: %" PRIu16 " - %s, for application '%s', and slotId = '%" PRIu32 "'",
                  static_cast<uint16_t>(authResult),
                  authResultToString(authResult),
                  request.jwtToken->getClaim("app").asString().c_str(),
                  slotId);

    if (!IS_CREDENTIAL_AUTHENTICATED(authResult))
    {
        return {HTTP::Status::Code::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(authResult)), authResultToString(authResult)};
    }

    if (!Globals::getIdentityManager()->authController->removeAccountCredential(clientDetails, accountUUID, accountUUID, slotId))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "deletion_failed", "Failed to delete credential"};
    }

    return response;
}
