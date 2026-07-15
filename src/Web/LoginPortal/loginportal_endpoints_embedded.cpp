#include "IdentityManager/ds_authentication.h"
#include "Tokens/tokensmanager.h"
#include "loginportal_endpoints.h"
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Program_Logs/loglevels.h>
#include <Mantids30/Protocol_HTTP/api_return.h>
#include <json/value.h>

#include "globals.h"

#include <cinttypes>
#include <cstdint>
#include <json/config.h>
#include <map>
#include <memory>
#include <optional>
#include <string>

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocol;
using namespace Mantids30::DataFormat;

/**
 * @brief Embedded direct token endpoint for embedded applications (e.g., PAM modules).
 *
 * Accepts all credentials for all slotIds in a single request, validates them sequentially
 * according to the authentication scheme, and returns access/refresh tokens directly.
 *
 * Input JSON:
 * {
 *   "accountName": "username",
 *   "appName": "myApp",
 *   "schemeId": 1,
 *   "keepAuthenticated": true,
 *   "credentials": [
 *     { "slotId": 1, "value": "password123" },
 *     { "slotId": 2, "value": "totp_code" }
 *   ]
 * }
 *
 * Output JSON (Success):
 * {
 *   "accessToken": "eyJ...",
 *   "refreshToken": "eyJ...",
 *   "tokenType": "Bearer"
 * }
 *
 * Output JSON (Error):
 * {
 *   "error": "AUTH_ERR_106",
 *   "message": "Authentication Failed",
 *   "failedSlotId": 1
 * }
 */
API::APIReturn LoginPortal_Endpoints::embedToken(void *context, const API::RESTful::RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    IdentityManager *identityManager = Globals::getIdentityManager();

    // -----------------------------------------------------------------
    // 1. Parse input JSON
    // -----------------------------------------------------------------
    std::string accountName = Helpers::JSON::ASSTRING(*request.inputJSON, "accountName", "");
    std::string appName = Helpers::JSON::ASSTRING(*request.inputJSON, "app", "");
    uint32_t schemeId = Helpers::JSON::ASUINT(*request.inputJSON, "schemeId", 0);
    bool keepAuthenticated = Helpers::JSON::ASBOOL(*request.inputJSON, "keepAuthenticated", false);
    bool usingEmbeddedInPortalAuthentication = false;

    const std::string apiKey = request.clientRequest->getHeaderOption("x-api-key");
    if (!apiKey.empty())
    {
        appName = identityManager->applications->getApplicationNameByAPIKey(apiKey);
        usingEmbeddedInPortalAuthentication = true;
        if (appName.empty())
        {
            LOG_APP->log2(__func__, "", authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "Invalid API key provided. Application not found.");
            return {HTTP::Status::Code::S_401_UNAUTHORIZED, "invalid_api_key", "The provided API key is invalid or unauthorized."};
        }

        // Check if the application has embedded authentication enabled
        std::optional<IdentityManager::Applications::ApplicationAttributes> appAttrs = identityManager->applications->getApplicationAttributes(appName);
        if (!appAttrs.has_value())
        {
            LOG_APP->log2(__func__, appName, authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "Application attributes not found for app: %s", appName.c_str());
            return {HTTP::Status::Code::S_404_NOT_FOUND, "not_found", "Application not found."};
        }
        if (!appAttrs.value().useEmbeddedInPortalAuthentication)
        {
            LOG_APP->log2(__func__, appName, authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "API key access attempted for non-embedded application. App: %s", appName.c_str());
            return {HTTP::Status::Code::S_403_FORBIDDEN, "security_error", "Application does not support embedded authentication via API key."};
        }
    }

    const Json::Value &jCredentials = (*request.inputJSON)["credentials"];

    // Validate required fields
    if (accountName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::BAD_PARAMETERS)), "Missing required field: accountName"};
    }
    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::BAD_PARAMETERS)), "Missing required field: app"};
    }
    if (schemeId == 0)
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::BAD_PARAMETERS)), "Missing required field: schemeId"};
    }
    if (!jCredentials.isArray() || jCredentials.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST,
                "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::BAD_PARAMETERS)),
                "Missing or invalid field: credentials (must be a non-empty array)"};
    }

    // -----------------------------------------------------------------
    // 2. Validate application exists
    // -----------------------------------------------------------------
    if (!identityManager->applications->doesApplicationExist(appName))
    {
        LOG_APP->log2(__func__, accountName, authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "Embedded token request denied: Application '%s' does not exist.", appName.c_str());
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::BAD_PARAMETERS)), "Invalid Application"};
    }

    // -----------------------------------------------------------------
    // 3. Resolve accountName to accountUUID
    // -----------------------------------------------------------------
    std::optional<std::string> _accountUUID = identityManager->accounts->getAccountUUIDByAccountName(accountName);
    std::string accountUUID;
    if (!_accountUUID.has_value())
    {
        LOG_APP->log2(__func__,
                      accountName,
                      authClientDetails.ipAddress,
                      Logs::LogLevel::SECURITY_ALERT,
                      "Embedded token request denied: Account '%s' not found, continuing without UUID to prevent user enumeration.",
                      accountName.c_str());
    }
    else
        accountUUID = _accountUUID.value();

    // -----------------------------------------------------------------
    // 3b. Validate that the requested scheme is applicable for LOGIN
    // -----------------------------------------------------------------
    std::set<uint32_t> schemesInActivity = identityManager->applicationActivities->listAuthenticationSchemesForApplicationActivity(IAM_LOGINPORTAL_APPNAME, "LOGIN");
    if (schemesInActivity.find(schemeId) == schemesInActivity.end())
    {
        LOG_APP->log2(__func__, accountName, authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "Token request denied: The user is requesting a scheme that is not in that activity.");
        return {HTTP::Status::Code::S_401_UNAUTHORIZED,
                "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::INVALID_SCHEME_FOR_ACTIVITY)),
                authResultToString(AuthenticationResult::INVALID_SCHEME_FOR_ACTIVITY)};
    }

    // -----------------------------------------------------------------
    // 4. Build a map: slotId -> credential value from input
    // -----------------------------------------------------------------
    std::map<uint32_t, std::string> credentialsMap;
    for (const auto &cred : jCredentials)
    {
        uint32_t slotId = Helpers::JSON::ASUINT(cred, "slotId", 0);
        std::string value = Helpers::JSON::ASSTRING(cred, "value", "");
        if (slotId > 0 && !value.empty())
        {
            credentialsMap[slotId] = value;
        }
    }

    // -----------------------------------------------------------------
    // 5. Get authentication scheme slots (ordered by priority)
    // -----------------------------------------------------------------
    std::vector<AuthenticationSchemeUsedSlot> schemeSlots = identityManager->authController->listAuthenticationSlotsUsedByScheme(schemeId);
    if (schemeSlots.empty())
    {
        LOG_APP->log2(__func__,
                      accountName,
                      authClientDetails.ipAddress,
                      Logs::LogLevel::SECURITY_ALERT,
                      "Embedded token request denied: Authentication scheme %" PRIu32 " has no slots configured.",
                      schemeId);
        return {HTTP::Status::Code::S_400_BAD_REQUEST,
                "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::AUTH_SCHEME_EMPTY)),
                authResultToString(AuthenticationResult::AUTH_SCHEME_EMPTY)};
    }

    // Get account's activated slots
    std::set<uint32_t> accountActivatedSlots = identityManager->authController->listUsedAuthenticationSlotsOnAccount(accountUUID);

    // -----------------------------------------------------------------
    // 6. Determine which slots are required for this account
    // -----------------------------------------------------------------
    std::vector<AuthenticationSchemeUsedSlot> requiredSlots;
    for (const auto &slot : schemeSlots)
    {
        bool isRequired = false;
        if (slot.optional)
        {
            // Optional slot: required only if activated on the account
            if (accountActivatedSlots.find(slot.slotId) != accountActivatedSlots.end())
            {
                isRequired = true;
            }
        }
        else
        {
            // Mandatory slot: always required
            isRequired = true;
        }

        if (isRequired)
        {
            requiredSlots.push_back(slot);
        }
    }

    if (requiredSlots.empty())
    {
        LOG_APP->log2(__func__,
                      accountName,
                      authClientDetails.ipAddress,
                      Logs::LogLevel::SECURITY_ALERT,
                      "Embedded token request denied: No required slots for account with scheme %" PRIu32 ".",
                      schemeId);
        return {HTTP::Status::Code::S_400_BAD_REQUEST,
                "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::AUTH_SCHEME_EMPTY)),
                authResultToString(AuthenticationResult::AUTH_SCHEME_EMPTY)};
    }

    // -----------------------------------------------------------------
    // 7. Validate credentials sequentially in scheme order
    // -----------------------------------------------------------------
    std::set<uint32_t> authenticatedSlotIds;

    for (const auto &slot : requiredSlots)
    {
        uint32_t slotId = slot.slotId;

        // Check if the caller provided a credential for this slot
        auto it = credentialsMap.find(slotId);
        if (it == credentialsMap.end())
        {
            LOG_APP->log2(__func__, accountName, authClientDetails.ipAddress, Logs::LogLevel::SECURITY_ALERT, "Embedded token request denied: Missing credential for required slot %" PRIu32 ".", slotId);
            return {HTTP::Status::Code::S_400_BAD_REQUEST,
                    "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::BAD_PARAMETERS)),
                    "Missing credential for required slotId: " + std::to_string(slotId)};
        }

        // Create a minimal TransientAuthenticationContext for authenticateCredential
        std::shared_ptr<TransientAuthenticationContext> authContext = std::make_shared<TransientAuthenticationContext>();
        authContext->accountUUID = accountUUID;
        authContext->accountName = accountName;
        authContext->appName = appName;
        authContext->schemeId = schemeId;
        authContext->currentSlotId = slotId;
        authContext->doesTransientTokenNotExist = true;

        // Authenticate the credential
        AuthenticationResult authResult = identityManager->authController->authenticateCredential(authClientDetails, accountUUID, it->second, slotId, Mode::PLAIN, "", authContext);

        if (!IS_CREDENTIAL_AUTHENTICATED(authResult))
        {
            LOG_APP->log2(__func__,
                          accountName,
                          authClientDetails.ipAddress,
                          Logs::LogLevel::SECURITY_ALERT,
                          "Embedded token request denied: Slot %" PRIu32 " authentication failed: %s",
                          slotId,
                          authResultToString(authResult));

            if (authResult == AuthenticationResult::INVALID_ACCOUNT)
            {
                authResult = AuthenticationResult::AUTHENTICATION_FAILED;
            }

            return {HTTP::Status::Code::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(authResult)), authResultToString(authResult)};
        }

        // Credential validated successfully
        authenticatedSlotIds.insert(slotId);
        LOG_APP->log2(__func__, accountName, authClientDetails.ipAddress, Logs::LogLevel::INFO, "Embedded auth: Slot %" PRIu32 " authenticated successfully.", slotId);
    }

    // -----------------------------------------------------------------
    // 8. Verify the account is valid for this application
    // -----------------------------------------------------------------
    if (!identityManager->applications->validateApplicationAccount(appName, accountUUID))
    {
        LOG_APP->log2(__func__,
                      accountName,
                      authClientDetails.ipAddress,
                      Logs::LogLevel::SECURITY_ALERT,
                      "Embedded token request denied: Account is not registered in application '%s'.",
                      appName.c_str());
        return {HTTP::Status::Code::S_403_FORBIDDEN,
                "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::ACCOUNT_NOT_IN_APP)),
                authResultToString(AuthenticationResult::ACCOUNT_NOT_IN_APP)};
    }

    // -----------------------------------------------------------------
    // 9. Generate and sign access/refresh tokens directly
    // -----------------------------------------------------------------
    ApplicationAuthSettings appAuthSettings = identityManager->applications->getAuthSettingsFromApplication(appName);

    if (appAuthSettings.appName != appName)
    {
        LOG_APP->log1(__func__, accountName, Logs::LogLevel::CRITICAL, "Configuration error: Application '%s' has invalid auth settings.", appName.c_str());
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Application configuration error"};
    }

    std::string refreshTokenId = Mantids30::Helpers::Random::createRandomString(16);

    JWT::Token accessToken, refreshToken;

    TokensManager::ApplicationTokenCommonParams params;
    params.refreshTokenId = refreshTokenId;
    params.appName = appName;
    params.jwtAccountName = accountName;
    params.slotIds = authenticatedSlotIds;
    params.appAuthSettings = appAuthSettings;

    TokensManager::RefreshTokenParams refreshExtraParams;
    refreshExtraParams.activity = "LOGIN";
    refreshExtraParams.keepAuthenticated = keepAuthenticated;
    refreshExtraParams.useEmbeddedInPortalAuthentication = usingEmbeddedInPortalAuthentication;

    TokensManager::configureApplicationRefreshToken(refreshToken, params, refreshExtraParams);
    TokensManager::configureApplicationAccessToken(accessToken, params);

    // Sign access token
    std::optional<std::string> accessTokenStr = LoginPortal_Endpoints::token_signApplicationJWT(accessToken);
    if (!accessTokenStr.has_value())
    {
        LOG_APP->log1(__func__, accountName, Logs::LogLevel::CRITICAL, "Failed to sign access token for application '%s'.", appName.c_str());
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to sign access token"};
    }

    // Sign refresh token
    std::optional<std::string> refreshTokenStr = LoginPortal_Endpoints::token_signApplicationJWT(refreshToken);
    if (!refreshTokenStr.has_value())
    {
        LOG_APP->log1(__func__, accountName, Logs::LogLevel::CRITICAL, "Failed to sign refresh token for application '%s'.", appName.c_str());
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to sign refresh token"};
    }

    // -----------------------------------------------------------------
    // 10. Log the session in the database
    // -----------------------------------------------------------------
    identityManager->authController->insertApplicationAccountAccessAuthLog(accountUUID,
                                                                           appName,
                                                                           schemeId,
                                                                           authClientDetails,
                                                                           refreshTokenId,
                                                                           accessToken.getJwtId(),
                                                                           accessToken.getExpirationTime(),
                                                                           refreshToken.getExpirationTime());

    LOG_APP
        ->log2(__func__, accountName, authClientDetails.ipAddress, Logs::LogLevel::INFO, "Embedded token issued successfully for application '%s' with scheme %" PRIu32 ".", appName.c_str(), schemeId);

    // -----------------------------------------------------------------
    // 11. Build success response
    // -----------------------------------------------------------------
    (*response.responseJSON())["accessToken"] = accessTokenStr.value();
    (*response.responseJSON())["refreshToken"] = refreshTokenStr.value();
    (*response.responseJSON())["tokenType"] = "Bearer";

    return response;
}