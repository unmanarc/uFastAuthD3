#include "IdentityManager/ds_authentication.h"
#include "identitymanager.h"

#include <json/value.h>
#include <Mantids30/Helpers/random.h>
#include <Mantids30/Threads/lock_shared.h>
#include <optional>
#include <string>

using namespace Mantids30;

Json::Value IdentityManager::AuthController::authSlotsToJSON(const std::vector<AuthenticationSchemeUsedSlot> &authSlots)
{
    Json::Value r;
    int i = 0;
    for (const AuthenticationSchemeUsedSlot &slot : authSlots)
    {
        r[i] = slot.toJSON();
    }
    return r;
}
void IdentityManager::AuthController::updateCredentialAuthStatus(const AuthenticationResult &authResult, const std::string &accountUUID, const Credential &storedCredentialData, const uint32_t &slotId,
                                                                 const ClientDetails &clientDetails)
{
    // Register the change for max attempts...
    if (!IS_CREDENTIAL_AUTHENTICATED(authResult))
    {
        // Increment the counter and disable the account according to the policy.
        if (storedCredentialData.hasExceededMaxAttempts(m_authenticationPolicy))
        {
            // Disable the account...
            m_parent->accounts->disableAccount(clientDetails, accountUUID, accountUUID, true);
        }
        else
        {
            incrementBadAttemptsOnAccountCredential(accountUUID, slotId);
        }
    }
    else
    {
        // Credential is authenticated:
        resetBadAttemptsOnAccountCredential(accountUUID, slotId);
    }

    // Log
    m_parent->authController->insertAccountAuthCredentialSlotLog(accountUUID, slotId, clientDetails, static_cast<uint16_t>(authResult));
}

bool IdentityManager::AuthController::isAccountInactive(const LastAccountAccessResult &lastLogin, bool isAdmin) const
{
    time_t currentLastLogin = 0;
    time_t now = time(nullptr);

    // Admin accounts are never considered inactive
    if (isAdmin)
    {
        return false;
    }

    // Check if an active inactivity extension exists and is still valid
    if (lastLogin.inactivityExtensionUntil.has_value() && lastLogin.inactivityExtensionUntil.value() > now)
    {
        // The account has a valid extension preventing inactivity
        return false;
    }

    // Determine the last login time for inactivity calculation
    if (lastLogin.lastAccess.has_value())
    {
        // Use the actual last access time
        currentLastLogin = lastLogin.lastAccess.value().time;
    }
    else
    {
        // No last login record: use current time so the account is NOT marked inactive.
        // (Don't penalize accounts if the log does not prove recent access,
        //  to avoid blocking if logs are moved or corrupted.)
        currentLastLogin = now;
    }

    // Check if the time since last access exceeds the abandoned account threshold
    return (currentLastLogin + m_authenticationPolicy.abandonedAccountExpirationSeconds < now);
}

AuthenticationResult IdentityManager::AuthController::authenticateCredential(const ClientDetails &clientDetails, const std::string &accountUUID, const std::string &incomingPassword,
                                                                             const uint32_t &slotId, const Mode &authMode, const std::string &challengeSalt,
                                                                             // Extras...
                                                                             std::shared_ptr<TransientAuthenticationContext> authContext)
{
    AuthenticationResult authResult = AuthenticationResult::BAD_ACCOUNT;
    bool accountFound = false, authSlotFound = false;
    Credential pStoredCredentialData;

    // If something changes in between,
    {
        std::shared_lock<std::shared_mutex> lock(m_parent->m_mutex);

        // Process the extras (using scheme/slot/app)...
        if (authContext)
        {
            // app does not exist or user not in app.
            /*if (!m_parent->applications->validateApplicationAccount(authContext->appName, accountUUID))
            {
                return AuthenticationResult::ACCOUNT_NOT_IN_APP;
            }*/

            // Get authentication slots for the scheme id:
            std::vector<AuthenticationSchemeUsedSlot> authSlotsUsedByScheme = listAuthenticationSlotsUsedByScheme(authContext->schemeId);

            // Empty slots / bad scheme id:
            if (authSlotsUsedByScheme.empty())
            {
                return AuthenticationResult::AUTH_SCHEME_EMPTY;
            }

            // Slots in position 0:
            if (authContext->doesTransientTokenNotExist)
            {
                //Calc the slot scheme hash
                authContext->slotSchemeHash = Helpers::Crypto::calcSHA256(authSlotsToJSON(authSlotsUsedByScheme).toStyledString());
            }
            else
            {
                // hash is not compatible (slots changed, prevent race condition)
                if (authContext->slotSchemeHash != Helpers::Crypto::calcSHA256(authSlotsToJSON(authSlotsUsedByScheme).toStyledString()))
                {
                    return AuthenticationResult::AUTH_SCHEME_CHANGED;
                }
            }
        }

        // Check if the retrieved credential
        pStoredCredentialData = retrieveAccountCredential(accountUUID, slotId, &accountFound, &authSlotFound);

        if (!accountFound)
        {
            authResult = AuthenticationResult::BAD_ACCOUNT;
        }
        else if (!authSlotFound)
        {
            authResult = AuthenticationResult::CREDENTIAL_INDEX_NOT_FOUND;
        }
        else
        {
            LastAccountAccessResult lastLogin = getAccountLastAccess(accountUUID);

            AccountFlags flags = m_parent->accounts->getAccountFlags(accountUUID);

            if (!flags.confirmed)
            {
                return AuthenticationResult::UNCONFIRMED_ACCOUNT;
            }
            else if (!flags.enabled || flags.blocked)
            {
                return AuthenticationResult::DISABLED_ACCOUNT;
            }
            else if (m_parent->accounts->isAccountExpired(accountUUID))
            {
                return AuthenticationResult::EXPIRED_ACCOUNT;
            }
            else if (isAccountInactive(lastLogin, flags.admin))
            {
                return AuthenticationResult::INACTIVE_ACCOUNT;
            }
            else if (pStoredCredentialData.isLocked)
            {
                return AuthenticationResult::LOCKED_CREDENTIAL;
            }
            else
            {
                authResult = validateStoredCredential(accountUUID, pStoredCredentialData, incomingPassword, challengeSalt, authMode);
            }
        }
    }

    updateCredentialAuthStatus(authResult, accountUUID, pStoredCredentialData, slotId, clientDetails);

    return authResult;
}

std::string IdentityManager::AuthController::genRandomConfirmationToken()
{
    return Mantids30::Helpers::Random::createRandomString(64);
}

AuthenticationPolicy IdentityManager::AuthController::getGlobalAuthenticationPolicy()
{
    std::shared_lock<std::shared_mutex> lock(m_parent->m_mutex);
    return m_authenticationPolicy;
}

void IdentityManager::AuthController::setAuthenticationPolicy(const AuthenticationPolicy &newAuthenticationPolicy)
{
    std::unique_lock<std::shared_mutex> lock(m_parent->m_mutex);
    m_authenticationPolicy = newAuthenticationPolicy;
}

Credential IdentityManager::AuthController::getAccountCredentialPublicData(const std::string &accountUUID, uint32_t slotId)
{
    // protective-limited method.
    bool bAccountFound = false;
    bool bSlotIdFound = false;
    Credential credential = retrieveAccountCredential(accountUUID, slotId, &bAccountFound, &bSlotIdFound);
    return credential.getPublicData(m_authenticationPolicy);
}

std::map<uint32_t, Credential> IdentityManager::AuthController::getAccountAllCredentialsPublicData(const std::string &accountUUID)
{
    // TODO: this function can only be accessed if the user has been authenticated...
    std::shared_lock<std::shared_mutex> lock(m_parent->m_mutex);
    std::map<uint32_t, Credential> r;
    std::set<uint32_t> slotIdsUsedByAccount = listUsedAuthenticationSlotsOnAccount(accountUUID);
    for (const uint32_t slotId : slotIdsUsedByAccount)
    {
        bool accountFound, authSlotFound;
        Credential credential = retrieveAccountCredential(accountUUID, slotId, &accountFound, &authSlotFound);
        if (accountFound && authSlotFound)
        {
            r[slotId] = credential.getPublicData(m_authenticationPolicy);
        }
    }
    return r;
}

// TODO: this can only be called when authenticated.
bool IdentityManager::AuthController::changeAccountAuthenticatedCredential(const ClientDetails &clientInfo, const std::string &performedBy, const std::string &accountUUID, uint32_t slotId,
                                                                           const std::string &sCurrentPassword, const Credential &passwordData, Mode authMode, const std::string &challengeSalt)
{
    {
        std::shared_lock<std::shared_mutex> lock(m_parent->m_mutex);

        std::map<uint32_t, AuthenticationSlotDetails> authSlots = listAllAuthenticationSlots();

        if (authSlots.find(slotId) == authSlots.end())
        {
            // Bad, no slot id available...
            return false;
        }

        if (!authSlots[slotId].isCompatible(passwordData.slotDetails))
        {
            // Bad, not compatible password...
            return false;
        }

        bool accountFound, authSlotFound;

        Credential storedCredential = retrieveAccountCredential(accountUUID, slotId, &accountFound, &authSlotFound);

        if (!accountFound)
        {
            // Account not found, you can't change this password...
            return false;
        }

        if (authSlotFound)
        {
            // If the slotId has been initialized, authenticate the current credential.
            AuthenticationResult i = authenticateCredential(clientInfo, accountUUID, sCurrentPassword, slotId, authMode, challengeSalt);
            // Now take the authentication and add/change the credential
            if (!(IS_CREDENTIAL_AUTHENTICATED(i)))
            {
                // Change the requested index.
                return false;
            }
        }
    }

    // change it here...
    return changeAccountCredential(clientInfo, performedBy, accountUUID, passwordData, slotId);
}


std::set<ApplicationScope> IdentityManager::ApplicationScopes::getAccountUsableApplicationScopes(const std::string &appName, const std::string &accountUUID)
{
    std::set<ApplicationScope> x;
    std::shared_lock<std::shared_mutex> lock(m_parent->m_mutex);
    // Take scope from the account
    for (const ApplicationScope &scope : getAccountDirectApplicationScopes(accountUUID, false))
    {
        x.insert(scope);
    }

    // Take the scope from the belonging roles
    for (const ApplicationRole &role : m_parent->accounts->getAccountApplicationRoles(appName, accountUUID, false))
    {
        for (const ApplicationScope &scope : getRoleApplicationScopes(appName, role.id, false))
        {
            x.insert(scope);
        }
    }
    return x;
}

bool IdentityManager::ApplicationScopes::validateAccountApplicationScope(const std::string &accountUUID, const ApplicationScope &applicationScope)
{
    std::shared_lock<std::shared_mutex> lock(m_parent->m_mutex);
    if (validateAccountDirectApplicationScope(accountUUID, applicationScope))
    {
        return true;
    }
    for (const ApplicationRole &role : m_parent->accounts->getAccountApplicationRoles(applicationScope.appName, accountUUID, false))
    {
        if (validateApplicationScopeOnRole(role.id, applicationScope, false))
        {
            return true;
        }
    }
    return false;
}

bool IdentityManager::AuthController::setAccountPasswordOnScheme(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, std::string *sInitPW,
                                                                 const uint32_t &schemeId)
{
    *sInitPW = "";
    std::vector<AuthenticationSchemeUsedSlot> authSlots;
    std::string newPass;
    Credential credentialData;

    {
        std::shared_lock<std::shared_mutex> lock(m_parent->m_mutex);

        authSlots = m_parent->authController->listAuthenticationSlotsUsedByScheme(schemeId);
        // not any slot assigned to this scheme
        if (authSlots.empty())
        {
            return false;
        }

        // not a password...
        if (!authSlots.begin()->details.isTextPasswordFunction())
        {
            return false;
        }
        newPass = Mantids30::Helpers::Random::createRandomString(16);
        credentialData = m_parent->authController->createNewCredential(authSlots.begin()->slotId, newPass, true);
    }

    bool r = m_parent->authController->changeAccountCredential(clientDetails, performedBy, accountUUID, credentialData, authSlots.begin()->slotId);

    if (r)
    {
        *sInitPW = newPass;
    }

    return r;

    /*
            &&

            &&
           _parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.accountCredentials "
                                "(`f_AuthSlotId`,`f_accountUUID`,`hash`,`expiration`,`salt`,`mustChange`)"
                                " VALUES"
                                "('0',:account,:hash,:expiration,:salt,:mustChange);",
                                {
                                    {":account",MAKE_VAR(STRING,accountUUID)},
                                    {":hash",MAKE_VAR(STRING,credentialData.hash)},
                                    {":expiration",MAKE_VAR(DATETIME,credentialData.expirationTimestamp)},
                                    {":salt",MAKE_VAR(STRING,Mantids30::Helpers::Encoders::toHex(credentialData.ssalt,4))},
                                    {":mustChange",MAKE_VAR(BOOL,credentialData.mustChange)}
                                }
                                );*/
    // TODO: pasar esto a slot
    //`totp2FAStepsToleranceWindow`,`function`
}

Credential IdentityManager::AuthController::createNewCredential(const uint32_t &slotId, const std::string &passwordInput, bool mustChange)
{
    Credential r;

    std::map<uint32_t, AuthenticationSlotDetails> authSlots = listAllAuthenticationSlots();

    if (authSlots.find(slotId) == authSlots.end())
    {
        return r;
    }

    r.slotDetails = authSlots[slotId];
    r.mustChange = mustChange;
    r.expirationTimestamp = time(nullptr) + r.slotDetails.defaultExpirationSeconds;

    if (r.slotDetails.passwordFunction.has_value())
    {
        switch (static_cast<HashFunction>(r.slotDetails.passwordFunction.value()))
        {
        case HashFunction::PLAIN:
        {
            r.hash = passwordInput;
        }
        break;
        case HashFunction::SHA256:
        {
            r.hash = Helpers::Crypto::calcSHA256(passwordInput);
        }
        break;
        case HashFunction::SHA512:
        {
            r.hash = Helpers::Crypto::calcSHA512(passwordInput);
        }
        break;
        case HashFunction::SSHA256:
        {
            Mantids30::Helpers::Random::createRandomSalt32(r.ssalt);
            r.hash = Helpers::Crypto::calcSSHA256(passwordInput, r.ssalt);
        }
        break;
        case HashFunction::SSHA512:
        {
            Mantids30::Helpers::Random::createRandomSalt32(r.ssalt);
            r.hash = Helpers::Crypto::calcSSHA512(passwordInput, r.ssalt);
        }
        break;
        case HashFunction::GAUTHTIME:
            r.hash = passwordInput;
        }
    }

    return r;
}

Json::Value IdentityManager::AuthController::getApplicableAuthenticationSchemesForAccount(const std::string &app, const std::string &activity, const std::string &accountUUID,
                                                                                   const std::set<uint32_t> &alreadyAuthenticatedSlots)
{
    std::shared_lock<std::shared_mutex> lock(m_parent->m_mutex);

    // Initialize the result JSON
    Json::Value r;
    r["defaultScheme"] = Json::nullValue;
    r["availableSchemes"] = Json::objectValue;

    std::map<uint32_t, std::string> allSchemes = listAuthenticationSchemes();

    ///////////////////////////////////////////////////////////////////////////
    ///  ACCOUNT DOES NOT BELONGS TO THE APP
    ///////////////////////////////////////////////////////////////////////////
    if (!m_parent->applications->validateApplicationAccount(app, accountUUID))
    {
        // If the user is invalid or not associated, return only the default scheme (reducing risk of user enumeration)
        std::optional<uint32_t> defaultSchemeId = m_parent->applicationActivities->getApplicationActivityDefaultScheme(app, activity);
        if (defaultSchemeId.has_value())
        {
            std::vector<AuthenticationSchemeUsedSlot> slots = listAuthenticationSlotsUsedByScheme(*defaultSchemeId);
            r["defaultScheme"] = std::to_string(*defaultSchemeId);

            // Create the scheme as a properly structured object
            Json::Value currentScheme;
            currentScheme["description"] = allSchemes[*defaultSchemeId];

            // Find the first available slot for this scheme
            if (!slots.empty())
            {
                currentScheme["firstSlot"] = slots.begin()->toJSON();
            }

            r["availableSchemes"][std::to_string(*defaultSchemeId)] = currentScheme;
        }
        return r;
    }

    ///////////////////////////////////////////////////////////////////////////
    ///  ACCOUNT DOES BELONGS TO THE APP
    ///////////////////////////////////////////////////////////////////////////
    // Fetch necessary data
    std::set<uint32_t> availableSchemes = m_parent->applicationActivities->listAuthenticationSchemesForApplicationActivity(app, activity);
    std::set<uint32_t> accountUsedAuthSlots = listUsedAuthenticationSlotsOnAccount(accountUUID);
    std::optional<uint32_t> defaultScheme = m_parent->applicationActivities->getApplicationActivityDefaultScheme(app, activity);

    // Iterate through available schemes
    for (const uint32_t &schemeId : availableSchemes)
    {
        std::vector<AuthenticationSchemeUsedSlot> slots = listAuthenticationSlotsUsedByScheme(schemeId);
        bool allSlotsAvailable = true;

        // Check if all required slots are available for the user
        for (const AuthenticationSchemeUsedSlot &slot : slots)
        {
            if (!slot.optional)
            {
                if (accountUsedAuthSlots.find(slot.slotId) == accountUsedAuthSlots.end())
                {
                    allSlotsAvailable = false;
                    break;
                }
            }
        }

        if (allSlotsAvailable)
        {
            int i = 0;
            Json::Value currentScheme;
            currentScheme["description"] = allSchemes[schemeId];

            // Find the first available slot for this scheme
            Json::Value firstSlot = Json::nullValue;
            for (const AuthenticationSchemeUsedSlot &slot : slots)
            {
                if (accountUsedAuthSlots.find(slot.slotId) != accountUsedAuthSlots.end() &&        // found in accountUsedAuthSlots
                    alreadyAuthenticatedSlots.find(slot.slotId) == alreadyAuthenticatedSlots.end() // not found in alreadyAuthenticatedSlots
                )
                {
                    firstSlot = slot.toJSON();
                    break;
                }
            }

            currentScheme["firstSlot"] = firstSlot;

            r["availableSchemes"][std::to_string(schemeId)] = currentScheme;

            // Put the default scheme OR if you found something without slot ids (already authenticated), go with it.
            if ((defaultScheme.has_value() && schemeId == *defaultScheme && r["defaultScheme"] == Json::nullValue) || firstSlot == Json::nullValue)
            {
                r["defaultScheme"] = std::to_string(schemeId);
            }
        }
    }
    return r;
}

std::optional<uint32_t> IdentityManager::AuthController::initializateDefaultPasswordSchemes(bool *defaultPasswordSchemesExist)
{
    uint32_t schemeId, authSlotId;
    bool r = true;
    ClientDetails clientDetails;
    const std::string performedBy;

    std::map<uint32_t, std::string> authSchemes = listAuthenticationSchemes();

    if (authSchemes.empty())
    {
        if (r)
        {
            std::optional<uint32_t> opt_asi = createAuthenticationSlot(clientDetails, performedBy,
                                                                       AuthenticationSlotDetails("Master Password", HashFunction::SHA256, "", 3600 * 24 * 365 * 1, 0, false));
            if ((r = opt_asi.has_value()))
            {
                authSlotId = *opt_asi;
            }
        }

        if (r)
        {
            std::optional<uint32_t> opt_sid = createAuthenticationScheme(clientDetails, performedBy, "Simple Password Login");
            if ((r = opt_sid.has_value()))
            {
                schemeId = *opt_sid;
            }
        }

        updateDefaultAuthScheme(clientDetails, performedBy, schemeId);

        r = r && updateAuthenticationSlotUsedByScheme(clientDetails, performedBy, schemeId, {AuthenticationSchemeUsedSlot(authSlotId, 0, false)});

        *defaultPasswordSchemesExist = false;

        if (!r)
        {
            return std::nullopt;
        }

        return schemeId;
    }

    *defaultPasswordSchemesExist = true;

    // Already initialized, return the first scheme with the description Simple Password Login
    for (const auto &scheme : authSchemes)
    {
        // Look for simple password login scheme:
        if (scheme.second == "Simple Password Login")
        {
            return scheme.first;
        }
    }
    return std::nullopt;
}
