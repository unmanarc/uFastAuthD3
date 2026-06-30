#pragma once

#include <json/value.h>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <set>

#include "credentialvalidator.h"
#include "ds_account.h"
#include "ds_application.h"
#include "ds_security_events.h"
#include <Mantids30/Helpers/json.h>
#include <ctime>
#include <string>

#include <Mantids30/DataFormat_JWT/jwt.h>
#include <Mantids30/Threads/mutex_shared.h>
#include <Mantids30/Threads/safe_mapitem.h>

class IdentityManager : public Mantids30::Threads::Safe::MapItem
{
public:
    using ClientDetails = Mantids30::Sessions::ClientDetails;

    /**
     * @brief Logout reasons for applicationAuthLog entries.
     */
    enum class LogoutReason : uint8_t
    {
        None = 0,
        RefreshTokenExpired = 2,
        UserInitiated = 3,
        Revoked = 4,
        Other = 100
    };

    struct LastAccountAccessResult
    {
        struct LastAccountAccessInfo
        {
            time_t time;
            std::string app;
        };
        std::optional<time_t> inactivityExtensionUntil;  // Si tiene extensión activa y hasta cuándo
        std::optional<LastAccountAccessInfo> lastAccess; // Último login (time + app juntos, o nullopt)
    };

    IdentityManager() = default;
    virtual ~IdentityManager();

    [[nodiscard]] bool isAccountActiveAndValidForApp(const std::string &accountUUID, const std::string &appName, AuthenticationResult &reason, bool checkValidAppAccount) const;

    class Accounts
    {
    public:
        Accounts(IdentityManager *m_parent) { this->m_parent = m_parent; }
        virtual ~Accounts() = default;

        virtual bool extendInactivity(const std::string &accountUUID, const time_t &validUntil) = 0;

        std::optional<std::string> createAdminAccount( const ClientDetails &clientDetails, const std::string & accountName, const std::string &performedBy );

        /////////////////////////////////////////////////////////////////////////////////
        // account:
        virtual CreateAccountResult createAccount(time_t expirationDate, // Note: use 1 to create an expired account.
                                                  const AccountFlags &accountFlags, const ClientDetails &clientDetails, const std::string &performedBy, const std::map<std::string,ApplicationDef> &appDefs,
                                                  const std::map<std::string, std::string> &detailFieldsValues)
            = 0;

        // Listing:
        virtual bool doesAccountExist(const std::string &accountUUID) = 0;
        virtual std::set<std::string> listAccounts() = 0;

        // List all admin account UUIDs:
        virtual std::set<std::string> listAdminAccounts() = 0;

        // Account confirmation:
        virtual bool confirmAccount(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, const std::string &confirmationToken) = 0;

        // The IAM has any admin account?
        virtual bool hasValidAdminAccount();

        // Lookup accountUUID by a login-identifier field value (e.g. email, username):
        virtual std::optional<std::string> getAccountUUIDByAccountName(const std::string &accountName) = 0;

        // Account Removing/Disabling/...
        virtual bool removeAccount(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID) = 0;
        virtual bool disableAccount(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, bool disabled = true) = 0;

        // Account Details:
        virtual std::optional<AccountDetails> getAccountDetails(const std::string &accountUUID, const AccountDetailsToShow &detailsToShow) = 0;
        virtual Json::Value searchAccounts(const Json::Value &dataTablesFilters) = 0;

        // Account Expiration:
        virtual bool changeAccountExpiration(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, time_t expiration = 0) = 0;
        virtual time_t getAccountExpirationTime(const std::string &accountUUID) = 0;
        virtual time_t getAccountCreationTime(const std::string &accountUUID) = 0;
        bool isAccountExpired(const std::string &accountUUID);

        // Account Flag Scopes:
        virtual AccountFlags getAccountFlags(const std::string &accountUUID) = 0;
        virtual bool changeAccountFlags(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, const AccountFlags &accountFlags) = 0;

        // Account role set:
        virtual bool updateAccountApplicationRoles(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &accountUUID,
                                                   const std::set<std::string> &roleSet)
            = 0;
        virtual std::set<ApplicationRole> getAccountApplicationRoles(const std::string &appName, const std::string &accountUUID, bool lock = true) = 0;

        // Account block using token:
        virtual std::string getAccountBlockToken(const std::string &accountUUID) = 0;
        virtual bool blockAccountUsingToken(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, const std::string &blockToken) = 0;

        /**
         * @brief Result codes for removing an account detail field.
         */
        enum class RemoveAccountDetailFieldResult : uint8_t
        {
            SUCCESS = 0,               // Field removed successfully.
            FIELD_NOT_FOUND = 1,       // Field does not exist.
            LAST_LOGIN_IDENTIFIER = 2, // Cannot remove: this is the last login identifier field.
            DB_ERROR = 3               // Database error occurred.
        };

        /**
         * @brief Result codes for updating an account detail field.
         */
        enum class UpdateAccountDetailFieldResult : uint8_t
        {
            SUCCESS = 0,                           // Field updated successfully.
            FIELD_NOT_FOUND = 1,                   // Field does not exist.
            LAST_LOGIN_IDENTIFIER = 2,             // Cannot update: this is the last login identifier field and you are trying to disable it.
            DB_ERROR = 3,                          // Database error occurred.
            DUPLICATE_VALUES_FOR_UNIQUE_FIELD = 4, // Cannot enable isUnique: duplicate values already exist for this field.
            LOGIN_IDENTIFIER_VALUE_CONFLICT = 5    // Cannot enable isLoginIdentifier: value would conflict with existing login identifier values across accounts.
        };

        // Account Details Fields
        virtual bool createAccountDetailField(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &fieldName, const AccountDetailField &details) = 0;
        virtual UpdateAccountDetailFieldResult updateAccountDetailField(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &fieldName,
                                                                        const AccountDetailField &details)
            = 0;
        virtual RemoveAccountDetailFieldResult removeAccountDetailField(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &fieldName) = 0;
        virtual std::map<std::string, AccountDetailField> listAccountDetailFields() = 0;
        virtual std::optional<AccountDetailField> getAccountDetailField(const std::string &fieldName) = 0;

        virtual Json::Value searchFields(const Json::Value &dataTablesFilters) = 0;

        // Account Details
        virtual bool changeAccountDetails(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, const std::map<std::string, std::string> &fieldsValues,
                                          bool resetAllValues = false)
            = 0;
        virtual bool removeAccountDetail(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, const std::string &fieldName) = 0;

        virtual std::map<std::string, AccountDetailFieldValue> getAccountDetailFieldValues(const std::string &accountUUID, const AccountDetailsToShow &detailsToShow = AccountDetailsToShow::ALL) = 0;
        virtual UpdateAccountDetailFieldValuesResult updateAccountDetailFieldValues(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID,
                                                                                    const std::map<std::string, std::string> &fieldValues, bool isAdmin)
            = 0;

    private:
        IdentityManager *m_parent = nullptr;
    };
    class ApplicationRoles
    {
    public:
        virtual ~ApplicationRoles() = default;
        /////////////////////////////////////////////////////////////////////////////////
        // role:
        virtual bool createRole(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &roleName, const std::string &roleDescription) = 0;
        virtual bool removeRole(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &roleName) = 0;
        virtual bool doesRoleExist(const std::string &appName, const std::string &roleName) = 0;
        virtual bool addAccountToRole(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &roleName, const std::string &accountUUID) = 0;
        virtual bool removeAccountFromRole(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &roleName, const std::string &accountUUID,
                                           bool lock = true)
            = 0;
        virtual bool updateRoleDescription(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &roleName,
                                           const std::string &roleDescription)
            = 0;

        virtual std::set<std::string> listApplicationScopesOnApplicationRole(const std::string &appName, const std::string &roleName) = 0;
        virtual std::string getApplicationRoleDescription(const std::string &appName, const std::string &roleName) = 0;
        virtual std::set<ApplicationRole> getApplicationRolesList(const std::string &appName) = 0;
        virtual std::set<std::string> getApplicationRoleAccounts(const std::string &appName, const std::string &roleName, bool lock = true) = 0;
        virtual Json::Value searchApplicationRoles(const Json::Value &dataTablesFilters) = 0;
    };

    class ApplicationScopes
    {
    public:
        ApplicationScopes(IdentityManager *m_parent) { this->m_parent = m_parent; }
        virtual ~ApplicationScopes() = default;

        virtual std::set<ApplicationScope> getAccountDirectApplicationScopes(const std::string &accountUUID, bool lock = true) = 0;

        std::set<ApplicationScope> getAccountUsableApplicationScopes(const std::string &appName, const std::string &accountUUID);
        bool validateAccountApplicationScope(const std::string &accountUUID, const ApplicationScope &applicationScope);

        virtual bool validateApplicationScopeOnRole(const std::string &roleName, const ApplicationScope &applicationScope, bool lock = true) = 0;
        virtual std::set<ApplicationScope> getRoleApplicationScopes(const std::string &appName, const std::string &roleName, bool lock = true) = 0;

        /////////////////////////////////////////////////////////////////////////////////
        // scopes:
        virtual bool createApplicationScope(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope) = 0;
        virtual bool removeApplicationScope(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope) = 0;
        virtual bool doesApplicationScopeExist(const ApplicationScope &applicationScope) = 0;
        virtual bool addApplicationScopeToRole(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope, const std::string &roleName) = 0;
        virtual bool removeApplicationScopeFromRole(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope, const std::string &roleName,
                                                    bool lock = true)
            = 0;
        virtual bool addApplicationScopeToAccount(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope, const std::string &accountUUID) = 0;
        virtual bool removeApplicationScopeFromAccount(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope, const std::string &accountUUID,
                                                       bool lock = true)
            = 0;
        virtual bool updateApplicationScopeDescription(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope) = 0;
        virtual std::string getApplicationScopeDescription(const ApplicationScope &applicationScope) = 0;
        virtual std::set<ApplicationScope> listApplicationScopes(const std::string &applicationName = "") = 0;
        virtual std::set<std::string> getApplicationRolesForScope(const ApplicationScope &applicationScope, bool lock = true) = 0;
        virtual std::set<std::string> listAccountsOnApplicationScope(const ApplicationScope &applicationScope, bool lock = true) = 0;
        virtual Json::Value searchApplicationScopes(const Json::Value &dataTablesFilters) = 0;
        virtual bool validateAccountDirectApplicationScope(const std::string &accountUUID, const ApplicationScope &applicationScope) = 0;

    private:
        IdentityManager *m_parent = nullptr;
    };

    class ApplicationActivities
    {
    public:
        struct ActivityData
        {
            [[nodiscard]] Json::Value toJSON() const
            {
                Json::Value r;
                r["description"] = description;
                r["parentActivity"] = parentActivity;
                r["defaultSchemeDescription"] = defaultSchemeDescription;
                r["defaultSchemeID"] = defaultSchemeID;
                return r;
            }
            void fromJSON(const Json::Value &r)
            {
                description = Helpers::JSON::ASSTRING(r, "description", "");
                parentActivity = Helpers::JSON::ASSTRING(r, "parentActivity", "");
                defaultSchemeDescription = Helpers::JSON::ASSTRING(r, "defaultSchemeDescription", "");
                defaultSchemeID = Helpers::JSON::ASUINT(r, "defaultSchemeID", -1);
            }

            std::string description;
            std::string parentActivity;
            std::string defaultSchemeDescription;
            uint32_t defaultSchemeID = -1;
        };

        virtual ~ApplicationActivities() = default;

        virtual bool createLoginActivity() = 0;

        /////////////////////////////////////////////////////////////////////////////////
        virtual bool createApplicationActivity(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &activityName,
                                               const std::string &activityDescription)
            = 0;
        virtual bool removeApplicationActivity(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &activityName) = 0;
        virtual bool setApplicationActivities(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::map<std::string, ActivityData> &activities) = 0;
        virtual bool removeAllApplicationActivities(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName) = 0;
        virtual std::map<std::string, ActivityData> listApplicationActivities(const std::string &appName) = 0;
        virtual std::optional<ActivityData> getApplicationActivityInfo(const std::string &appName, const std::string &activityName) = 0;
        virtual bool setApplicationActivityParentActivity(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &activityName,
                                                          const std::string &parentActivityName)
            = 0;
        virtual bool setApplicationActivityDescription(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &activityName,
                                                       const std::string &description)
            = 0;

        /**
         * @brief Retrieves the default authentication scheme ID for a specific application and activity.
         *
         * This function queries the database to fetch the `defaultSchemeId` for the given application (`appName`)
         * and activity (`activityName`). If no default scheme is set, the function returns std::nullopt
         *
         * @param appName The name of the application.
         * @param activityName The name of the activity within the application.
         * @return uint32_t The ID of the default authentication scheme, std::nullopt if not set.
         *
         * @note This function acquires a read lock (`Lock_RD`) to ensure thread safety while accessing shared resources.
         */
        virtual std::optional<uint32_t> getApplicationActivityDefaultScheme(const std::string &appName, const std::string &activityName) = 0;
        /**
         * @brief Sets or updates the default authentication scheme ID for a specific application and activity.
         *
         * This function updates the `defaultSchemeId` in the database for the given application (`appName`) and
         * activity (`activityName`) to the specified `schemeId`.
         *
         * @param appName The name of the application.
         * @param activityName The name of the activity within the application.
         * @param schemeId The ID of the authentication scheme to set as the default.
         * @return bool `true` if the operation succeeds, `false` otherwise.
         *
         * @note This function acquires a write lock (`Lock_RW`) to ensure thread safety while modifying the database.
         */
        virtual bool setApplicationActivityDefaultScheme(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &activityName,
                                                         const uint32_t &schemeId)
            = 0;
        virtual std::set<uint32_t> listAuthenticationSchemesForApplicationActivity(const std::string &appName, const std::string &activityName) = 0;
        virtual bool addAuthenticationSchemeToApplicationActivity(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &activityName,
                                                                  const uint32_t &schemeId, bool lock = true)
            = 0;
        virtual bool removeAuthenticationSchemeFromApplicationActivity(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &activityName,
                                                                       const uint32_t &schemeId)
            = 0;
    };
    class AuthController : public CredentialValidator
    {
    private:
        IdentityManager *m_parent = nullptr;
        Mantids30::Threads::GarbageCollector m_authLogGC;
        static Json::Value authSlotsToJSON(const std::vector<AuthenticationSchemeUsedSlot> &authSlots);
        void updateCredentialAuthStatus(const AuthenticationResult &authResult, const std::string &accountUUID, const Credential &storedCredentialData, const uint32_t &slotId,
                                        const ClientDetails &clientDetails);

    protected:
        AuthenticationPolicy m_authenticationPolicy;
        virtual Credential retrieveAccountCredential(const std::string &accountUUID, const uint32_t &slotId, bool *accountFound, bool *authSlotFound) = 0;

    public:
        AuthController(IdentityManager *parent);
        ~AuthController() override = default;

        static void markExpiredAuthLogSessions(void *p) { static_cast<AuthController *>(p)->markExpiredAuthLogSessions(); }

        virtual void markExpiredAuthLogSessions() = 0;

        std::optional<uint32_t> initializateDefaultPasswordSchemes(bool *defaultPasswordSchemesExist);

        std::string genRandomConfirmationToken();

        AuthenticationPolicy getGlobalAuthenticationPolicy();
        void setAuthenticationPolicy(const AuthenticationPolicy &newAuthenticationPolicy);

        bool validateAccountApplicationScope(const std::string &accountUUID, const ApplicationScope &applicationScope) override
        {
            return m_parent->applicationScopes->validateAccountApplicationScope(accountUUID, applicationScope);
        }

        // Account bad attempts for pass slot id...
        virtual void resetBadAttemptsOnAccountCredential(const std::string &accountUUID, const uint32_t &slotId) = 0;
        virtual void incrementBadAttemptsOnAccountCredential(const std::string &accountUUID, const uint32_t &slotId) = 0;

        // Account Credentials:
        virtual bool changeAccountCredential(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, Credential passwordData, uint32_t slotId) = 0;
        // TODO: the slotId of the master password should be configured in a configuration file.
        bool recoverAccountMasterCredential(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, std::string *password);

        virtual bool activateAccountCredential(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, uint32_t slotId, const std::string &hash,
                                               const std::string &ssalt)
            = 0;
        virtual bool setAccountCredentialMustChange(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, uint32_t slotId, bool mustChange) = 0;
        virtual bool setAccountCredentialLockedStatus(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, uint32_t slotId, bool isLocked) = 0;

        bool setAccountPasswordOnScheme(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, std::string *sInitPW, const uint32_t &schemeId);

        // Account last login:
        virtual void insertApplicationAccountAccessAuthLog(const std::string &accountUUID, const std::string &appName, const uint32_t &schemeId, const ClientDetails &clientDetails,
                                                           const std::string &refresherTokenId, const std::string &accessTokenId, const time_t &accessTokenExpiration,
                                                           const time_t &refreshTokenExpiration)
            = 0;
        virtual void insertAccountAuthCredentialSlotLog(const std::string &accountUUID, uint32_t slotId, const ClientDetails &clientDetails, int logStatus) = 0;

        virtual LastAccountAccessResult getAccountLastAccess(const std::string &accountUUID) = 0;

        virtual uint32_t getAccountActiveSessionsCount(const std::string &accountUUID) = 0;
        virtual std::pair<uint32_t, uint32_t> getAccountActiveCredentialsCount(const std::string &accountUUID) = 0;
        virtual Json::Value searchAccountSessions(const std::string &accountUUID, const Json::Value &dataTablesFilters) = 0;
        virtual Json::Value searchAccountCredentialsActivity(const std::string &accountUUID, const Json::Value &dataTablesFilters) = 0;

        // Application Auth Log - Logout and Token tracking:
        virtual bool updateApplicationAuthLogAccessTokenId(const std::string &accountUUID, const std::string &appName, const std::string &refresherTokenId, const std::string &accessTokenId,
                                                           const time_t &accessTokenExpiration)
            = 0;
        virtual bool logoutApplicationAuthLog(const std::string &accountUUID, const std::string &appName, const std::string &refresherTokenId, LogoutReason reason) = 0;

        /////////////////////////////////////////////////////////////////////////////////
        // authentication:
        /**
         * @brief Authenticates a user's credential based on provided details and optional authentication context.
         *
         * This function validates the user's credentials, checking against account status, authentication policies,
         * and slot-based authentication schemes. It also supports additional authentication context for enhanced flexibility.
         * If authentication fails, the function increments the bad attempt counters for the account and authentication slot.
         *
         * @param clientDetails Contains session-related details for the client attempting authentication (e.g., IP address, session ID).
         * @param accountUUID The user or account identifier to authenticate.
         * @param password The incoming password or credential to validate against stored data.
         * @param slotId The identifier for the specific authentication slot being used.
         * @param authMode Specifies the mode of authentication (e.g., plain text, hashed). Default is `MODE_PLAIN`.
         * @param challengeSalt Optional salt used in challenge-based authentication methods. Default is an empty string.
         * @param authContext (Optional) A shared pointer to an `TransientAuthenticationContext` object, which provides supplementary
         *        data for authentication, such as:
         *        - Application name (`appName`)
         *        - Authentication scheme ID (`schemeId`)
         *        - Slot scheme hash (`slotSchemeHash`)
         *        - Current slot position (`currentSlotPosition`)
         *        - List of authentication slots (`authSlots`)
         *        This is useful for multi-step or application-specific authentication workflows.
         *
         * @return `AuthenticationResult` Enum value indicating the result of the authentication attempt:
         *         - `NONE`: Authentication successful.
         *         - `ACCOUNT_NOT_IN_APP`: Account is not registered for the specified application.
         *         - `AUTH_SCHEME_EMPTY`: The authentication scheme has no associated slots.
         *         - `AUTH_SCHEME_CHANGED`: The slot scheme has changed, indicating a possible race condition.
         *         - `CREDENTIAL_INDEX_NOT_FOUND`: The specified slot ID or index is invalid.
         *         - `BAD_ACCOUNT`: The account does not exist or is invalid.
         *         - `UNCONFIRMED_ACCOUNT`: The account is not confirmed.
         *         - `DISABLED_ACCOUNT`: The account is disabled or blocked.
         *         - `EXPIRED_ACCOUNT`: The account has expired or is considered abandoned.
         *         - Other `AuthenticationResult` codes depending on the implementation of `validateStoredCredential`.
         *
         * @note On failure, the function ensures to increment bad attempt counters for the account and the password slot.
         */
        AuthenticationResult authenticateCredential(const ClientDetails &clientDetails, const std::string &accountUUID, const std::string &sPassword, const uint32_t &slotId = 0,
                                                    const Mode &authMode = Mode::PLAIN, const std::string &challengeSalt = "",
                                                    std::shared_ptr<TransientAuthenticationContext> authContext = nullptr) override;

        bool isAccountInactive(const LastAccountAccessResult &lastLogin, bool isAdmin) const;

        /**
     * @brief getAccountCredentialPublicData Get information for Salted Password Calculation and expiration info (Not Authenticated)
     * @param accountUUID Account Name
     * @param found value set to true/false if the account was found or not.
     * @param slotId AuthController Slot SlotId.
     * @return Password Information (Eg. hashing function, salt, expiration, etc)
     */
        Credential getAccountCredentialPublicData(const std::string &accountUUID, uint32_t slotId) override;

        /**
     * @brief getAccountAllCredentialsPublicData Get a map with slotId->public credential data for an account.
     * @param accountUUID account ID or user string.
     * @return map with every defined and not defined password.
     */
        std::map<uint32_t, Credential> getAccountAllCredentialsPublicData(const std::string &accountUUID);

        virtual bool doesCredentialSlotExistOnAccount(const std::string &accountUUID, uint32_t slotId) = 0;

        /**
     * @brief changeAccountAuthenticatedCredential Change the password doing current password authentication
     * @param accountUUID
     * @param currentPassword
     * @param authMode
     * @param challengeSalt
     * @param newPasswordData New Password Data (hash, salt, expiration, etc)
     * @param slotId AuthController Slot SlotId.
     * @return true if changed, false if not (bad password, etc)
     */
        virtual bool changeAccountAuthenticatedCredential(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, uint32_t slotId,
                                                          const std::string &sCurrentPassword, const Credential &newPasswordData, Mode authMode = Mode::PLAIN, const std::string &challengeSalt = "");

        virtual bool removeAccountCredential(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, uint32_t slotId) = 0;

        /////////////////////////////////////////////////////////////////////////////////
        // AuthController Slot SlotIds:
        virtual std::optional<uint32_t> createAuthenticationSlot(const ClientDetails &clientDetails, const std::string &performedBy, const AuthenticationSlotDetails &details) = 0;
        virtual bool removeAuthenticationSlot(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &slotId) = 0;
        virtual bool updateAuthenticationSlotDetails(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &slotId, const AuthenticationSlotDetails &details) = 0;
        virtual std::map<uint32_t, AuthenticationSlotDetails> listAllAuthenticationSlots() = 0;

        virtual std::optional<uint32_t> createAuthenticationScheme(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &description) = 0;
        virtual bool updateAuthenticationScheme(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &schemeId, const std::string &description) = 0;
        virtual bool removeAuthenticationScheme(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &schemeId) = 0;
        virtual std::map<uint32_t, std::string> listAuthenticationSchemes() = 0;

        virtual std::vector<AuthenticationSchemeUsedSlot> listAuthenticationSlotsUsedByScheme(const uint32_t &schemeId) = 0;
        virtual bool updateAuthenticationSlotUsedByScheme(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &schemeId,
                                                          const std::list<AuthenticationSchemeUsedSlot> &slotsUsedByScheme)
            = 0;
        virtual std::set<uint32_t> listUsedAuthenticationSlotsOnAccount(const std::string &accountUUID) = 0;
        virtual std::map<uint32_t, std::pair<bool, Credential>> listAllAuthCredentialSlotsPublicDataForAccount(const std::string &accountUUID) = 0;

        virtual bool updateDefaultAuthScheme(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &schemeId) = 0;
        virtual std::optional<uint32_t> getDefaultAuthScheme() = 0;

        Credential createNewCredential(const uint32_t &slotId, const std::string &passwordInput, bool mustChange = false);

        /**
         * @brief Retrieves the applicable authentication schemes for a user for a specific application activity.
         *
         * This function checks the available authentication schemes for an application activity and determines
         * which schemes are applicable to the user based on the authentication slots the user has.
         *
         * @param app The name of the application.
         * @param activity The name of the activity within the application.
         * @param accountUUID account ID or user string.
         * @return Json::Value A JSON object containing the applicable authentication schemes, their details, and the default scheme.
         */
        Json::Value getApplicableAuthenticationSchemesForAccount(const std::string &app, const std::string &activity, const std::string &accountUUID,
                                                                 const std::set<uint32_t> &alreadyAuthenticatedSlots);
    };
    class Applications
    {
    public:
        virtual ~Applications() = default;
        struct ApplicationAttributes
        {
            [[nodiscard]] Json::Value toJSON() const
            {
                Json::Value root;
                root["canAdminModifyApplicationSecurityContext"] = canAdminModifyApplicationSecurityContext;
                root["canUserAutoRegister"] = canUserAutoRegister;
                root["useEmbeddedAuthentication"] = useEmbeddedAuthentication;
                root["appSyncEnabled"] = appSyncEnabled;
                root["appSyncCanRetrieveAppAccountsList"] = appSyncCanRetrieveAppAccountsList;
                root["allowKeepMeSignedIn"] = allowKeepMeSignedIn;
                return root;
            }

            void fromJSON(const Json::Value &root)
            {
                canAdminModifyApplicationSecurityContext = Helpers::JSON::ASBOOL(root, "canAdminModifyApplicationSecurityContext", false);
                canUserAutoRegister = Helpers::JSON::ASBOOL(root, "canUserAutoRegister", false);
                appSyncEnabled = Helpers::JSON::ASBOOL(root, "appSyncEnabled", false);
                useEmbeddedAuthentication = Helpers::JSON::ASBOOL(root, "useEmbeddedAuthentication", false);
                appSyncCanRetrieveAppAccountsList = Helpers::JSON::ASBOOL(root, "appSyncCanRetrieveAppAccountsList", false);
                allowKeepMeSignedIn = Helpers::JSON::ASBOOL(root, "allowKeepMeSignedIn", false);
            }

            [[nodiscard]] std::string toString() const
            {
                return "adminModifySecurity=" + std::to_string(canAdminModifyApplicationSecurityContext) + ", autoRegister=" + std::to_string(canUserAutoRegister)
                       + ", useEmbeddedAuth=" + std::to_string(useEmbeddedAuthentication) + ", syncEnabled=" + std::to_string(appSyncEnabled)
                       + ", syncCanRetrieveAccounts=" + std::to_string(appSyncCanRetrieveAppAccountsList) + ", keepMeSignedIn=" + std::to_string(allowKeepMeSignedIn);
            }
            bool canAdminModifyApplicationSecurityContext = false;
            bool canUserAutoRegister = false;
            bool useEmbeddedAuthentication = false;
            bool appSyncEnabled = false;
            bool appSyncCanRetrieveAppAccountsList = false;
            bool allowKeepMeSignedIn = false;
        };

        /////////////////////////////////////////////////////////////////////////////////
        // applications:
        virtual bool createApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &applicationDescription,
                                       const std::string &appURL, const std::string &apiKey, const std::string &creatorAccountName, const ApplicationAttributes &appAttributes,
                                       bool initializeDefaultValues)
            = 0;
        virtual bool removeApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName) = 0;
        virtual bool doesApplicationExist(const std::string &appName) = 0;

        virtual std::optional<ApplicationAttributes> getApplicationAttributes(const std::string &appName) = 0;
        virtual bool updateApplicationAttributes(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const ApplicationAttributes &appAttributes) = 0;

        virtual std::string getApplicationDescription(const std::string &appName) = 0;
        virtual std::string getApplicationAPIKey(const std::string &appName) = 0;
        virtual bool updateApplicationDescription(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &applicationDescription) = 0;
        virtual bool updateApplicationAPIKey(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &apiKey) = 0;
        virtual std::string getApplicationNameByAPIKey(const std::string &apiKey) = 0;

        virtual std::set<std::string> listApplications() = 0;
        virtual bool isApplicationAdmin(const std::string &appName, const std::string &accountUUID) = 0;
        virtual bool validateApplicationAccount(const std::string &appName, const std::string &accountUUID) = 0;
        virtual std::set<std::string> listApplicationAdmins(const std::string &appName) = 0;
        virtual std::set<std::string> listApplicationAccounts(const std::string &appName) = 0;
        virtual std::set<std::string> listAccountApplications(const std::string &accountUUID) = 0;
        virtual bool addAccountToApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &accountUUID) = 0;
        virtual bool removeAccountFromApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &accountUUID) = 0;
        virtual bool setAccountAsApplicationAdmin(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &accountUUID, bool isAppAdmin) = 0;
        virtual Json::Value searchApplications(const Json::Value &dataTablesFilters) = 0;

        virtual std::vector<AccountApplicationInfo> listAccountApplicationsFullInfo(const std::string &accountUUID) = 0;

        // Weblogin return urls:
        virtual bool addWebLoginAllowedRedirectURIToApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &loginRedirectURI) = 0;
        virtual bool removeWebLoginAllowedRedirectURIToApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &loginRedirectURI)
            = 0;
        virtual std::set<std::string> listWebLoginAllowedRedirectURIsFromApplication(const std::string &appName) = 0;

        virtual bool updateWebLoginDefaultRedirectURIForApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &loginRedirectURI)
            = 0;
        virtual std::string getWebLoginDefaultRedirectURIForApplication(const std::string &appName) = 0;

        virtual bool setApplicationWebLoginCallbackURI(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &callbackURI) = 0;
        virtual std::string getApplicationCallbackURI(const std::string &appName) = 0;

        // Application admited origin URLS:
        virtual bool addWebLoginOriginURLToApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &originUrl) = 0;
        virtual bool removeWebLoginOriginURLToApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &originUrl) = 0;
        virtual std::set<std::string> listWebLoginOriginUrlsFromApplication(const std::string &appName) = 0;

        // A aplication activity can have multiple authentication schemes...
        // by example, some (special) activities can be: transfer_money, edit_details, and so...
        // Activities can be defined here:

        // Tokens:
        virtual bool updateWebLoginJWTConfigForApplication(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationTokenProperties &tokenInfo) = 0;
        virtual ApplicationTokenProperties getWebLoginJWTConfigFromApplication(const std::string &appName) = 0;
        virtual bool setWebLoginJWTSigningKeyForApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &signingKey) = 0;
        virtual std::string getWebLoginJWTSigningKeyForApplication(const std::string &appName) = 0;
        virtual bool setWebLoginJWTValidationKeyForApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &signingKey) = 0;
        virtual std::string getWebLoginJWTValidationKeyForApplication(const std::string &appName) = 0;

        std::shared_ptr<Mantids30::DataFormat::JWT> getAppJWTValidator(const std::string &appName);
        std::shared_ptr<Mantids30::DataFormat::JWT> getAppJWTSigner(const std::string &appName);
    };

    Accounts *accounts = nullptr;
    ApplicationScopes *applicationScopes = nullptr;
    ApplicationRoles *applicationRoles = nullptr;
    ApplicationActivities *applicationActivities = nullptr;
    Applications *applications = nullptr;
    AuthController *authController = nullptr;

    /**
     * @brief checkConnection Check if the Authentication IdentityManager Connection is Alive.
     * @return true if alive, false otherwise.
     */
    virtual bool checkConnection() { return true; }
    virtual bool initializeDatabase() = 0;

    [[nodiscard]] bool initializeAdminAccountWithPasswordIfNotExist(const uint32_t &schemeId, bool forceIfExist) const;
    bool initializeApplicationWithScheme(const std::string &appName, const std::string &appDescription, const std::string &appURL, const uint32_t &schemeId, bool *alreadyExist) const;

protected:
    Mantids30::Threads::Sync::Mutex_Shared m_mutex;
};
