#pragma once

#include <Mantids30/DataFormat_JSON/json.h>

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

    [[nodiscard]] bool isAccountActiveAndValidForApp(std::string_view accountUUID, std::string_view appName, AuthenticationResult &reason, bool checkValidAppAccount) const;

    class Accounts
    {
    public:
        Accounts(IdentityManager *m_parent) { this->m_parent = m_parent; }
        virtual ~Accounts() = default;

        virtual bool extendInactivity(std::string_view accountUUID, const time_t &validUntil) = 0;

        std::optional<std::string> createAdminAccount( const ClientDetails &clientDetails, std::string_view accountName, std::string_view performedBy );

        /////////////////////////////////////////////////////////////////////////////////
        // account:
        virtual CreateAccountResult createAccount(time_t expirationDate, // Note: use 1 to create an expired account.
                                                  const AccountFlags &accountFlags, const ClientDetails &clientDetails, std::string_view performedBy, const std::map<std::string,ApplicationDef> &appDefs,
                                                  const std::map<std::string, std::string> &detailFieldsValues)
            = 0;

        // Listing:
        virtual bool doesAccountExist(std::string_view accountUUID) = 0;
        virtual std::set<std::string> listAccounts() = 0;

        // List all admin account UUIDs:
        virtual std::set<std::string> listAdminAccounts() = 0;

        // Account confirmation:
        virtual bool confirmAccount(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, std::string_view confirmationToken) = 0;

        // The IAM has any admin account?
        virtual bool hasValidAdminAccount();

        // Lookup accountUUID by a login-identifier field value (e.g. email, username):
        virtual std::optional<std::string> getAccountUUIDByAccountName(std::string_view accountName) = 0;
        // Get all account names (login identifiers) for a given account UUID:
        virtual std::set<std::string> getAccountNamesByAccountUUID(std::string_view accountUUID) = 0;

        // Get the formatted display name for an account based on the configured DisplayFormat template:
        virtual std::string getAccountDisplayName(std::string_view accountUUID) = 0;

        // Account Removing/Disabling/...
        virtual bool removeAccount(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID) = 0;
        virtual bool disableAccount(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, bool disabled = true) = 0;

        // Account Details:
        virtual std::optional<AccountDetails> getAccountDetails(std::string_view accountUUID, const AccountDetailsToShow &detailsToShow) = 0;
        virtual boost::json::value searchAccounts(const boost::json::value &dataTablesFilters) = 0;

        // Account Expiration:
        virtual bool changeAccountExpiration(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, time_t expiration = 0) = 0;
        virtual time_t getAccountExpirationTime(std::string_view accountUUID) = 0;
        virtual time_t getAccountCreationTime(std::string_view accountUUID) = 0;
        bool isAccountExpired(std::string_view accountUUID);

        // Account Flag Scopes:
        virtual AccountFlags getAccountFlags(std::string_view accountUUID) = 0;
        virtual bool changeAccountFlags(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, const AccountFlags &accountFlags) = 0;

        // Account role set:
        virtual bool updateAccountApplicationRoles(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view accountUUID,
                                                   const std::set<std::string> &roleSet)
            = 0;
        virtual std::set<ApplicationRole> getAccountApplicationRoles(std::string_view appName, std::string_view accountUUID, bool lock = true) = 0;

        // Account block using token:
        virtual std::string getAccountBlockToken(std::string_view accountUUID) = 0;
        virtual bool blockAccountUsingToken(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, std::string_view blockToken) = 0;

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
        virtual bool createAccountDetailField(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view fieldName, const AccountDetailField &details) = 0;
        virtual UpdateAccountDetailFieldResult updateAccountDetailField(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view fieldName,
                                                                        const AccountDetailField &details)
            = 0;
        virtual RemoveAccountDetailFieldResult removeAccountDetailField(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view fieldName) = 0;
        virtual std::map<std::string, AccountDetailField> listAccountDetailFields() = 0;
        virtual std::optional<AccountDetailField> getAccountDetailField(std::string_view fieldName) = 0;

         virtual boost::json::value searchFields(const boost::json::value &dataTablesFilters) = 0;

         // Account Detail Fields Order Priority
         virtual bool moveAccountDetailFieldUp(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view fieldName) = 0;
         virtual bool moveAccountDetailFieldDown(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view fieldName) = 0;

         // Account Details
        virtual bool changeAccountDetails(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, const std::map<std::string, std::string> &fieldsValues,
                                          bool resetAllValues = false)
            = 0;
        virtual bool removeAccountDetail(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, std::string_view fieldName) = 0;

        virtual std::map<std::string, AccountDetailFieldValue> getAccountDetailFieldValues(std::string_view accountUUID, const AccountDetailsToShow &detailsToShow = AccountDetailsToShow::ALL) = 0;
        virtual UpdateAccountDetailFieldValuesResult updateAccountDetailFieldValues(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID,
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
        virtual bool createRole(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view roleName, std::string_view roleDescription) = 0;
        virtual bool removeRole(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view roleName) = 0;
        virtual bool doesRoleExist(std::string_view appName, std::string_view roleName) = 0;
        virtual bool addAccountToRole(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view roleName, std::string_view accountUUID) = 0;
        virtual bool removeAccountFromRole(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view roleName, std::string_view accountUUID,
                                           bool lock = true)
            = 0;
        virtual bool updateRoleDescription(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view roleName,
                                           std::string_view roleDescription)
            = 0;

        virtual std::set<std::string> listApplicationScopesOnApplicationRole(std::string_view appName, std::string_view roleName) = 0;
        virtual std::string getApplicationRoleDescription(std::string_view appName, std::string_view roleName) = 0;
        virtual std::set<ApplicationRole> getApplicationRolesList(std::string_view appName) = 0;
        virtual std::set<std::string> getApplicationRoleAccounts(std::string_view appName, std::string_view roleName, bool lock = true) = 0;
        virtual boost::json::value searchApplicationRoles(const boost::json::value &dataTablesFilters) = 0;
    };

    class ApplicationScopes
    {
    public:
        ApplicationScopes(IdentityManager *m_parent) { this->m_parent = m_parent; }
        virtual ~ApplicationScopes() = default;

        virtual std::set<ApplicationScope> getAccountDirectApplicationScopes(std::string_view accountUUID, bool lock = true) = 0;

        std::set<ApplicationScope> getAccountUsableApplicationScopes(std::string_view appName, std::string_view accountUUID);
        bool validateAccountApplicationScope(std::string_view accountUUID, const ApplicationScope &applicationScope);

        virtual bool validateApplicationScopeOnRole(std::string_view roleName, const ApplicationScope &applicationScope, bool lock = true) = 0;
        virtual std::set<ApplicationScope> getRoleApplicationScopes(std::string_view appName, std::string_view roleName, bool lock = true) = 0;

        /////////////////////////////////////////////////////////////////////////////////
        // scopes:
        virtual bool createApplicationScope(const ClientDetails &clientDetails, std::string_view performedBy, const ApplicationScope &applicationScope) = 0;
        virtual bool removeApplicationScope(const ClientDetails &clientDetails, std::string_view performedBy, const ApplicationScope &applicationScope) = 0;
        virtual bool doesApplicationScopeExist(const ApplicationScope &applicationScope) = 0;
        virtual bool addApplicationScopeToRole(const ClientDetails &clientDetails, std::string_view performedBy, const ApplicationScope &applicationScope, std::string_view roleName) = 0;
        virtual bool removeApplicationScopeFromRole(const ClientDetails &clientDetails, std::string_view performedBy, const ApplicationScope &applicationScope, std::string_view roleName,
                                                    bool lock = true)
            = 0;
        virtual bool addApplicationScopeToAccount(const ClientDetails &clientDetails, std::string_view performedBy, const ApplicationScope &applicationScope, std::string_view accountUUID) = 0;
        virtual bool removeApplicationScopeFromAccount(const ClientDetails &clientDetails, std::string_view performedBy, const ApplicationScope &applicationScope, std::string_view accountUUID,
                                                       bool lock = true)
            = 0;
        virtual bool updateApplicationScopeDescription(const ClientDetails &clientDetails, std::string_view performedBy, const ApplicationScope &applicationScope) = 0;
        virtual std::string getApplicationScopeDescription(const ApplicationScope &applicationScope) = 0;
        virtual std::set<ApplicationScope> listApplicationScopes(std::string_view applicationName = "") = 0;
        virtual std::set<std::string> getApplicationRolesForScope(const ApplicationScope &applicationScope, bool lock = true) = 0;
        virtual std::set<std::string> listAccountsOnApplicationScope(const ApplicationScope &applicationScope, bool lock = true) = 0;
        virtual boost::json::value searchApplicationScopes(const boost::json::value &dataTablesFilters) = 0;
        virtual bool validateAccountDirectApplicationScope(std::string_view accountUUID, const ApplicationScope &applicationScope) = 0;

    private:
        IdentityManager *m_parent = nullptr;
    };

    class ApplicationActivities
    {
    public:
        struct ActivityData
        {
            [[nodiscard]] boost::json::object toJSON() const
            {
                return boost::json::object{
                    {"description",              description},
                    {"parentActivity",           parentActivity},
                    {"defaultSchemeDescription", defaultSchemeDescription},
                    {"defaultSchemeID",          defaultSchemeID},
                };
            }
            void fromJSON(const boost::json::value &r)
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
        virtual bool createApplicationActivity(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view activityName,
                                               std::string_view activityDescription)
            = 0;
        virtual bool removeApplicationActivity(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view activityName) = 0;
        virtual bool setApplicationActivities(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, const std::map<std::string, ActivityData> &activities) = 0;
        virtual bool removeAllApplicationActivities(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName) = 0;
        virtual std::map<std::string, ActivityData> listApplicationActivities(std::string_view appName) = 0;
        virtual std::optional<ActivityData> getApplicationActivityInfo(std::string_view appName, std::string_view activityName) = 0;
        virtual bool setApplicationActivityParentActivity(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view activityName,
                                                          std::string_view parentActivityName)
            = 0;
        virtual bool setApplicationActivityDescription(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view activityName,
                                                       std::string_view description)
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
        virtual std::optional<uint32_t> getApplicationActivityDefaultScheme(std::string_view appName, std::string_view activityName) = 0;
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
        virtual bool setApplicationActivityDefaultScheme(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view activityName,
                                                         const uint32_t &schemeId)
            = 0;
        virtual std::set<uint32_t> listAuthenticationSchemesForApplicationActivity(std::string_view appName, std::string_view activityName) = 0;
        virtual bool addAuthenticationSchemeToApplicationActivity(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view activityName,
                                                                  const uint32_t &schemeId, bool lock = true)
            = 0;
        virtual bool removeAuthenticationSchemeFromApplicationActivity(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view activityName,
                                                                       const uint32_t &schemeId)
            = 0;
    };
    class AuthController : public CredentialValidator
    {
    private:
        IdentityManager *m_parent = nullptr;
        Mantids30::Threads::GarbageCollector m_authLogGC;
        static boost::json::array authSlotsToJSON(const std::vector<AuthenticationSchemeUsedSlot> &authSlots);
        void updateCredentialAuthStatus(const AuthenticationResult &authResult, std::string_view accountUUID, const Credential &storedCredentialData, const uint32_t &slotId,
                                        const ClientDetails &clientDetails);

    protected:
        AuthenticationPolicy m_authenticationPolicy;
        virtual Credential retrieveAccountCredential(std::string_view accountUUID, const uint32_t &slotId, bool *accountFound, bool *authSlotFound) = 0;

    public:
        AuthController(IdentityManager *parent);
        ~AuthController() override = default;

        static void markExpiredAuthLogSessions(void *p) { static_cast<AuthController *>(p)->markExpiredAuthLogSessions(); }

        virtual void markExpiredAuthLogSessions() = 0;

        std::optional<uint32_t> initializateDefaultPasswordSchemes(bool *defaultPasswordSchemesExist);

        std::string genRandomConfirmationToken();

        AuthenticationPolicy getGlobalAuthenticationPolicy();
        void setAuthenticationPolicy(const AuthenticationPolicy &newAuthenticationPolicy);

        bool validateAccountApplicationScope(std::string_view accountUUID, const ApplicationScope &applicationScope) override
        {
            return m_parent->applicationScopes->validateAccountApplicationScope(accountUUID, applicationScope);
        }

        // Account bad attempts for pass slot id...
        virtual void resetBadAttemptsOnAccountCredential(std::string_view accountUUID, const uint32_t &slotId) = 0;
        virtual void incrementBadAttemptsOnAccountCredential(std::string_view accountUUID, const uint32_t &slotId) = 0;

        // Account Credentials:
        virtual bool changeAccountCredential(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, Credential passwordData, uint32_t slotId) = 0;
        // TODO: the slotId of the master password should be configured in a configuration file.
        bool recoverAccountMasterCredential(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, std::string *password);

        virtual bool activateAccountCredential(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, uint32_t slotId, std::string_view hash,
                                               std::string_view ssalt)
            = 0;
        virtual bool setAccountCredentialMustChange(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, uint32_t slotId, bool mustChange) = 0;
        virtual bool setAccountCredentialLockedStatus(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, uint32_t slotId, bool isLocked) = 0;

        bool setAccountPasswordOnScheme(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, std::string *sInitPW, const uint32_t &schemeId);

        // Account last login:
        virtual void insertApplicationAccountAccessAuthLog(std::string_view accountUUID, std::string_view appName, const uint32_t &schemeId, const ClientDetails &clientDetails,
                                                           std::string_view refresherTokenId, std::string_view accessTokenId, const time_t &accessTokenExpiration,
                                                           const time_t &refreshTokenExpiration)
            = 0;
        virtual void insertAccountAuthCredentialSlotLog(std::string_view accountUUID, uint32_t slotId, const ClientDetails &clientDetails, int logStatus) = 0;

        virtual LastAccountAccessResult getAccountLastAccess(std::string_view accountUUID) = 0;

        virtual uint32_t getAccountActiveSessionsCount(std::string_view accountUUID) = 0;
        virtual std::pair<uint32_t, uint32_t> getAccountActiveCredentialsCount(std::string_view accountUUID) = 0;
        virtual boost::json::value searchAccountSessions(std::string_view accountUUID, const boost::json::value &dataTablesFilters) = 0;
        virtual boost::json::value searchAccountCredentialsActivity(std::string_view accountUUID, const boost::json::value &dataTablesFilters) = 0;

        // Application Auth Log - Logout and Token tracking:
        virtual bool updateApplicationAuthLogAccessTokenId(std::string_view accountUUID, std::string_view appName, std::string_view refresherTokenId, std::string_view accessTokenId,
                                                           const time_t &accessTokenExpiration)
            = 0;
        virtual bool logoutApplicationAuthLog(std::string_view accountUUID, std::string_view appName, std::string_view refresherTokenId, LogoutReason reason) = 0;

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
         *         - `INVALID_ACCOUNT`: The account does not exist or is invalid.
         *         - `UNCONFIRMED_ACCOUNT`: The account is not confirmed.
         *         - `DISABLED_ACCOUNT`: The account is disabled or blocked.
         *         - `EXPIRED_ACCOUNT`: The account has expired or is considered abandoned.
         *         - Other `AuthenticationResult` codes depending on the implementation of `validateStoredCredential`.
         *
         * @note On failure, the function ensures to increment bad attempt counters for the account and the password slot.
         */
        AuthenticationResult authenticateCredential(const ClientDetails &clientDetails, std::string_view accountUUID, std::string_view sPassword, const uint32_t &slotId = 0,
                                                    const Mode &authMode = Mode::PLAIN, std::string_view challengeSalt = "",
                                                    std::shared_ptr<TransientAuthenticationContext> authContext = nullptr) override;

        bool isAccountInactive(const LastAccountAccessResult &lastLogin, bool isAdmin) const;

        /**
     * @brief getAccountCredentialPublicData Get information for Salted Password Calculation and expiration info (Not Authenticated)
     * @param accountUUID Account Name
     * @param found value set to true/false if the account was found or not.
     * @param slotId AuthController Slot SlotId.
     * @return Password Information (Eg. hashing function, salt, expiration, etc)
     */
        Credential getAccountCredentialPublicData(std::string_view accountUUID, uint32_t slotId) override;

        /**
     * @brief getAccountAllCredentialsPublicData Get a map with slotId->public credential data for an account.
     * @param accountUUID account ID or user string.
     * @return map with every defined and not defined password.
     */
        std::map<uint32_t, Credential> getAccountAllCredentialsPublicData(std::string_view accountUUID);

        virtual bool doesCredentialSlotExistOnAccount(std::string_view accountUUID, uint32_t slotId) = 0;

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
        virtual bool changeAccountAuthenticatedCredential(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, uint32_t slotId,
                                                          std::string_view sCurrentPassword, const Credential &newPasswordData, Mode authMode = Mode::PLAIN, std::string_view challengeSalt = "");

        virtual bool removeAccountCredential(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, uint32_t slotId) = 0;

        /////////////////////////////////////////////////////////////////////////////////
        // AuthController Slot SlotIds:
        virtual std::optional<uint32_t> createAuthenticationSlot(const ClientDetails &clientDetails, std::string_view performedBy, const AuthenticationSlotDetails &details) = 0;
        virtual bool removeAuthenticationSlot(const ClientDetails &clientDetails, std::string_view performedBy, const uint32_t &slotId) = 0;
        virtual bool updateAuthenticationSlotDetails(const ClientDetails &clientDetails, std::string_view performedBy, const uint32_t &slotId, const AuthenticationSlotDetails &details) = 0;
        virtual std::map<uint32_t, AuthenticationSlotDetails> listAllAuthenticationSlots() = 0;

        virtual std::optional<uint32_t> createAuthenticationScheme(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view description) = 0;
        virtual bool updateAuthenticationScheme(const ClientDetails &clientDetails, std::string_view performedBy, const uint32_t &schemeId, std::string_view description) = 0;
        virtual bool removeAuthenticationScheme(const ClientDetails &clientDetails, std::string_view performedBy, const uint32_t &schemeId) = 0;
        virtual std::map<uint32_t, std::string> listAuthenticationSchemes() = 0;

        virtual std::vector<AuthenticationSchemeUsedSlot> listAuthenticationSlotsUsedByScheme(const uint32_t &schemeId) = 0;
        virtual bool updateAuthenticationSlotUsedByScheme(const ClientDetails &clientDetails, std::string_view performedBy, const uint32_t &schemeId,
                                                          const std::list<AuthenticationSchemeUsedSlot> &slotsUsedByScheme)
            = 0;
        virtual std::set<uint32_t> listUsedAuthenticationSlotsOnAccount(std::string_view accountUUID) = 0;
        virtual std::map<uint32_t, std::pair<bool, Credential>> listAllAuthCredentialSlotsPublicDataForAccount(std::string_view accountUUID) = 0;

        virtual bool updateDefaultAuthScheme(const ClientDetails &clientDetails, std::string_view performedBy, const uint32_t &schemeId) = 0;
        virtual std::optional<uint32_t> getDefaultAuthScheme() = 0;

        Credential createNewCredential(const uint32_t &slotId, std::string_view passwordInput, bool mustChange = false);

        /**
         * @brief Retrieves the applicable authentication schemes for a user for a specific application activity.
         *
         * This function checks the available authentication schemes for an application activity and determines
         * which schemes are applicable to the user based on the authentication slots the user has.
         *
         * @param app The name of the application.
         * @param activity The name of the activity within the application.
         * @param accountUUID account ID or user string.
         * @return boost::json::value A JSON object containing the applicable authentication schemes, their details, and the default scheme.
         */
        boost::json::value getApplicableAuthenticationSchemesForAccount(std::string_view app, std::string_view activity, std::string_view accountUUID,
                                                                 const std::set<uint32_t> &alreadyAuthenticatedSlots);
    };
    class Applications
    {
    public:
        virtual ~Applications() = default;
        struct ApplicationAttributes
        {
            [[nodiscard]] boost::json::object toJSON() const
            {
                return boost::json::object{
                    {"canAdminModifyApplicationSecurityContext", canAdminModifyApplicationSecurityContext},
                    {"canUserAutoRegister",                      canUserAutoRegister},
                    {"useEmbeddedInPortalAuthentication",        useEmbeddedInPortalAuthentication},
                    {"appSyncEnabled",                           appSyncEnabled},
                    {"appSyncCanRetrieveAppAccountsList",        appSyncCanRetrieveAppAccountsList},
                    {"allowKeepMeSignedIn",                      allowKeepMeSignedIn},
                };
            }

            void fromJSON(const boost::json::value &root)
            {
                canAdminModifyApplicationSecurityContext = Helpers::JSON::ASBOOL(root, "canAdminModifyApplicationSecurityContext", false);
                canUserAutoRegister = Helpers::JSON::ASBOOL(root, "canUserAutoRegister", false);
                appSyncEnabled = Helpers::JSON::ASBOOL(root, "appSyncEnabled", false);
                useEmbeddedInPortalAuthentication = Helpers::JSON::ASBOOL(root, "useEmbeddedInPortalAuthentication", false);
                appSyncCanRetrieveAppAccountsList = Helpers::JSON::ASBOOL(root, "appSyncCanRetrieveAppAccountsList", false);
                allowKeepMeSignedIn = Helpers::JSON::ASBOOL(root, "allowKeepMeSignedIn", false);
            }

            [[nodiscard]] std::string toString() const
            {
                return "adminModifySecurity=" + std::to_string(canAdminModifyApplicationSecurityContext) + ", autoRegister=" + std::to_string(canUserAutoRegister)
                       + ", useEmbeddedInPortalAuth=" + std::to_string(useEmbeddedInPortalAuthentication) + ", syncEnabled=" + std::to_string(appSyncEnabled)
                       + ", syncCanRetrieveAccounts=" + std::to_string(appSyncCanRetrieveAppAccountsList) + ", keepMeSignedIn=" + std::to_string(allowKeepMeSignedIn);
            }
            bool canAdminModifyApplicationSecurityContext = false;
            bool canUserAutoRegister = false;
            bool useEmbeddedInPortalAuthentication = false;
            bool appSyncEnabled = false;
            bool appSyncCanRetrieveAppAccountsList = false;
            bool allowKeepMeSignedIn = false;
        };

        /////////////////////////////////////////////////////////////////////////////////
        // applications:
        virtual bool createApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view applicationDescription,
                                       std::string_view appURL, std::string_view apiKey, std::string_view creatorAccountName, const ApplicationAttributes &appAttributes,
                                       bool initializeDefaultValues)
            = 0;
        virtual bool removeApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName) = 0;
        virtual bool doesApplicationExist(std::string_view appName) = 0;

        virtual std::optional<ApplicationAttributes> getApplicationAttributes(std::string_view appName) = 0;
        virtual bool updateApplicationAttributes(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, const ApplicationAttributes &appAttributes) = 0;

        virtual std::string getApplicationDescription(std::string_view appName) = 0;
        virtual std::string getApplicationAPIKey(std::string_view appName) = 0;
        virtual bool updateApplicationDescription(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view applicationDescription) = 0;
        virtual bool updateApplicationAPIKey(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view apiKey) = 0;
        virtual std::string getApplicationNameByAPIKey(std::string_view apiKey) = 0;

        virtual std::set<std::string> listApplications() = 0;
        virtual bool isApplicationAdmin(std::string_view appName, std::string_view accountUUID) = 0;
        virtual bool validateApplicationAccount(std::string_view appName, std::string_view accountUUID) = 0;
        virtual std::set<std::string> listApplicationAdmins(std::string_view appName) = 0;
        virtual std::set<std::string> listApplicationAccounts(std::string_view appName) = 0;
        virtual std::set<std::string> listAccountApplications(std::string_view accountUUID) = 0;
        virtual bool addAccountToApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view accountUUID) = 0;
        virtual bool removeAccountFromApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view accountUUID) = 0;
        virtual bool setAccountAsApplicationAdmin(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view accountUUID, bool isAppAdmin) = 0;
        virtual boost::json::value searchApplications(const boost::json::value &dataTablesFilters) = 0;

        virtual std::vector<AccountApplicationInfo> listAccountApplicationsFullInfo(std::string_view accountUUID) = 0;

        // Weblogin return urls:
        virtual bool addWebLoginAllowedRedirectURIToApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view loginRedirectURI) = 0;
        virtual bool removeWebLoginAllowedRedirectURIToApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view loginRedirectURI)
            = 0;
        virtual std::set<std::string> listWebLoginAllowedRedirectURIsFromApplication(std::string_view appName) = 0;

        virtual bool updateWebLoginDefaultRedirectURIForApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view loginRedirectURI)
            = 0;
        virtual std::string getWebLoginDefaultRedirectURIForApplication(std::string_view appName) = 0;

        virtual bool setApplicationWebLoginCallbackURI(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view callbackURI) = 0;
        virtual std::string getApplicationCallbackURI(std::string_view appName) = 0;

        // Application admited origin URLS:
        virtual bool addWebLoginOriginURLToApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view originUrl) = 0;
        virtual bool removeWebLoginOriginURLToApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view originUrl) = 0;
        virtual std::set<std::string> listWebLoginOriginUrlsFromApplication(std::string_view appName) = 0;

        // A aplication activity can have multiple authentication schemes...
        // by example, some (special) activities can be: transfer_money, edit_details, and so...
        // Activities can be defined here:

        // Tokens:
        virtual bool updateAuthSettingsForApplication(const ClientDetails &clientDetails, std::string_view performedBy, const ApplicationAuthSettings &tokenInfo) = 0;
        virtual ApplicationAuthSettings getAuthSettingsFromApplication(std::string_view appName) = 0;
        virtual bool setWebLoginJWTSigningKeyForApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view signingKey) = 0;
        virtual std::string getWebLoginJWTSigningKeyForApplication(std::string_view appName) = 0;
        virtual bool setWebLoginJWTValidationKeyForApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view signingKey) = 0;
        virtual std::string getWebLoginJWTValidationKeyForApplication(std::string_view appName) = 0;

        std::shared_ptr<Mantids30::DataFormat::JWT> getAppJWTValidator(std::string_view appName);
        std::shared_ptr<Mantids30::DataFormat::JWT> getAppJWTSigner(std::string_view appName);
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
    bool initializeApplicationWithScheme(std::string_view appName, std::string_view appDescription, std::string_view appURL, const uint32_t &schemeId, bool *alreadyExist) const;

protected:
    std::shared_mutex m_mutex;
};
