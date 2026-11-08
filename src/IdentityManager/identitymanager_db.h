#pragma once

#include "IdentityManager/credentialvalidator.h"
#include "identitymanager.h"
#include <Mantids30/DB/sqlconnector.h>
#include <optional>

class IdentityManager_DB : public IdentityManager
{
public:
    IdentityManager_DB(Mantids30::Database::SQLConnector *_SQLDirConnection);
    bool initializeDatabase() override;

    void logSecurityEventOnAccounts(std::string_view accountUUID, SecurityEventAction eventAction, std::string_view description, std::string_view performedBy, const ClientDetails &clientDetails);
    void logSecurityEventOnAccountDetailFields(std::string_view fieldName, SecurityEventAction eventAction, std::string_view eventDescription, std::string_view performedBy,
                                               const ClientDetails &clientDetails);
    void logSecurityEventOnAccountCredentials(std::string_view accountUUID, uint32_t slotId, SecurityEventAction eventAction, std::string_view eventDescription, std::string_view performedBy,
                                              const ClientDetails &clientDetails);
    void logSecurityEventOnAuthenticationSlots(uint32_t slotId, SecurityEventAction eventAction, std::string_view eventDescription, std::string_view performedBy,
                                               const ClientDetails &clientDetails);
    void logSecurityEventOnAuthenticationSchemes(uint32_t schemeId, SecurityEventAction eventAction, std::string_view eventDescription, std::string_view performedBy,
                                                 const ClientDetails &clientDetails);
    void logSecurityEventOnApplications(std::string_view applicationName, SecurityEventAction eventAction, std::string_view eventDescription, std::string_view performedBy,
                                        const ClientDetails &clientDetails);
    void logSecurityEventOnApplicationRoles(std::string_view applicationName, std::string_view roleName, std::string_view accountUUID, SecurityEventAction eventAction,
                                            std::string_view eventDescription, std::string_view performedBy, const ClientDetails &clientDetails);
    void logSecurityEventApplicationScopes(std::string_view applicationName, std::string_view scopeName, std::string_view accountUUID, SecurityEventAction eventAction,
                                           std::string_view eventDescription, std::string_view performedBy, const ClientDetails &clientDetails);
    void logSecurityEventOnApplicationActivities(std::string_view applicationName, std::string_view activityName, std::optional<uint32_t> schemeId, SecurityEventAction eventAction,
                                                 std::string_view eventDescription, std::string_view performedBy, const ClientDetails &clientDetails);

    /////////////////////////////////////////////////////////////////////////////////
    // Accounts DB Class
    class Accounts_DB : public Accounts
    {
    public:
        Accounts_DB(IdentityManager_DB *parent)
            : Accounts(parent)
        {
            _parent = parent;
        }

        ~Accounts_DB() override = default;

        // Friend declarations to access private methods of other DB classes
        friend class Applications_DB;
        friend class ApplicationRoles_DB;
        friend class ApplicationScopes_DB;

        bool extendInactivity(std::string_view accountUUID, const time_t &validUntil) override;

        // Account Management
        CreateAccountResult createAccount(time_t expirationDate, // Note: use 1 to create an expired account.
                                          const AccountFlags &accountFlags, const ClientDetails &clientDetails, std::string_view performedBy, const std::map<std::string, ApplicationDef> &appDefs,
                                          const std::map<std::string, std::string> &detailFieldsValues) override;

        bool removeAccount(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID) override;
        bool doesAccountExist(std::string_view accountUUID) override;
        bool disableAccount(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, bool disabled = true) override;
        bool confirmAccount(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, std::string_view confirmationToken) override;
        bool changeAccountExpiration(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, time_t expiration = 0) override;
        AccountFlags getAccountFlags(std::string_view accountUUID) override;
        bool changeAccountFlags(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, const AccountFlags &accountFlags) override;
        std::optional<AccountDetails> getAccountDetails(std::string_view accountUUID, const AccountDetailsToShow &detailsToShow) override;
        time_t getAccountExpirationTime(std::string_view accountUUID) override;
        time_t getAccountCreationTime(std::string_view accountUUID) override;

        // Account Listing/Search
        boost::json::value searchAccounts(const boost::json::value &dataTablesFilters) override;
        std::set<std::string> listAccounts() override;
        std::set<std::string> listAdminAccounts() override;
        std::optional<std::string> getAccountUUIDByAccountName(std::string_view accountName) override;
        std::set<std::string> getAccountNamesByAccountUUID(std::string_view accountUUID) override;
        std::string getAccountDisplayName(std::string_view accountUUID) override;

        // Application Roles
        bool updateAccountApplicationRoles(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view accountUUID,
                                           const std::set<std::string> &roleSet) override;
        std::set<ApplicationRole> getAccountApplicationRoles(std::string_view appName, std::string_view accountUUID, bool lock = true) override;

        // Admin Account
        bool hasValidAdminAccount() override;

        // Block Token Management
        int32_t getAccountBlockTokenNoRenew(std::string_view accountUUID, std::string &token);
        void removeBlockToken(std::string_view accountUUID);
        void updateOrCreateBlockToken(std::string_view accountUUID);
        std::string getAccountBlockToken(std::string_view accountUUID) override;
        bool blockAccountUsingToken(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, std::string_view blockToken) override;

        // Account Details Fields
        bool createAccountDetailField(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view fieldName, const AccountDetailField &details) override;
        UpdateAccountDetailFieldResult updateAccountDetailField(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view fieldName,
                                                                const AccountDetailField &details) override;
        RemoveAccountDetailFieldResult removeAccountDetailField(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view fieldName) override;
        std::map<std::string, AccountDetailField> listAccountDetailFields() override;
        std::optional<AccountDetailField> getAccountDetailField(std::string_view fieldName) override;
         boost::json::value searchFields(const boost::json::value &dataTablesFilters) override;

         // Account Detail Fields Order Priority
         bool moveAccountDetailFieldUp(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view fieldName) override;
         bool moveAccountDetailFieldDown(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view fieldName) override;

         // Account Detail Value Operations
        bool changeAccountDetails(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, const std::map<std::string, std::string> &fieldsValues,
                                  bool resetAllValues = false) override;
        bool removeAccountDetail(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, std::string_view fieldName) override;

        std::map<std::string, AccountDetailFieldValue> getAccountDetailFieldValues(std::string_view accountUUID, const AccountDetailsToShow &detailsToShow = AccountDetailsToShow::ALL) override;
        UpdateAccountDetailFieldValuesResult updateAccountDetailFieldValues(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID,
                                                                            const std::map<std::string, std::string> &inputFieldValues, bool isAdmin) override;

    private:
        std::map<std::string, AccountDetailField> _listAccountDetailFields();
        UpdateAccountDetailFieldValuesResult _updateAccountDetailFieldValues(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID,
                                                                              const std::map<std::string, std::string> &inputFieldValues, bool isAdmin);
        void _reorderAccountDetailFields();
        bool isThereAnotherAdmin(std::string_view accountUUID);
        IdentityManager_DB *_parent;
    };

    class ApplicationScopes_DB : public ApplicationScopes

    {
    public:
        ApplicationScopes_DB(IdentityManager_DB *parent)
            : ApplicationScopes(parent)
        {
            _parent = parent;
        }
        ~ApplicationScopes_DB() override = default;

        // Friend declaration to allow Accounts_DB to access private methods
        friend class Accounts_DB;

        // Application Scopes
        std::set<ApplicationScope> getAccountDirectApplicationScopes(std::string_view accountUUID, bool lock = true) override;

        bool validateApplicationScopeOnRole(std::string_view roleName, const ApplicationScope &scope, bool lock = true) override;
        std::set<ApplicationScope> getRoleApplicationScopes(std::string_view appName, std::string_view roleName, bool lock = true) override;

        // Scope CRUD Operations
        bool createApplicationScope(const ClientDetails &clientDetails, std::string_view performedBy, const ApplicationScope &applicationScope) override;
        bool removeApplicationScope(const ClientDetails &clientDetails, std::string_view performedBy, const ApplicationScope &applicationScope) override;
        bool doesApplicationScopeExist(const ApplicationScope &applicationScope) override;
        bool addApplicationScopeToRole(const ClientDetails &clientDetails, std::string_view performedBy, const ApplicationScope &applicationScope, std::string_view roleName) override;
        bool removeApplicationScopeFromRole(const ClientDetails &clientDetails, std::string_view performedBy, const ApplicationScope &applicationScope, std::string_view roleName,
                                            bool lock = true) override;
        bool addApplicationScopeToAccount(const ClientDetails &clientDetails, std::string_view performedBy, const ApplicationScope &applicationScope, std::string_view accountUUID) override;
        bool removeApplicationScopeFromAccount(const ClientDetails &clientDetails, std::string_view performedBy, const ApplicationScope &applicationScope, std::string_view accountUUID,
                                               bool lock = true) override;
        bool updateApplicationScopeDescription(const ClientDetails &clientDetails, std::string_view performedBy, const ApplicationScope &applicationScope) override;
        std::string getApplicationScopeDescription(const ApplicationScope &applicationScope) override;
        std::set<ApplicationScope> listApplicationScopes(std::string_view applicationName = "") override;
        std::set<std::string> getApplicationRolesForScope(const ApplicationScope &applicationScope, bool lock = true) override;
        std::set<std::string> listAccountsOnApplicationScope(const ApplicationScope &applicationScope, bool lock = true) override;
        boost::json::value searchApplicationScopes(const boost::json::value &dataTablesFilters) override;
        bool validateAccountDirectApplicationScope(std::string_view accountUUID, const ApplicationScope &applicationScope) override;

    private:
        bool _addApplicationScopeToAccount(const ClientDetails &clientDetails, std::string_view performedBy, const ApplicationScope &applicationScope, std::string_view accountUUID);
        IdentityManager_DB *_parent;
    };

    /////////////////////////////////////////////////////////////////////////////////
    // Application Roles DB Class
    class ApplicationRoles_DB : public ApplicationRoles
    {
    public:
        ApplicationRoles_DB(IdentityManager_DB *parent)
            : ApplicationRoles()
        {
            _parent = parent;
        }

        ~ApplicationRoles_DB() override = default;

        // Friend declaration to allow Accounts_DB to access private methods
        friend class Accounts_DB;

        // Role Management
        bool createRole(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view roleName, std::string_view roleDescription) override;
        bool removeRole(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view roleName) override;
        bool doesRoleExist(std::string_view appName, std::string_view roleName) override;
        bool addAccountToRole(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view roleName, std::string_view accountUUID) override;
        bool removeAccountFromRole(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view roleName, std::string_view accountUUID,
                                   bool lock = true) override;
        bool updateRoleDescription(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view roleName,
                                   std::string_view roleDescription) override;

        // Role Scopes
        std::set<std::string> listApplicationScopesOnApplicationRole(std::string_view appName, std::string_view roleName) override;

        // Role Metadata
        std::string getApplicationRoleDescription(std::string_view appName, std::string_view roleName) override;
        std::set<ApplicationRole> getApplicationRolesList(std::string_view appName) override;
        std::set<std::string> getApplicationRoleAccounts(std::string_view appName, std::string_view roleName, bool lock = true) override;
        boost::json::value searchApplicationRoles(const boost::json::value &dataTablesFilters) override;

    private:
        bool _addAccountToRole(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view roleName, std::string_view accountUUID);
        IdentityManager_DB *_parent;
    };

    /////////////////////////////////////////////////////////////////////////////////
    // Application Activities DB Class
    class ApplicationActivities_DB : public ApplicationActivities
    {
    public:
        ApplicationActivities_DB(IdentityManager_DB *parent)
            : ApplicationActivities()
        {
            _parent = parent;
        }

        ~ApplicationActivities_DB() override = default;

        bool createLoginActivity() override;

        // Activity Management
        bool createApplicationActivity(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view activityName,
                                       std::string_view activityDescription) override;
        bool removeApplicationActivity(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view activityName) override;
        bool setApplicationActivities(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, const std::map<std::string, ActivityData> &activities) override;
        bool removeAllApplicationActivities(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName) override;
        std::map<std::string, ActivityData> listApplicationActivities(std::string_view appName) override;
        std::optional<ActivityData> getApplicationActivityInfo(std::string_view appName, std::string_view activityName) override;

        // Activity Relations
        bool setApplicationActivityParentActivity(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view activityName,
                                                  std::string_view parentActivityName) override;
        bool setApplicationActivityDescription(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view activityName,
                                               std::string_view description) override;

        // Default Scheme
        std::optional<uint32_t> getApplicationActivityDefaultScheme(std::string_view appName, std::string_view activityName) override;
        bool setApplicationActivityDefaultScheme(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view activityName,
                                                 const uint32_t &schemeId) override;

        // Auth Schemes
        std::set<uint32_t> listAuthenticationSchemesForApplicationActivity(std::string_view appName, std::string_view activityName) override;
        bool addAuthenticationSchemeToApplicationActivity(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view activityName,
                                                          const uint32_t &schemeId, bool lock = true) override;
        bool removeAuthenticationSchemeFromApplicationActivity(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view activityName,
                                                               const uint32_t &schemeId) override;

    private:
        IdentityManager_DB *_parent;
    };

    /////////////////////////////////////////////////////////////////////////////////
    // Auth Controller DB Class
    class AuthController_DB : public AuthController
    {
    public:
        AuthController_DB(IdentityManager_DB *parent)
            : AuthController(parent)
        {
            _parent = parent;
        }

        // Session Handling
        void markExpiredAuthLogSessions() override;
        boost::json::value searchAccountSessions(std::string_view accountUUID, const boost::json::value &dataTablesFilters) override;
        void insertApplicationAccountAccessAuthLog(std::string_view accountUUID, std::string_view appName, const uint32_t &schemeId, const ClientDetails &clientDetails,
                                                   std::string_view refresherTokenId, std::string_view accessTokenId, const time_t &accessTokenExpiration,
                                                   const time_t &refreshTokenExpiration) override;

        // Sessions:
        LastAccountAccessResult getAccountLastAccess(std::string_view accountUUID) override;
        uint32_t getAccountActiveSessionsCount(std::string_view accountUUID) override;

        // Token/Logout Handling
        bool updateApplicationAuthLogAccessTokenId(std::string_view accountUUID, std::string_view appName, std::string_view refresherTokenId, std::string_view accessTokenId,
                                                   const time_t &accessTokenExpiration) override;
        bool logoutApplicationAuthLog(std::string_view accountUUID, std::string_view appName, std::string_view refresherTokenId, LogoutReason reason) override;

        // Authentication Schemesw
        std::optional<uint32_t> createAuthenticationScheme(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view description) override;
        bool updateAuthenticationScheme(const ClientDetails &clientDetails, std::string_view performedBy, const uint32_t &schemeId, std::string_view description) override;
        bool removeAuthenticationScheme(const ClientDetails &clientDetails, std::string_view performedBy, const uint32_t &schemeId) override;
        std::map<uint32_t, std::string> listAuthenticationSchemes() override;
        std::vector<AuthenticationSchemeUsedSlot> listAuthenticationSlotsUsedByScheme(const uint32_t &schemeId) override;
        bool updateAuthenticationSlotUsedByScheme(const ClientDetails &clientDetails, std::string_view performedBy, const uint32_t &schemeId,
                                                  const std::list<AuthenticationSchemeUsedSlot> &slotsUsedByScheme) override;
        bool updateDefaultAuthScheme(const ClientDetails &clientDetails, std::string_view performedBy, const uint32_t &schemeId) override;
        std::optional<uint32_t> getDefaultAuthScheme() override;

        ////////////////////////////////////////////////////////////////////////////////////////
        // Account Credentials:
        Credential retrieveAccountCredential(std::string_view accountUUID, const uint32_t &slotId, bool *accountFound, bool *authSlotFound) override;
        std::pair<uint32_t, uint32_t> getAccountActiveCredentialsCount(std::string_view accountUUID) override;
        std::set<uint32_t> listUsedAuthenticationSlotsOnAccount(std::string_view accountUUID) override;
        std::map<uint32_t, std::pair<bool, Credential>> listAllAuthCredentialSlotsPublicDataForAccount(std::string_view accountUUID) override;
        bool doesCredentialSlotExistOnAccount(std::string_view accountUUID, uint32_t slotId) override;
        boost::json::value searchAccountCredentialsActivity(std::string_view accountUUID, const boost::json::value &dataTablesFilters) override;

        void resetBadAttemptsOnAccountCredential(std::string_view accountUUID, const uint32_t &slotId) override;
        void incrementBadAttemptsOnAccountCredential(std::string_view accountUUID, const uint32_t &slotId) override;

        bool changeAccountCredential(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, Credential passwordData, uint32_t slotId) override;
        bool activateAccountCredential(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, uint32_t slotId, std::string_view hash,
                                       std::string_view ssalt) override;
        bool setAccountCredentialMustChange(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, uint32_t slotId, bool mustChange) override;
        bool setAccountCredentialLockedStatus(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, uint32_t slotId, bool isLocked) override;
        bool removeAccountCredential(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view accountUUID, uint32_t slotId) override;

        void insertAccountAuthCredentialSlotLog(std::string_view accountUUID, uint32_t slotId, const ClientDetails &clientDetails, int logStatus) override;
        ////////////////////////////////////////////////////////////////////////////////////////

        // Auth Slot Management
        std::optional<uint32_t> createAuthenticationSlot(const ClientDetails &clientDetails, std::string_view performedBy, const AuthenticationSlotDetails &details) override;
        bool removeAuthenticationSlot(const ClientDetails &clientDetails, std::string_view performedBy, const uint32_t &slotId) override;
        bool updateAuthenticationSlotDetails(const ClientDetails &clientDetails, std::string_view performedBy, const uint32_t &slotId, const AuthenticationSlotDetails &details) override;
        std::map<uint32_t, AuthenticationSlotDetails> listAllAuthenticationSlots() override;

        // Tokens
        std::string getAccountConfirmationToken(std::string_view accountUUID) override;

        IdentityManager_DB *_parent;
    };

    /////////////////////////////////////////////////////////////////////////////////
    // Applications DB Class
    class Applications_DB : public Applications
    {
    public:
        Applications_DB(IdentityManager_DB *parent)
            : Applications()
        {
            _parent = parent;
        }

        ~Applications_DB() override = default;

        // Friend declaration to allow Accounts_DB to access private methods
        friend class Accounts_DB;

        // Application CRUD Operations
        bool createApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view applicationDescription, std::string_view appURL,
                               std::string_view apiKey, std::string_view creatorAccountUUID, const ApplicationAttributes &appAttributes, bool initializeDefaultValues) override;

        bool removeApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName) override;
        bool doesApplicationExist(std::string_view appName) override;

        // Application Metadata
        std::optional<ApplicationAttributes> getApplicationAttributes(std::string_view appName) override;
        bool updateApplicationAttributes(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, const ApplicationAttributes &appAttributes) override;

        std::string getApplicationDescription(std::string_view appName) override;
        std::string getApplicationAPIKey(std::string_view appName) override;
        bool updateApplicationAPIKey(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view apiKey) override;
        bool updateApplicationDescription(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view applicationDescription) override;
        std::string getApplicationNameByAPIKey(std::string_view apiKey) override;

        // Application Lists
        std::set<std::string> listApplications() override;
        bool isApplicationAdmin(std::string_view appName, std::string_view accountUUID) override;
        bool validateApplicationAccount(std::string_view appName, std::string_view accountUUID) override;
        std::set<std::string> listApplicationAdmins(std::string_view appName) override;
        std::set<std::string> listApplicationAccounts(std::string_view appName) override;
        std::set<std::string> listAccountApplications(std::string_view accountUUID) override;
        bool addAccountToApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view accountUUID) override;
        bool removeAccountFromApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view accountUUID) override;
        bool setAccountAsApplicationAdmin(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view accountUUID, bool isAppAdmin) override;

        // Search
        boost::json::value searchApplications(const boost::json::value &dataTablesFilters) override;

        // Full Account Application Info
        std::vector<AccountApplicationInfo> listAccountApplicationsFullInfo(std::string_view accountUUID) override;

        // Redirect URIs
        bool addWebLoginAllowedRedirectURIToApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view loginRedirectURI) override;
        bool removeWebLoginAllowedRedirectURIToApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view loginRedirectURI) override;
        std::set<std::string> listWebLoginAllowedRedirectURIsFromApplication(std::string_view appName) override;
        bool updateWebLoginDefaultRedirectURIForApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName,
                                                            std::string_view loginRedirectURI) override;
        std::string getWebLoginDefaultRedirectURIForApplication(std::string_view appName) override;

        // Callback URI
        bool setApplicationWebLoginCallbackURI(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view callbackURI) override;
        std::string getApplicationCallbackURI(std::string_view appName) override;

        // Origin URLs
        bool addWebLoginOriginURLToApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view originUrl) override;
        bool removeWebLoginOriginURLToApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view originUrl) override;
        std::set<std::string> listWebLoginOriginUrlsFromApplication(std::string_view appName) override;

        // JWT Token Config
        bool updateAuthSettingsForApplication(const ClientDetails &clientDetails, std::string_view performedBy, const ApplicationAuthSettings &tokenInfo) override;
        ApplicationAuthSettings getAuthSettingsFromApplication(std::string_view appName) override;
        bool setWebLoginJWTSigningKeyForApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view signingKey) override;
        std::string getWebLoginJWTSigningKeyForApplication(std::string_view appName) override;
        bool setWebLoginJWTValidationKeyForApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view validationKey) override;
        std::string getWebLoginJWTValidationKeyForApplication(std::string_view appName) override;

    private:
        bool _setAccountAsApplicationAdmin(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view accountUUID, bool isAppAdmin);
        bool _addAccountToApplication(const ClientDetails &clientDetails, std::string_view performedBy, std::string_view appName, std::string_view accountUUID);
        IdentityManager_DB *_parent;
    };

    // SQL Error Handling
    [[nodiscard]] std::list<std::string> getSqlErrorList() const;
    void clearSQLErrorList();

private:
    std::list<std::string> m_sqlErrorList;
    Mantids30::Database::SQLConnector *m_sqlConnector;
};
