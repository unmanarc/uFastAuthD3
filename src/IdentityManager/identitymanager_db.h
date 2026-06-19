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

    void logSecurityEventOnAccounts(const std::string &accountName, SecurityEventAction eventAction, const std::string &description, const std::string &performedBy, const ClientDetails &clientDetails);
    void logSecurityEventOnAccountDetailFields(const std::string &fieldName, SecurityEventAction eventAction, const std::string &eventDescription, const std::string &performedBy,
                                               const ClientDetails &clientDetails);
    void logSecurityEventOnAccountCredentials(const std::string &accountName, uint32_t slotId, SecurityEventAction eventAction, const std::string &eventDescription, const std::string &performedBy,
                                              const ClientDetails &clientDetails);
    void logSecurityEventOnAuthenticationSlots(uint32_t slotId, SecurityEventAction eventAction, const std::string &eventDescription, const std::string &performedBy,
                                               const ClientDetails &clientDetails);
    void logSecurityEventOnAuthenticationSchemes(uint32_t schemeId, SecurityEventAction eventAction, const std::string &eventDescription, const std::string &performedBy,
                                                 const ClientDetails &clientDetails);

    void logSecurityEventOnApplications(const std::string &applicationName, SecurityEventAction eventAction, const std::string &eventDescription, const std::string &performedBy,
                                        const ClientDetails &clientDetails);
    void logSecurityEventOnApplicationRoles(const std::string &applicationName, const std::string &roleName, const std::string &accountName, SecurityEventAction eventAction,
                                            const std::string &eventDescription, const std::string &performedBy, const ClientDetails &clientDetails);
    void logSecurityEventApplicationScopes(const std::string &applicationName, const std::string &scopeName, const std::string &accountName, SecurityEventAction eventAction,
                                           const std::string &eventDescription, const std::string &performedBy, const ClientDetails &clientDetails);
    void logSecurityEventOnApplicationActivities(const std::string &applicationName, const std::string &activityName, std::optional<uint32_t> schemeId, SecurityEventAction eventAction,
                                                 const std::string &eventDescription, const std::string &performedBy, const ClientDetails &clientDetails);

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

        virtual ~Accounts_DB() = default;

        // Account Management
        bool addAccount(const std::string &accountName,
                        time_t expirationDate = 0, // Note: use 1 to create an expired account.
                        const AccountFlags &accountFlags = {true, true, false, false}, const ClientDetails &clientDetails = {}, const std::string &sCreatorAccountName = "") override;

        bool removeAccount(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountName) override;
        bool doesAccountExist(const std::string &accountName) override;
        bool disableAccount(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountName, bool disabled = true) override;
        bool confirmAccount(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountName, const std::string &confirmationToken) override;
        bool changeAccountExpiration(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountName, time_t expiration = 0) override;
        AccountFlags getAccountFlags(const std::string &accountName) override;
        bool changeAccountFlags(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountName, const AccountFlags &accountFlags) override;
        std::optional<AccountDetails> getAccountDetails(const std::string &accountName, const AccountDetailsToShow &detailsToShow) override;
        time_t getAccountExpirationTime(const std::string &accountName) override;
        time_t getAccountCreationTime(const std::string &accountName) override;

        // Account Listing/Search
        Json::Value searchAccounts(const json &dataTablesFilters) override;
        std::set<std::string> listAccounts() override;

        // Application Roles
        bool updateAccountApplicationRoles(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &accountName,
                                           const std::set<std::string> &roleSet) override;
        std::set<ApplicationRole> getAccountApplicationRoles(const std::string &appName, const std::string &accountName, bool lock = true) override;

        // Admin Account
        bool hasAdminAccount() override;

        // Block Token Management
        int32_t getAccountBlockTokenNoRenew(const std::string &accountName, std::string &token);
        void removeBlockToken(const std::string &accountName);
        void updateOrCreateBlockToken(const std::string &accountName);
        std::string getAccountBlockToken(const std::string &accountName) override;
        bool blockAccountUsingToken(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountName, const std::string &blockToken) override;

        // Account Details Fields
        bool addAccountDetailField(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &fieldName, const AccountDetailField &details) override;
        bool updateAccountDetailField(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &fieldName, const AccountDetailField &details) override;
        bool removeAccountDetailField(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &fieldName) override;
        std::map<std::string, AccountDetailField> listAccountDetailFields() override;
        std::optional<AccountDetailField> getAccountDetailField(const std::string &fieldName) override;
        Json::Value searchFields(const json &dataTablesFilters) override;

        // Account Detail Value Operations
        bool changeAccountDetails(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountName, const std::map<std::string, std::string> &fieldsValues,
                                  bool resetAllValues = false) override;
        bool removeAccountDetail(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountName, const std::string &fieldName) override;

        std::map<std::string, AccountDetailFieldValue> getAccountDetailFieldValues(const std::string &accountName, const AccountDetailsToShow &detailsToShow = AccountDetailsToShow::ALL) override;
        bool updateAccountDetailFieldValues(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountName,
                                            const std::list<AccountDetailFieldValue> &inputFieldValues, bool isAdmin) override;

    private:
        bool isThereAnotherAdmin(const std::string &accountName);
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

        virtual ~ApplicationRoles_DB() = default;

        // Role Management
        bool addRole(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &roleName, const std::string &roleDescription) override;
        bool removeRole(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &roleName) override;
        bool doesRoleExist(const std::string &appName, const std::string &roleName) override;
        bool addAccountToRole(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &roleName, const std::string &accountName) override;
        bool removeAccountFromRole(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &roleName, const std::string &accountName,
                                   bool lock = true) override;
        bool updateRoleDescription(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &roleName,
                                   const std::string &roleDescription) override;

        // Role Scopes
        std::set<std::string> listApplicationScopesOnApplicationRole(const std::string &appName, const std::string &roleName) override;

        // Role Metadata
        std::string getApplicationRoleDescription(const std::string &appName, const std::string &roleName) override;
        std::set<ApplicationRole> getApplicationRolesList(const std::string &appName) override;
        std::set<std::string> getApplicationRoleAccounts(const std::string &appName, const std::string &roleName, bool lock = true) override;
        Json::Value searchApplicationRoles(const json &dataTablesFilters) override;

    private:
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

        virtual ~ApplicationActivities_DB() = default;

        bool createLoginActivity() override;

        // Activity Management
        bool addApplicationActivity(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &activityName,
                                    const std::string &activityDescription) override;
        bool removeApplicationActivity(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &activityName) override;
        bool setApplicationActivities(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::map<std::string, ActivityData> &activities) override;
        bool removeAllApplicationActivities(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName) override;
        std::map<std::string, ActivityData> listApplicationActivities(const std::string &appName) override;
        std::optional<ActivityData> getApplicationActivityInfo(const std::string &appName, const std::string &activityName) override;

        // Activity Relations
        bool setApplicationActivityParentActivity(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &activityName,
                                                  const std::string &parentActivityName) override;
        bool setApplicationActivityDescription(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &activityName,
                                               const std::string &description) override;

        // Default Scheme
        std::optional<uint32_t> getApplicationActivityDefaultScheme(const std::string &appName, const std::string &activityName) override;
        bool setApplicationActivityDefaultScheme(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &activityName,
                                                 const uint32_t &schemeId) override;

        // Auth Schemes
        std::set<uint32_t> listAuthenticationSchemesForApplicationActivity(const std::string &appName, const std::string &activityName) override;
        bool addAuthenticationSchemeToApplicationActivity(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &activityName,
                                                          const uint32_t &schemeId, bool lock = true) override;
        bool removeAuthenticationSchemeFromApplicationActivity(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &activityName,
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
        Json::Value searchAccountSessions(const std::string &accountName, const json &dataTablesFilters) override;
        void insertApplicationAccountAccessAuthLog(const std::string &accountName, const std::string &appName, const uint32_t &schemeId, const ClientDetails &clientDetails,
                                                   const std::string &refresherTokenId, const std::string &accessTokenId, const time_t &accessTokenExpiration,
                                                   const time_t &refreshTokenExpiration) override;

        // Application Scopes
        std::set<ApplicationScope> getAccountDirectApplicationScopes(const std::string &accountName, bool lock = true) override;

        bool validateApplicationScopeOnRole(const std::string &roleName, const ApplicationScope &scope, bool lock = true) override;
        std::set<ApplicationScope> getRoleApplicationScopes(const std::string &appName, const std::string &roleName, bool lock = true) override;

        // Scope CRUD Operations
        bool addApplicationScope(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope) override;
        bool removeApplicationScope(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope) override;
        bool doesApplicationScopeExist(const ApplicationScope &applicationScope) override;
        bool addApplicationScopeToRole(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope, const std::string &roleName) override;
        bool removeApplicationScopeFromRole(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope, const std::string &roleName,
                                            bool lock = true) override;
        bool addApplicationScopeToAccount(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope, const std::string &accountName) override;
        bool removeApplicationScopeFromAccount(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope, const std::string &accountName,
                                               bool lock = true) override;
        bool updateApplicationScopeDescription(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationScope &applicationScope) override;
        std::string getApplicationScopeDescription(const ApplicationScope &applicationScope) override;
        std::set<ApplicationScope> listApplicationScopes(const std::string &applicationName = "") override;
        std::set<std::string> getApplicationRolesForScope(const ApplicationScope &applicationScope, bool lock = true) override;
        std::set<std::string> listAccountsOnApplicationScope(const ApplicationScope &applicationScope, bool lock = true) override;
        Json::Value searchApplicationScopes(const json &dataTablesFilters) override;
        bool validateAccountDirectApplicationScope(const std::string &accountName, const ApplicationScope &applicationScope) override;

        // Sessions:
        LastAccountAccessResult getAccountLastAccess(const std::string &accountName) override;
        uint32_t getAccountActiveSessionsCount(const std::string &accountName) override;

        // Token/Logout Handling
        bool updateApplicationAuthLogAccessTokenId(const std::string &accountName, const std::string &appName, const std::string &refresherTokenId, const std::string &accessTokenId,
                                                   const time_t &accessTokenExpiration) override;
        bool logoutApplicationAuthLog(const std::string &accountName, const std::string &appName, const std::string &refresherTokenId, LogoutReason reason) override;

        // Authentication Schemesw
        std::optional<uint32_t> addAuthenticationScheme(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &description) override;
        bool updateAuthenticationScheme(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &schemeId, const std::string &description) override;
        bool removeAuthenticationScheme(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &schemeId) override;
        std::map<uint32_t, std::string> listAuthenticationSchemes() override;
        std::vector<AuthenticationSchemeUsedSlot> listAuthenticationSlotsUsedByScheme(const uint32_t &schemeId) override;
        bool updateAuthenticationSlotUsedByScheme(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &schemeId,
                                                  const std::list<AuthenticationSchemeUsedSlot> &slotsUsedByScheme) override;
        bool updateDefaultAuthScheme(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &schemeId) override;
        std::optional<uint32_t> getDefaultAuthScheme() override;

        ////////////////////////////////////////////////////////////////////////////////////////
        // Account Credentials:
        Credential retrieveAccountCredential(const std::string &accountName, const uint32_t &slotId, bool *accountFound, bool *authSlotFound) override;
        std::pair<uint32_t, uint32_t> getAccountActiveCredentialsCount(const std::string &accountName) override;
        std::set<uint32_t> listUsedAuthenticationSlotsOnAccount(const std::string &accountName) override;
        std::map<uint32_t, std::pair<bool, Credential>> listAllAuthCredentialSlotsPublicDataForAccount(const std::string &accountName) override;
        bool doesCredentialSlotExistOnAccount(const std::string &accountName, uint32_t slotId) override;
        Json::Value searchAccountCredentialsActivity(const std::string &accountName, const json &dataTablesFilters) override;

        void resetBadAttemptsOnAccountCredential(const std::string &accountName, const uint32_t &slotId) override;
        void incrementBadAttemptsOnAccountCredential(const std::string &accountName, const uint32_t &slotId) override;

        bool changeAccountCredential(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountName, Credential passwordData, uint32_t slotId) override;
        bool activateAccountCredential(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountName, uint32_t slotId, const std::string &hash,
                                       const std::string &ssalt) override;
        bool setCredentialMustChange(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountName, uint32_t slotId, bool mustChange) override;
        bool setCredentialLockedStatus(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountName, uint32_t slotId, bool isLocked) override;
        bool removeAccountCredential(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountName, uint32_t slotId) override;

        void insertAccountAuthCredentialSlotLog(const std::string &accountName, uint32_t slotId, const ClientDetails &clientDetails, int logStatus) override;
        ////////////////////////////////////////////////////////////////////////////////////////

        // Auth Slot Management
        std::optional<uint32_t> addNewAuthenticationSlot(const ClientDetails &clientDetails, const std::string &performedBy, const AuthenticationSlotDetails &details) override;
        bool removeAuthenticationSlot(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &slotId) override;
        bool updateAuthenticationSlotDetails(const ClientDetails &clientDetails, const std::string &performedBy, const uint32_t &slotId, const AuthenticationSlotDetails &details) override;
        std::map<uint32_t, AuthenticationSlotDetails> listAllAuthenticationSlots() override;

        // Tokens
        std::string getAccountConfirmationToken(const std::string &accountName) override;

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

        virtual ~Applications_DB() = default;

        // Application CRUD Operations
        bool addApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &applicationDescription, const std::string &appURL,
                            const std::string &apiKey, const std::string &creatorAccountName, const ApplicationAttributes &appAttributes, bool initializeDefaultValues) override;

        bool removeApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName) override;
        bool doesApplicationExist(const std::string &appName) override;

        // Application Metadata
        std::optional<ApplicationAttributes> getApplicationAttributes(const std::string &appName) override;
        bool updateApplicationAttributes(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const ApplicationAttributes &appAttributes) override;

        std::string getApplicationDescription(const std::string &appName) override;
        std::string getApplicationAPIKey(const std::string &appName) override;
        bool updateApplicationAPIKey(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &apiKey) override;
        bool updateApplicationDescription(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &applicationDescription) override;
        std::string getApplicationNameByAPIKey(const std::string &apiKey) override;

        // Application Lists
        std::set<std::string> listApplications() override;
        bool isApplicationAdmin(const std::string &appName, const std::string &accountName) override;
        bool validateApplicationAccount(const std::string &appName, const std::string &accountName) override;
        std::set<std::string> listApplicationAdmins(const std::string &appName) override;
        std::set<std::string> listApplicationAccounts(const std::string &appName) override;
        std::set<std::string> listAccountApplications(const std::string &accountName) override;
        bool addAccountToApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &accountName) override;
        bool removeAccountFromApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &accountName) override;
        bool changeApplicationAdmin(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &accountName, bool isAppAdmin) override;

        // Search
        Json::Value searchApplications(const json &dataTablesFilters) override;

        // Full Account Application Info
        std::vector<AccountApplicationInfo> listAccountApplicationsFullInfo(const std::string &accountName) override;

        // Redirect URIs
        bool addWebLoginAllowedRedirectURIToApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &loginRedirectURI) override;
        bool removeWebLoginAllowedRedirectURIToApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &loginRedirectURI) override;
        std::set<std::string> listWebLoginAllowedRedirectURIsFromApplication(const std::string &appName) override;
        bool updateWebLoginDefaultRedirectURIForApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName,
                                                            const std::string &loginRedirectURI) override;
        std::string getWebLoginDefaultRedirectURIForApplication(const std::string &appName) override;

        // Callback URI
        bool setApplicationWebLoginCallbackURI(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &callbackURI) override;
        std::string getApplicationCallbackURI(const std::string &appName) override;

        // Origin URLs
        bool addWebLoginOriginURLToApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &originUrl) override;
        bool removeWebLoginOriginURLToApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &originUrl) override;
        std::set<std::string> listWebLoginOriginUrlsFromApplication(const std::string &appName) override;

        // JWT Token Config
        bool updateWebLoginJWTConfigForApplication(const ClientDetails &clientDetails, const std::string &performedBy, const ApplicationTokenProperties &tokenInfo) override;
        ApplicationTokenProperties getWebLoginJWTConfigFromApplication(const std::string &appName) override;
        bool setWebLoginJWTSigningKeyForApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &signingKey) override;
        std::string getWebLoginJWTSigningKeyForApplication(const std::string &appName) override;
        bool setWebLoginJWTValidationKeyForApplication(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &appName, const std::string &validationKey) override;
        std::string getWebLoginJWTValidationKeyForApplication(const std::string &appName) override;

    private:
        IdentityManager_DB *_parent;
    };

    // SQL Error Handling
    std::list<std::string> getSqlErrorList() const;
    void clearSQLErrorList();

private:
    std::list<std::string> m_sqlErrorList;
    Mantids30::Database::SQLConnector *m_sqlConnector;
};
