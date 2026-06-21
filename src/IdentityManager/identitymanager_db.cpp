#include "identitymanager_db.h"
#include "Mantids30/Memory/a_int32.h"
#include "Mantids30/Memory/a_string.h"
#include "Mantids30/Memory/a_uint32.h"
#include "ds_security_events.h"
#include "globals.h"

using namespace Mantids30::Program;
using namespace Mantids30;

IdentityManager_DB::IdentityManager_DB(Mantids30::Database::SQLConnector *_SQLDirConnection)
{
    applications = new Applications_DB(this);
    accounts = new Accounts_DB(this);
    applicationRoles = new ApplicationRoles_DB(this);
    applicationActivities = new ApplicationActivities_DB(this);
    authController = new AuthController_DB(this);

    m_sqlConnector = _SQLDirConnection;
    //    m_sqlConnector->setThrowCPPErrorOnQueryFailure(true);
}

bool IdentityManager_DB::initializeDatabase()
{
    const std::vector<std::string_view> sqlStatements = {
        R"(CREATE TABLE IF NOT EXISTS `iam`.`accounts` (
                                             `accountName`              VARCHAR(256)    NOT NULL,
                                             `creation`              DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                             `creator`               VARCHAR(256)    DEFAULT NULL,
                                             `expiration`            DATETIME        NOT NULL,
                                             `isAdmin`               BOOLEAN         NOT NULL,
                                             `isEnabled`             BOOLEAN         NOT NULL,
                                             `isBlocked`             BOOLEAN         NOT NULL,
                                             `isAccountConfirmed`    BOOLEAN         NOT NULL,
                                             PRIMARY KEY(`accountName`)
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`inactivityExtensions` (
                                               `accountName` VARCHAR(256) NOT NULL,
                                               `validUntil` DATETIME NOT NULL,
                                               PRIMARY KEY(`accountName`),
                                               FOREIGN KEY(`accountName`) REFERENCES accounts(`accountName`) ON DELETE CASCADE
                                           );)",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`accountDetailFields` (
                                             `fieldName`                     VARCHAR(256)   NOT NULL,
                                             `fieldDescription`              VARCHAR(4096)  NOT NULL,
                                             `fieldType`                     VARCHAR(256)   NOT NULL DEFAULT 'TEXTLINE',
                                             `isUnique`                      BOOLEAN        NOT NULL DEFAULT FALSE,
                                             `isOptionalField`               BOOLEAN        NOT NULL DEFAULT TRUE,
                                             `jsonExtendedAttribs`           TEXT           DEFAULT NULL,
                                             `orderPriority`                 INTEGER        NOT NULL,
                                              PRIMARY KEY(`fieldName`)
                                                                        );
                                       )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`accountDetailValues` (
                                              `f_accountName`           VARCHAR(256)  NOT NULL,
                                              `f_fieldName`             VARCHAR(256)  NOT NULL,
                                              `value`                   TEXT DEFAULT NULL,
                                              `lastUpdate`              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                              FOREIGN KEY(`f_accountName`)   REFERENCES accounts(`accountName`) ON DELETE CASCADE
                                              PRIMARY KEY(`f_accountName`,`f_fieldName`)
                                                                        );
                                       )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applications` (
                                              `appName`                                      VARCHAR(256)  NOT NULL,
                                              `f_appCreator`                                 VARCHAR(256)  NOT NULL,
                                              `appDescription`                               VARCHAR(4096) NOT NULL,
                                              `apiKey`                                       VARCHAR(512)  NOT NULL,
                                              `appAttributesJSON`                            TEXT NOT NULL DEFAULT '{"canAdminModifyApplicationSecurityContext":false,"canUserAutoRegister":false,"useEmbeddedAuthentication":false,"appSyncEnabled":true,"appSyncCanRetrieveAppAccountsList":true,"allowKeepMeSignedIn":false}',
                                              `appIcon`                                      BLOB DEFAULT NULL,
                                              `appLogo`                                      BLOB DEFAULT NULL,
                                               FOREIGN KEY(`f_appCreator`) REFERENCES accounts(`accountName`) ON DELETE CASCADE
                                               PRIMARY KEY(`appName`)
                                               UNIQUE(`apiKey`)
                                                                         );
                                     )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationsWebLoginAllowedRedirectURIs` (
                                             `f_appName`             VARCHAR(256)  NOT NULL,
                                             `loginRedirectURI`        VARCHAR(4096) NOT NULL,
                                              FOREIGN KEY(`f_appName`)   REFERENCES applications(`appName`) ON DELETE CASCADE
                                              PRIMARY KEY(`f_appName`,`loginRedirectURI`)
                                                                        );
                                    )",

        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationsWebLoginDefaultRedirectURI` (
                                             `f_appName`             VARCHAR(256)  NOT NULL,
                                             `f_loginRedirectURI`      VARCHAR(4096) NOT NULL,
                                             `lastUpdated`           DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                             PRIMARY KEY(`f_appName`),
                                             FOREIGN KEY(`f_appName`)   REFERENCES applications(`appName`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_appName`,`f_loginRedirectURI`) REFERENCES applicationsWebLoginAllowedRedirectURIs(`f_appName`,`loginRedirectURI`) ON DELETE CASCADE
                                                                        );
                                    )",

        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationsLoginCallbackURI` (
                                             `f_appName`             VARCHAR(256)  NOT NULL,
                                             `callbackURI`           VARCHAR(4096) NOT NULL,
                                              FOREIGN KEY(`f_appName`)   REFERENCES applications(`appName`) ON DELETE CASCADE,
                                              PRIMARY KEY(`f_appName`,`callbackURI`)
                                              UNIQUE(`f_appName`)
                     );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationActivities` (
                                             `f_appName`             VARCHAR(256)  NOT NULL,
                                             `activityName`          VARCHAR(256)  NOT NULL,
                                             `parentActivity`        VARCHAR(256)  DEFAULT NULL,
                                             `description`           VARCHAR(4096) NOT NULL,
                                             `defaultSchemeId` INTEGER DEFAULT NULL,
                                              FOREIGN KEY(`f_appName`)   REFERENCES applications(`appName`) ON DELETE CASCADE
                                              PRIMARY KEY(`f_appName`,`activityName`)
                     );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationsWebLoginOrigins` (
                                             `f_appName`             VARCHAR(256)  NOT NULL,
                                             `originUrl`              VARCHAR(2048) NOT NULL,
                                             FOREIGN KEY(`f_appName`)   REFERENCES applications(`appName`) ON DELETE CASCADE
                                             PRIMARY KEY(`f_appName`,`originUrl`)
                                                                        );
                                        )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationsJWTTokenConfig` (
                                            `f_appName`                       VARCHAR(256)    NOT NULL,
                                            `sessionInactivityTimeout`        BIGINT UNSIGNED NOT NULL DEFAULT '180',
                                            `tokenType`                       VARCHAR(20)     NOT NULL DEFAULT 'HS256',
                                            `accessTokenSigningKey`           TEXT DEFAULT NULL,
                                            `accessTokenValidationKey`        TEXT DEFAULT NULL,
                                            `tokensConfigJSON`                TEXT NOT NULL DEFAULT '{ "accessToken" : { useSessionCookiesByDefault : true, "path" : "/", "timeout" : 300},"refreshToken" : {"path" : "/auth", "timeout" : 2592000} }',
                                            `includeApplicationScopes`        BOOLEAN NOT NULL DEFAULT TRUE,
                                            `includeBasicAccountInfo`         BOOLEAN NOT NULL DEFAULT TRUE,
                                            `maintainRevocationAndLogoutInfo` BOOLEAN NOT NULL DEFAULT FALSE,
                                            `allowRefreshTokenRenovation`     BOOLEAN NOT NULL DEFAULT TRUE,
                                            FOREIGN KEY (`f_appName`) REFERENCES applications(`appName`) ON DELETE CASCADE,
                                            PRIMARY KEY (`f_appName`)
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationScopes` (
                                             `f_appName`               VARCHAR(256) NOT NULL,
                                             `scopeId`            VARCHAR(256) NOT NULL,
                                             `description`     VARCHAR(4096),
                                             PRIMARY KEY(`f_appName`,`scopeId`),
                                             FOREIGN KEY(`f_appName`)   REFERENCES applications(`appName`) ON DELETE CASCADE
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationAccounts` (
                                             `f_accountName`       VARCHAR(256)    NOT NULL,
                                             `f_appName`           VARCHAR(256)    NOT NULL,
                                             `isAppAdmin`          BOOLEAN NOT NULL DEFAULT FALSE,
                                             `enrollmentDate`      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                             PRIMARY KEY(`f_accountName`,`f_appName`),
                                             FOREIGN KEY(`f_accountName`) REFERENCES accounts(`accountName`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_appName`)  REFERENCES applications(`appName`) ON DELETE CASCADE
                                                                        );
                                    )",

        R"(CREATE TABLE IF NOT EXISTS `iam`.`authenticationSchemes` (
                                            `schemeId`          INTEGER PRIMARY KEY AUTOINCREMENT,
                                            `description`       VARCHAR(4096) NOT NULL
                     );     )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`defaultAuthScheme` (
                                             `id` INTEGER PRIMARY KEY DEFAULT 1,
                                             `f_defaultSchemeId` INTEGER NOT NULL,
                                             `lastUpdated` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (`f_defaultSchemeId`) REFERENCES `authenticationSchemes`(`schemeId`) ON DELETE CASCADE,
            CHECK (`id` = 1)
            );)",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationActivitiesAuthSchemes` (
                                             `f_appName`             VARCHAR(256)  NOT NULL,
                                             `f_activityName`        VARCHAR(256)  NOT NULL,
                                             `f_schemeId`            INTEGER       NOT NULL,
                                              FOREIGN KEY(`f_appName`,`f_activityName`)   REFERENCES applicationActivities(`f_appName`,`activityName`) ON DELETE CASCADE
                                              FOREIGN KEY(`f_schemeId`) REFERENCES authenticationSchemes(`schemeId`) ON DELETE CASCADE,
                                              PRIMARY KEY(`f_appName`,`f_activityName`,`f_schemeId`)
                     );    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`authenticationSlots` (
                                             `slotId`                        INTEGER PRIMARY KEY AUTOINCREMENT,
                                             `description`                   VARCHAR(4096) NOT NULL,
                                             `function`                      INTEGER       DEFAULT 0,
                                             `defaultExpirationSeconds`      INTEGER       DEFAULT 0,
                                             `canSkipWhenExpired`            BOOLEAN       NOT NULL DEFAULT FALSE,
                                             `strengthJSONValidator`         TEXT          NOT NULL,
                                             `totp2FAStepsToleranceWindow`  INTEGER         DEFAULT 0
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`authenticationSchemeUsedSlots` (
                                            `f_schemeId`             INTEGER        NOT NULL,
                                            `f_slotId`               INTEGER        NOT NULL,
                                            `orderPriority`          INTEGER        NOT NULL,
                                            `optional`               BOOLEAN        NOT NULL,
                                             FOREIGN KEY(`f_schemeId`) REFERENCES authenticationSchemes(`schemeId`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_slotId`) REFERENCES authenticationSlots(`slotId`) ON DELETE CASCADE,
                                             PRIMARY KEY(`f_schemeId`,`f_slotId`)
                     );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`accountManagers` (
                                             `f_accountNameManager`     VARCHAR(256)    NOT NULL,
                                             `f_accountName_managed`    VARCHAR(256)    NOT NULL,
                                             PRIMARY KEY(`f_accountNameManager`,`f_accountName_managed`),
                                             FOREIGN KEY(`f_accountNameManager`)   REFERENCES accounts(`accountName`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_accountName_managed`)  REFERENCES accounts(`accountName`) ON DELETE CASCADE
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`accountsActivationToken` (
                                             `f_accountName`            VARCHAR(256) NOT NULL,
                                             `confirmationToken`     VARCHAR(256) NOT NULL,
                                             PRIMARY KEY(`f_accountName`),
                                             FOREIGN KEY(`f_accountName`) REFERENCES accounts(`accountName`) ON DELETE CASCADE
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`accountsBlockToken` (
                                             `f_accountName`            VARCHAR(256) NOT NULL,
                                             `blockToken`            VARCHAR(256) NOT NULL,
                                             `lastAccess`            DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                             PRIMARY KEY(`f_accountName`),
                                             FOREIGN KEY(`f_accountName`) REFERENCES accounts(`accountName`) ON DELETE CASCADE
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`accountCredentials` (
                                             `f_AuthSlotId`                 INTEGER         NOT NULL,
                                             `f_accountName`                VARCHAR(256) NOT NULL,
                                             `hash`                         VARCHAR(256)    NOT NULL,
                                             `expiration`                   DATETIME        DEFAULT NULL,
                                             `salt`                         VARCHAR(256)            ,
                                             `mustChange`             BOOLEAN         NOT NULL DEFAULT 0,
                                             `isLocked`             BOOLEAN         NOT NULL DEFAULT 0,
                                             `badAttempts`                  INTEGER         NOT NULL DEFAULT 0,
                                             `lastChange`                   DATETIME        DEFAULT CURRENT_TIMESTAMP NOT NULL,

                                             PRIMARY KEY(`f_AuthSlotId`,`f_accountName`),
                                             FOREIGN KEY(`f_AuthSlotId`)      REFERENCES authenticationSlots(`slotId`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_accountName`)        REFERENCES accounts(`accountName`) ON DELETE CASCADE
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationRoles` (
                                             `f_appName`                 VARCHAR(256) NOT NULL,
                                             `roleName`                  VARCHAR(256) NOT NULL,
                                             `roleDescription`           VARCHAR(4096),
                                             FOREIGN KEY(`f_appName`) REFERENCES applications(`appName`) ON DELETE CASCADE,
                                             PRIMARY KEY(`roleName`,`f_appName`)
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`defaultAppRoleWhenRegistering` (
                                             `f_appName`                 VARCHAR(256) NOT NULL,
                                             `f_roleName` VARCHAR(256) NOT NULL,
            PRIMARY KEY(`f_appName`,`f_roleName`),
            FOREIGN KEY(`f_appName`) REFERENCES applications(`appName`) ON DELETE CASCADE,
            FOREIGN KEY(`f_roleName`, `f_appName`) REFERENCES applicationRoles(`roleName`, `f_appName`) ON DELETE CASCADE
            );)",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationRolesAccounts` (
                                             `f_appName`                VARCHAR(256) NOT NULL,
                                             `f_roleName`               VARCHAR(256) NOT NULL,
                                             `f_accountName`            VARCHAR(256) NOT NULL,
                                             FOREIGN KEY(`f_roleName`,`f_appName`)      REFERENCES applicationRoles(`roleName`,`f_appName`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_accountName`)     REFERENCES accounts(`accountName`) ON DELETE CASCADE,
                                             UNIQUE (`f_roleName`, `f_appName`, `f_accountName`)
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationRolesScopes` (
                                             `f_scopeId`            VARCHAR(256) NOT NULL,
                                             `f_appName`            VARCHAR(256) NOT NULL,
                                             `f_roleName`           VARCHAR(256) NOT NULL,
                                             FOREIGN KEY(`f_appName`,`f_scopeId`) REFERENCES applicationScopes(`f_appName`,`scopeId`) ON DELETE CASCADE,
                                             FOREIGN KEY(`f_roleName`,`f_appName`)      REFERENCES applicationRoles(`roleName`,`f_appName`) ON DELETE CASCADE,
                                             UNIQUE (`f_appName`, `f_scopeId`, `f_roleName`) );
                                    )",

        R"(CREATE TABLE IF NOT EXISTS `iam`.`applicationScopeAccounts` (
                                              `f_appName`                VARCHAR(256) NOT NULL,
                                              `f_scopeId`                VARCHAR(256) NOT NULL,
                                              `f_accountName`            VARCHAR(256) NOT NULL,
                                              FOREIGN KEY(`f_appName`,`f_scopeId`) REFERENCES applicationScopes(`f_appName`,`scopeId`) ON DELETE CASCADE,
                                              FOREIGN KEY(`f_accountName`, `f_appName`) REFERENCES applicationAccounts(`f_accountName`, `f_appName`) ON DELETE CASCADE,
                                              UNIQUE (`f_appName`, `f_scopeId`, `f_accountName`)
                                                                        );
                                    )",
        R"(CREATE TABLE IF NOT EXISTS `logs`.`applicationAccess_accountLastLogin` (
                                              `f_accountName`            VARCHAR(256)  NOT NULL,
                                              `f_appName`                VARCHAR(256)  NOT NULL,
                                              `lastLogin`                DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                              PRIMARY KEY(`f_accountName`, `f_appName`)
                                                                         );
                                        )",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_applicationAccess_accountLastLogin_accountName ON applicationAccess_accountLastLogin (f_accountName);)",

        R"(CREATE TABLE IF NOT EXISTS `logs`.`applicationAccess_accountSessions` (
                                              `id`                   INTEGER         PRIMARY KEY AUTOINCREMENT,
                                              `f_accountName`        VARCHAR(256)    NOT NULL,
                                              `f_schemeId`           INTEGER         NOT NULL,
                                              `f_appName`            VARCHAR(256)    NOT NULL,
                                              `loginDateTime`        DATETIME        NOT NULL,
                                              `loginIP`              VARCHAR(64)     NOT NULL,
                                              `loginTLSCN`           VARCHAR(1024)   NOT NULL,
                                              `loginUserAgent`       VARCHAR(4096)   NOT NULL,
                                              `loginExtraData`       VARCHAR(4096)   NOT NULL,
                                              `logoutDateTime`       DATETIME        DEFAULT NULL,
                                              `logoutReason`         INTEGER         DEFAULT NULL,
                                              `refresherTokenId`     VARCHAR(256)    DEFAULT NULL,
                                              `accessTokenId`        VARCHAR(256)    DEFAULT NULL,
                                              `accessTokenExpiration` DATETIME       DEFAULT NULL,
                                              `refreshTokenExpiration` DATETIME     DEFAULT NULL);
                                      )",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_applicationAccess_accountSessions_accountName ON applicationAccess_accountSessions (f_accountName);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_applicationAccess_accountSessions_schemeID ON applicationAccess_accountSessions (f_schemeId);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_applicationAccess_accountSessions_dateTime ON applicationAccess_accountSessions (loginDateTime);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_applicationAccess_accountSessions_loginIP ON applicationAccess_accountSessions (loginIP);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_applicationAccess_accountSessions_accessTokenExpiration ON applicationAccess_accountSessions (accessTokenExpiration);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_applicationAccess_accountSessions_refreshTokenExpiration ON applicationAccess_accountSessions (refreshTokenExpiration);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_applicationAccess_accountSessions_logoutDateTime ON applicationAccess_accountSessions (logoutDateTime);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_applicationAccess_accountSessions_logoutReason ON applicationAccess_accountSessions (logoutReason);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_applicationAccess_accountSessions_refresherTokenId ON applicationAccess_accountSessions (refresherTokenId);)",

        R"(CREATE TABLE IF NOT EXISTS `logs`.`authEvents_accountCredentialValidation` (
                                              `f_accountName`        VARCHAR(256)    NOT NULL,
                                              `f_slotId`             INTEGER         NOT NULL,
                                              `logDateTime`          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                              `logIP`                VARCHAR(64)     NOT NULL,
                                              `logTLSCN`             VARCHAR(1024)   NOT NULL,
                                              `logUserAgent`         VARCHAR(4096)   NOT NULL,
                                              `logExtraData`         VARCHAR(4096)   NOT NULL,
                                              `logStatus`            INTEGER    NOT NULL);
                                      )",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_authEvents_accountCredentialValidation_accountName ON authEvents_accountCredentialValidation (f_accountName);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_authEvents_accountCredentialValidation_slotId ON authEvents_accountCredentialValidation (f_slotId);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_authEvents_accountCredentialValidation_dateTime ON authEvents_accountCredentialValidation (logDateTime);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_authEvents_accountCredentialValidation_IP ON authEvents_accountCredentialValidation (logIP);)",

        R"(CREATE TABLE IF NOT EXISTS `logs`.`securityEvents_accounts` (
                                             `id`                   INTEGER         PRIMARY KEY AUTOINCREMENT,
                                             `f_accountName`        VARCHAR(256)    NOT NULL,
                                             `f_performedBy`        VARCHAR(256)    NOT NULL,
                                             `eventDateTime`        DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                             `eventAction`              INTEGER         NOT NULL,
                                             `eventDescription`     TEXT            NOT NULL,
                                             `clientIP`              VARCHAR(64)     NOT NULL,
                                             `clientTLSCN`           VARCHAR(1024)   NOT NULL,
                                             `clientUserAgent`       VARCHAR(4096)   NOT NULL,
                                             `clientExtraData`       TEXT            NOT NULL
                                                                        );
                                    )",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_accounts_accountName ON securityEvents_accounts (f_accountName);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_accounts_dateTime ON securityEvents_accounts (eventDateTime);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_accounts_eventAction ON securityEvents_accounts (eventAction);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_accounts_clientIP ON securityEvents_accounts (clientIP);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_accounts_performedBy ON securityEvents_accounts (f_performedBy);)",

        R"(CREATE TABLE IF NOT EXISTS `logs`.`securityEvents_accountCredentials` (
                                             `id`                   INTEGER         PRIMARY KEY AUTOINCREMENT,
                                             `f_accountName`        VARCHAR(256)    NOT NULL,
                                             `f_performedBy`        VARCHAR(256)    NOT NULL,
                                             `f_slotId`             INTEGER         NOT NULL,
                                             `eventDateTime`        DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                             `eventAction`              INTEGER         NOT NULL,
                                             `eventDescription`     TEXT            NOT NULL,
                                             `clientIP`              VARCHAR(64)     NOT NULL,
                                             `clientTLSCN`           VARCHAR(1024)   NOT NULL,
                                             `clientUserAgent`       VARCHAR(4096)   NOT NULL,
                                             `clientExtraData`       TEXT            DEFAULT NULL
                                                                        );
                                    )",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_accountCredentials_accountName ON securityEvents_accountCredentials (f_accountName);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_accountCredentials_slotId ON securityEvents_accountCredentials (f_slotId);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_accountCredentials_eventDateTime ON securityEvents_accountCredentials (eventDateTime);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_accountCredentials_eventAction ON securityEvents_accountCredentials (eventAction);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_accountCredentials_clientIP ON securityEvents_accountCredentials (clientIP);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_accountCredentials_performedBy ON securityEvents_accountCredentials (f_performedBy);)",

        R"(CREATE TABLE IF NOT EXISTS `logs`.`securityEvents_authenticationSlots` (
                                             `id`                   INTEGER         PRIMARY KEY AUTOINCREMENT,
                                             `f_slotId`             INTEGER         NOT NULL,
                                             `f_performedBy`        VARCHAR(256)    NOT NULL,
                                             `eventDateTime`        DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                             `eventAction`              INTEGER         NOT NULL,
                                             `eventDescription`     TEXT            NOT NULL,
                                             `clientIP`              VARCHAR(64)     NOT NULL,
                                             `clientTLSCN`           VARCHAR(1024)   NOT NULL,
                                             `clientUserAgent`       VARCHAR(4096)   NOT NULL,
                                             `clientExtraData`       TEXT            DEFAULT NULL
                                                                        );
                                    )",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_authenticationSlots_slotId ON securityEvents_authenticationSlots (f_slotId);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_authenticationSlots_eventDateTime ON securityEvents_authenticationSlots (eventDateTime);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_authenticationSlots_eventAction ON securityEvents_authenticationSlots (eventAction);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_authenticationSlots_clientIP ON securityEvents_authenticationSlots (clientIP);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_authenticationSlots_performedBy ON securityEvents_authenticationSlots (f_performedBy);)",

        R"(CREATE TABLE IF NOT EXISTS `logs`.`securityEvents_authenticationSchemes` (
                                             `id`                   INTEGER         PRIMARY KEY AUTOINCREMENT,
                                             `f_schemeId`           INTEGER         NOT NULL,
                                             `f_performedBy`        VARCHAR(256)    NOT NULL,
                                             `eventDateTime`        DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                             `eventAction`              INTEGER         NOT NULL,
                                             `eventDescription`     TEXT            NOT NULL,
                                             `clientIP`              VARCHAR(64)     NOT NULL,
                                             `clientTLSCN`           VARCHAR(1024)   NOT NULL,
                                             `clientUserAgent`       VARCHAR(4096)   NOT NULL,
                                             `clientExtraData`       TEXT            DEFAULT NULL
                                                                        );
                                    )",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_authenticationSchemes_schemeId ON securityEvents_authenticationSchemes (f_schemeId);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_authenticationSchemes_eventDateTime ON securityEvents_authenticationSchemes (eventDateTime);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_authenticationSchemes_eventAction ON securityEvents_authenticationSchemes (eventAction);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_authenticationSchemes_clientIP ON securityEvents_authenticationSchemes (clientIP);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_authenticationSchemes_performedBy ON securityEvents_authenticationSchemes (f_performedBy);)",

        R"(CREATE TABLE IF NOT EXISTS `logs`.`securityEvents_accountFields` (
                                             `id`                   INTEGER         PRIMARY KEY AUTOINCREMENT,
                                             `f_fieldName`          VARCHAR(256)    NOT NULL,
                                             `f_performedBy`        VARCHAR(256)    NOT NULL,
                                             `eventDateTime`        DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                             `eventAction`              INTEGER         NOT NULL,
                                             `eventDescription`     TEXT            NOT NULL,
                                             `clientIP`              VARCHAR(64)     NOT NULL,
                                             `clientTLSCN`           VARCHAR(1024)   NOT NULL,
                                             `clientUserAgent`       VARCHAR(4096)   NOT NULL,
                                             `clientExtraData`       TEXT            DEFAULT NULL
                                                                        );
                                    )",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_accountFields_fieldName ON securityEvents_accountFields (f_fieldName);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_accountFields_eventDateTime ON securityEvents_accountFields (eventDateTime);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_accountFields_eventAction ON securityEvents_accountFields (eventAction);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_accountFields_clientIP ON securityEvents_accountFields (clientIP);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_accountFields_performedBy ON securityEvents_accountFields (f_performedBy);)",

        R"(CREATE TABLE IF NOT EXISTS `logs`.`securityEvents_applications` (
                                             `id`                   INTEGER         PRIMARY KEY AUTOINCREMENT,
                                             `f_appName`            VARCHAR(256)    NOT NULL,
                                             `f_performedBy`        VARCHAR(256)    NOT NULL,
                                             `eventDateTime`        DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                             `eventAction`          INTEGER         NOT NULL,
                                             `eventDescription`     TEXT            NOT NULL,
                                             `clientIP`              VARCHAR(64)     NOT NULL,
                                             `clientTLSCN`           VARCHAR(1024)   NOT NULL,
                                             `clientUserAgent`       VARCHAR(4096)   NOT NULL,
                                             `clientExtraData`       TEXT            DEFAULT NULL
                                                                        );
                                    )",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applications_appName ON securityEvents_applications (f_appName);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applications_eventDateTime ON securityEvents_applications (eventDateTime);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applications_eventAction ON securityEvents_applications (eventAction);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applications_clientIP ON securityEvents_applications (clientIP);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applications_performedBy ON securityEvents_applications (f_performedBy);)",

        R"(CREATE TABLE IF NOT EXISTS `logs`.`securityEvents_applicationRole` (
                                             `id`                   INTEGER         PRIMARY KEY AUTOINCREMENT,
                                             `f_appName`            VARCHAR(256)    NOT NULL,
                                             `f_roleName`           VARCHAR(256)    NOT NULL,
                                             `f_accountName`        VARCHAR(256)    NOT NULL,
                                             `f_performedBy`        VARCHAR(256)    NOT NULL,
                                             `eventDateTime`        DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                             `eventAction`          INTEGER         NOT NULL,
                                             `eventDescription`     TEXT            NOT NULL,
                                             `clientIP`              VARCHAR(64)     NOT NULL,
                                             `clientTLSCN`           VARCHAR(1024)   NOT NULL,
                                             `clientUserAgent`       VARCHAR(4096)   NOT NULL,
                                             `clientExtraData`       TEXT            DEFAULT NULL
                                                                        );
                                    )",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationRole_appName ON securityEvents_applicationRole (f_appName);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationRole_roleName ON securityEvents_applicationRole (f_roleName);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationRole_eventDateTime ON securityEvents_applicationRole (eventDateTime);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationRole_accountName ON securityEvents_applicationRole (f_accountName);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationRole_eventAction ON securityEvents_applicationRole (eventAction);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationRole_clientIP ON securityEvents_applicationRole (clientIP);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationRole_performedBy ON securityEvents_applicationRole (f_performedBy);)",

        R"(CREATE TABLE IF NOT EXISTS `logs`.`securityEvents_applicationActivities` (
                                             `id`                   INTEGER         PRIMARY KEY AUTOINCREMENT,
                                             `f_appName`            VARCHAR(256)    NOT NULL,
                                             `f_activityName`       VARCHAR(256)    NOT NULL,
                                             `f_schemeId`           INTEGER         DEFAULT NULL,
                                             `f_performedBy`        VARCHAR(256)    NOT NULL,
                                             `eventDateTime`        DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                             `eventAction`          INTEGER         NOT NULL,
                                             `eventDescription`     TEXT            NOT NULL,
                                             `clientIP`              VARCHAR(64)     NOT NULL,
                                             `clientTLSCN`           VARCHAR(1024)   NOT NULL,
                                             `clientUserAgent`       VARCHAR(4096)   NOT NULL,
                                             `clientExtraData`       TEXT            DEFAULT NULL
                                                                        );
                                    )",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationActivities_appName ON securityEvents_applicationActivities (f_appName);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationActivities_activityName ON securityEvents_applicationActivities (f_activityName);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationActivities_schemeId ON securityEvents_applicationActivities (f_schemeId);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationActivities_eventDateTime ON securityEvents_applicationActivities (eventDateTime);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationActivities_eventAction ON securityEvents_applicationActivities (eventAction);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationActivities_clientIP ON securityEvents_applicationActivities (clientIP);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationActivities_performedBy ON securityEvents_applicationActivities (f_performedBy);)",

        R"(CREATE TABLE IF NOT EXISTS `logs`.`securityEvents_applicationScopes` (
                                             `id`                   INTEGER         PRIMARY KEY AUTOINCREMENT,
                                             `f_appName`            VARCHAR(256)    NOT NULL,
                                             `f_scopeId`            VARCHAR(256)    NOT NULL,
                                             `f_accountName`        VARCHAR(256)    NOT NULL,
                                             `f_performedBy`        VARCHAR(256)    NOT NULL,
                                             `eventDateTime`        DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                             `eventAction`          INTEGER         NOT NULL,
                                             `eventDescription`     TEXT            NOT NULL,
                                             `clientIP`              VARCHAR(64)     NOT NULL,
                                             `clientTLSCN`           VARCHAR(1024)   NOT NULL,
                                             `clientUserAgent`       VARCHAR(4096)   NOT NULL,
                                             `clientExtraData`       TEXT            DEFAULT NULL
                                                                        );
                                    )",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationScopes_appName ON securityEvents_applicationScopes (f_appName);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationScopes_scopeId ON securityEvents_applicationScopes (f_scopeId);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationScopes_accountName ON securityEvents_applicationScopes (f_accountName);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationScopes_eventDateTime ON securityEvents_applicationScopes (eventDateTime);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationScopes_eventAction ON securityEvents_applicationScopes (eventAction);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationScopes_clientIP ON securityEvents_applicationScopes (clientIP);)",
        R"(CREATE INDEX IF NOT EXISTS `logs`.idx_securityEvents_applicationScopes_performedBy ON securityEvents_applicationScopes (f_performedBy);)",

    };

    bool success = true;
    for (const std::string_view &sql : sqlStatements)
    {
        if (!m_sqlConnector->qExecuteEx(std::string(sql)))
        {
            LOG_APP->log0(__func__, Logs::LogLevel::CRITICAL, "Failed to execute SQL: '%s'", std::string(sql).c_str());
            success = false;
            break;
        }
    }

    return success;
}

std::list<std::string> IdentityManager_DB::getSqlErrorList() const
{
    return m_sqlErrorList;
}

void IdentityManager_DB::clearSQLErrorList()
{
    m_sqlErrorList.clear();
}

void IdentityManager_DB::logSecurityEventOnAccounts(const std::string &accountName, SecurityEventAction eventAction, const std::string &description, const std::string &performedBy,
                                                    const ClientDetails &clientDetails)
{
    LOG_APP->log2(__func__, performedBy, clientDetails.ipAddress, SecurityEventActionToLogLevel(eventAction), "account='%s', action='%s', desc='%s'", accountName.c_str(),
                  SecurityEventActionToString(eventAction), description.c_str());

    m_sqlConnector->qExecuteEx(
        R"(INSERT INTO logs.securityEvents_accounts
               (`f_accountName`, `f_performedBy`, `eventAction`, `eventDescription`,
                `clientIP`, `clientTLSCN`, `clientUserAgent`, `clientExtraData`)
              VALUES (:f_accountName, :f_performedBy, :eventAction, :eventDescription,
                      :clientIP, :clientTLSCN, :clientUserAgent, :clientExtraData);)",
        {{":f_accountName", MAKE_VAR(STRING, accountName)},
         {":f_performedBy", MAKE_VAR(STRING, performedBy)},
         {":eventAction", MAKE_VAR(INT32, static_cast<int>(eventAction))},
         {":eventDescription", MAKE_VAR(STRING, description)},
         {":clientIP", MAKE_VAR(STRING, clientDetails.ipAddress)},
         {":clientTLSCN", MAKE_VAR(STRING, clientDetails.tlsCommonName)},
         {":clientUserAgent", MAKE_VAR(STRING, clientDetails.userAgent)},
         {":clientExtraData", MAKE_VAR(STRING, clientDetails.extraData)}});
}

void IdentityManager_DB::logSecurityEventOnAccountCredentials(const std::string &accountName, uint32_t slotId, SecurityEventAction eventAction, const std::string &eventDescription,
                                                              const std::string &performedBy, const ClientDetails &clientDetails)
{
    LOG_APP->log2(__func__, performedBy, clientDetails.ipAddress, SecurityEventActionToLogLevel(eventAction), "account='%s', slot=%u, action='%s', desc='%s'", accountName.c_str(), slotId,
                  SecurityEventActionToString(eventAction), eventDescription.c_str());

    m_sqlConnector->qExecuteEx(
        R"(INSERT INTO logs.securityEvents_accountCredentials
               (`f_accountName`, `f_slotId`, `f_performedBy`, `eventAction`, `eventDescription`,
                `clientIP`, `clientTLSCN`, `clientUserAgent`, `clientExtraData`)
              VALUES (:f_accountName, :f_slotId, :f_performedBy, :eventAction, :eventDescription,
                      :clientIP, :clientTLSCN, :clientUserAgent, :clientExtraData);)",
        {{":f_accountName", MAKE_VAR(STRING, accountName)},
         {":f_slotId", MAKE_VAR(UINT32, slotId)},
         {":f_performedBy", MAKE_VAR(STRING, performedBy)},
         {":eventAction", MAKE_VAR(INT32, static_cast<int>(eventAction))},
         {":eventDescription", MAKE_VAR(STRING, eventDescription)},
         {":clientIP", MAKE_VAR(STRING, clientDetails.ipAddress)},
         {":clientTLSCN", MAKE_VAR(STRING, clientDetails.tlsCommonName)},
         {":clientUserAgent", MAKE_VAR(STRING, clientDetails.userAgent)},
         {":clientExtraData", MAKE_VAR(STRING, clientDetails.extraData)}});
}

void IdentityManager_DB::logSecurityEventOnAuthenticationSlots(uint32_t slotId, SecurityEventAction eventAction, const std::string &eventDescription, const std::string &performedBy,
                                                               const ClientDetails &clientDetails)
{
    LOG_APP->log2(__func__, performedBy, clientDetails.ipAddress, SecurityEventActionToLogLevel(eventAction), "slot=%u, action='%s', desc='%s'", slotId, SecurityEventActionToString(eventAction),
                  eventDescription.c_str());

    m_sqlConnector->qExecuteEx(
        R"(INSERT INTO logs.securityEvents_authenticationSlots
               (`f_slotId`, `f_performedBy`, `eventAction`, `eventDescription`,
                `clientIP`, `clientTLSCN`, `clientUserAgent`, `clientExtraData`)
              VALUES (:f_slotId, :f_performedBy, :eventAction, :eventDescription,
                      :clientIP, :clientTLSCN, :clientUserAgent, :clientExtraData);)",
        {{":f_slotId", MAKE_VAR(UINT32, slotId)},
         {":f_performedBy", MAKE_VAR(STRING, performedBy)},
         {":eventAction", MAKE_VAR(INT32, static_cast<int>(eventAction))},
         {":eventDescription", MAKE_VAR(STRING, eventDescription)},
         {":clientIP", MAKE_VAR(STRING, clientDetails.ipAddress)},
         {":clientTLSCN", MAKE_VAR(STRING, clientDetails.tlsCommonName)},
         {":clientUserAgent", MAKE_VAR(STRING, clientDetails.userAgent)},
         {":clientExtraData", MAKE_VAR(STRING, clientDetails.extraData)}});
}

void IdentityManager_DB::logSecurityEventOnAccountDetailFields(const std::string &fieldName, SecurityEventAction eventAction, const std::string &eventDescription, const std::string &performedBy,
                                                               const ClientDetails &clientDetails)
{
    LOG_APP->log2(__func__, performedBy, clientDetails.ipAddress, SecurityEventActionToLogLevel(eventAction), "field='%s', action='%s', desc='%s'", fieldName.c_str(),
                  SecurityEventActionToString(eventAction), eventDescription.c_str());

    m_sqlConnector->qExecuteEx(
        R"(INSERT INTO logs.securityEvents_accountFields
               (`f_fieldName`, `f_performedBy`, `eventAction`, `eventDescription`,
                `clientIP`, `clientTLSCN`, `clientUserAgent`, `clientExtraData`)
              VALUES (:f_fieldName, :f_performedBy, :eventAction, :eventDescription,
                      :clientIP, :clientTLSCN, :clientUserAgent, :clientExtraData);)",
        {{":f_fieldName", MAKE_VAR(STRING, fieldName)},
         {":f_performedBy", MAKE_VAR(STRING, performedBy)},
         {":eventAction", MAKE_VAR(INT32, static_cast<int>(eventAction))},
         {":eventDescription", MAKE_VAR(STRING, eventDescription)},
         {":clientIP", MAKE_VAR(STRING, clientDetails.ipAddress)},
         {":clientTLSCN", MAKE_VAR(STRING, clientDetails.tlsCommonName)},
         {":clientUserAgent", MAKE_VAR(STRING, clientDetails.userAgent)},
         {":clientExtraData", MAKE_VAR(STRING, clientDetails.extraData)}});
}

void IdentityManager_DB::logSecurityEventOnAuthenticationSchemes(uint32_t schemeId, SecurityEventAction eventAction, const std::string &eventDescription, const std::string &performedBy,
                                                                 const ClientDetails &clientDetails)
{
    LOG_APP->log2(__func__, performedBy, clientDetails.ipAddress, SecurityEventActionToLogLevel(eventAction), "scheme=%u, action='%s', desc='%s'", schemeId, SecurityEventActionToString(eventAction),
                  eventDescription.c_str());

    m_sqlConnector->qExecuteEx(
        R"(INSERT INTO logs.securityEvents_authenticationSchemes
               (`f_schemeId`, `f_performedBy`, `eventAction`, `eventDescription`,
                `clientIP`, `clientTLSCN`, `clientUserAgent`, `clientExtraData`)
              VALUES (:f_schemeId, :f_performedBy, :eventAction, :eventDescription,
                      :clientIP, :clientTLSCN, :clientUserAgent, :clientExtraData);)",
        {{":f_schemeId", MAKE_VAR(UINT32, schemeId)},
         {":f_performedBy", MAKE_VAR(STRING, performedBy)},
         {":eventAction", MAKE_VAR(INT32, static_cast<int>(eventAction))},
         {":eventDescription", MAKE_VAR(STRING, eventDescription)},
         {":clientIP", MAKE_VAR(STRING, clientDetails.ipAddress)},
         {":clientTLSCN", MAKE_VAR(STRING, clientDetails.tlsCommonName)},
         {":clientUserAgent", MAKE_VAR(STRING, clientDetails.userAgent)},
         {":clientExtraData", MAKE_VAR(STRING, clientDetails.extraData)}});
}

void IdentityManager_DB::logSecurityEventOnApplications(const std::string &applicationName, SecurityEventAction eventAction, const std::string &eventDescription, const std::string &performedBy,
                                                        const ClientDetails &clientDetails)
{
    LOG_APP->log2(__func__, performedBy, clientDetails.ipAddress, SecurityEventActionToLogLevel(eventAction), "app='%s', action='%s', desc='%s'", applicationName.c_str(),
                  SecurityEventActionToString(eventAction), eventDescription.c_str());

    m_sqlConnector->qExecuteEx(
        R"(INSERT INTO logs.securityEvents_applications
               (`f_appName`, `f_performedBy`, `eventAction`, `eventDescription`,
                `clientIP`, `clientTLSCN`, `clientUserAgent`, `clientExtraData`)
              VALUES (:f_appName, :f_performedBy, :eventAction, :eventDescription,
                      :clientIP, :clientTLSCN, :clientUserAgent, :clientExtraData);)",
        {{":f_appName", MAKE_VAR(STRING, applicationName)},
         {":f_performedBy", MAKE_VAR(STRING, performedBy)},
         {":eventAction", MAKE_VAR(INT32, static_cast<int>(eventAction))},
         {":eventDescription", MAKE_VAR(STRING, eventDescription)},
         {":clientIP", MAKE_VAR(STRING, clientDetails.ipAddress)},
         {":clientTLSCN", MAKE_VAR(STRING, clientDetails.tlsCommonName)},
         {":clientUserAgent", MAKE_VAR(STRING, clientDetails.userAgent)},
         {":clientExtraData", MAKE_VAR(STRING, clientDetails.extraData)}});
}

void IdentityManager_DB::logSecurityEventOnApplicationRoles(const std::string &applicationName, const std::string &roleName, const std::string &accountName, SecurityEventAction eventAction,
                                                            const std::string &eventDescription, const std::string &performedBy, const ClientDetails &clientDetails)
{
    LOG_APP->log2(__func__, performedBy, clientDetails.ipAddress, SecurityEventActionToLogLevel(eventAction), "app='%s', role='%s', account='%s', action='%s', desc='%s'", applicationName.c_str(),
                  roleName.c_str(), accountName.c_str(), SecurityEventActionToString(eventAction), eventDescription.c_str());

    m_sqlConnector->qExecuteEx(
        R"(INSERT INTO logs.securityEvents_applicationRole
               (`f_appName`, `f_roleName`, `f_accountName`, `f_performedBy`, `eventAction`, `eventDescription`,
                `clientIP`, `clientTLSCN`, `clientUserAgent`, `clientExtraData`)
              VALUES (:f_appName, :f_roleName, :f_accountName, :f_performedBy, :eventAction, :eventDescription,
                      :clientIP, :clientTLSCN, :clientUserAgent, :clientExtraData);)",
        {{":f_appName", MAKE_VAR(STRING, applicationName)},
         {":f_roleName", MAKE_VAR(STRING, roleName)},
         {":f_accountName", MAKE_VAR(STRING, accountName)},
         {":f_performedBy", MAKE_VAR(STRING, performedBy)},
         {":eventAction", MAKE_VAR(INT32, static_cast<int>(eventAction))},
         {":eventDescription", MAKE_VAR(STRING, eventDescription)},
         {":clientIP", MAKE_VAR(STRING, clientDetails.ipAddress)},
         {":clientTLSCN", MAKE_VAR(STRING, clientDetails.tlsCommonName)},
         {":clientUserAgent", MAKE_VAR(STRING, clientDetails.userAgent)},
         {":clientExtraData", MAKE_VAR(STRING, clientDetails.extraData)}});
}

void IdentityManager_DB::logSecurityEventApplicationScopes(const std::string &applicationName, const std::string &scopeName, const std::string &accountName, SecurityEventAction eventAction,
                                                           const std::string &eventDescription, const std::string &performedBy, const ClientDetails &clientDetails)
{
    LOG_APP->log2(__func__, performedBy, clientDetails.ipAddress, SecurityEventActionToLogLevel(eventAction), "app='%s', scope='%s', account='%s', action='%s', desc='%s'", applicationName.c_str(),
                  scopeName.c_str(), accountName.c_str(), SecurityEventActionToString(eventAction), eventDescription.c_str());

    m_sqlConnector->qExecuteEx(
        R"(INSERT INTO logs.securityEvents_applicationScopes
               (`f_appName`, `f_scopeId`, `f_accountName`, `f_performedBy`, `eventAction`, `eventDescription`,
                `clientIP`, `clientTLSCN`, `clientUserAgent`, `clientExtraData`)
              VALUES (:f_appName, :f_scopeId, :f_accountName, :f_performedBy, :eventAction, :eventDescription,
                      :clientIP, :clientTLSCN, :clientUserAgent, :clientExtraData);)",
        {{":f_appName", MAKE_VAR(STRING, applicationName)},
         {":f_scopeId", MAKE_VAR(STRING, scopeName)},
         {":f_accountName", MAKE_VAR(STRING, accountName)},
         {":f_performedBy", MAKE_VAR(STRING, performedBy)},
         {":eventAction", MAKE_VAR(INT32, static_cast<int>(eventAction))},
         {":eventDescription", MAKE_VAR(STRING, eventDescription)},
         {":clientIP", MAKE_VAR(STRING, clientDetails.ipAddress)},
         {":clientTLSCN", MAKE_VAR(STRING, clientDetails.tlsCommonName)},
         {":clientUserAgent", MAKE_VAR(STRING, clientDetails.userAgent)},
         {":clientExtraData", MAKE_VAR(STRING, clientDetails.extraData)}});
}

void IdentityManager_DB::logSecurityEventOnApplicationActivities(const std::string &applicationName, const std::string &activityName, std::optional<uint32_t> schemeId, SecurityEventAction eventAction,
                                                                 const std::string &eventDescription, const std::string &performedBy, const ClientDetails &clientDetails)
{
    if (schemeId.has_value())
    {
        LOG_APP->log2(__func__, performedBy, clientDetails.ipAddress, SecurityEventActionToLogLevel(eventAction), "app='%s', activity='%s', scheme=%u, action='%s', desc='%s'", applicationName.c_str(),
                      activityName.c_str(), schemeId.value(), SecurityEventActionToString(eventAction), eventDescription.c_str());
    }
    else
    {
        LOG_APP->log2(__func__, performedBy, clientDetails.ipAddress, SecurityEventActionToLogLevel(eventAction), "app='%s', activity='%s', scheme=null, action='%s', desc='%s'",
                      applicationName.c_str(), activityName.c_str(), SecurityEventActionToString(eventAction), eventDescription.c_str());
    }

    std::string sql = std::string("INSERT INTO logs.securityEvents_applicationActivities "
                                  "(`f_appName`, `f_activityName`, `f_schemeId`, `f_performedBy`, `eventAction`, `eventDescription`, `clientIP`, `clientTLSCN`, `clientUserAgent`, `clientExtraData`)"
                                  " VALUES (:f_appName, :f_activityName, ")
                      + (schemeId.has_value() ? ":f_schemeId" : "null") + ", :f_performedBy, :eventAction, :eventDescription,:clientIP, :clientTLSCN, :clientUserAgent, :clientExtraData);";

    m_sqlConnector->qExecuteEx(sql, {{":f_appName", MAKE_VAR(STRING, applicationName)},
                                     {":f_activityName", MAKE_VAR(STRING, activityName)},
                                     {":f_schemeId", MAKE_VAR(UINT32, schemeId.has_value() ? schemeId.value() : 0)},
                                     {":f_performedBy", MAKE_VAR(STRING, performedBy)},
                                     {":eventAction", MAKE_VAR(INT32, static_cast<int>(eventAction))},
                                     {":eventDescription", MAKE_VAR(STRING, eventDescription)},
                                     {":clientIP", MAKE_VAR(STRING, clientDetails.ipAddress)},
                                     {":clientTLSCN", MAKE_VAR(STRING, clientDetails.tlsCommonName)},
                                     {":clientUserAgent", MAKE_VAR(STRING, clientDetails.userAgent)},
                                     {":clientExtraData", MAKE_VAR(STRING, clientDetails.extraData)}});
}
