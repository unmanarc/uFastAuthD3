#pragma once

#include <Mantids30/Helpers/json.h>
#include <optional>
#include <stdint.h>
#include <string>

struct ApplicationDetails
{
    ApplicationDetails() {}
    std::string applicationName;
    std::string appCreator;
    std::string description;
};

struct AppError
{
    uint32_t http_code;
    std::string error;
    std::string message;
};

struct AccountApplicationInfo
{
    Json::Value toJSON() const
    {
        Json::Value app;
        app["name"] = appName;
        app["description"] = appDescription;
        app["isAppAdmin"] = isAppAdmin;
        app["enrollmentDate"] = Json::Int64(enrollmentDate);
        app["defaultReturnURL"] = defaultReturnURL;

        // Roles as array
        Json::Value rolesArray(Json::arrayValue);
        for (const std::string &role : roles)
            rolesArray.append(role);
        app["roles"] = rolesArray;

        // Direct scopes as array
        Json::Value directScopesArray(Json::arrayValue);
        for (const std::string &scope : directScopes)
            directScopesArray.append(scope);
        app["directScopes"] = directScopesArray;

        // All scopes (union) as array
        Json::Value allScopesArray(Json::arrayValue);
        for (const std::string &scope : allScopes)
            allScopesArray.append(scope);
        app["allScopes"] = allScopesArray;

        return app;
    }
    std::string appName;
    std::string appDescription;
    std::set<std::string> roles;        // Roles del account en el app
    std::set<std::string> directScopes; // Scopes directos (de applicationAccounts)
    std::set<std::string> allScopes;    // Union: direct + roles' scopes
    std::string defaultReturnURL;       // Default app URL
    bool isAppAdmin;
    time_t enrollmentDate;
};

struct ApplicationTokenProperties
{
    Json::Value toJSON() const
    {
        Json::Value root(Json::objectValue);
        root["appName"] = appName;
        root["sessionInactivityTimeout"] = sessionInactivityTimeout;
        root["tokenType"] = signAlgorithm;
        root["allowRefreshTokenRenovation"] = allowRefreshTokenRenovation;
        root["includeApplicationScopes"] = includeApplicationScopes;
        root["includeBasicAccountInfo"] = includeBasicAccountInfo;
        root["maintainRevocationAndLogoutInfo"] = maintainRevocationAndLogoutInfo;
        root["tokensConfiguration"] = tokensConfiguration;
        return root;
    }
    std::optional<AppError> fromJSON(const Json::Value &root)
    {
        appName = JSON_ASSTRING(root, "appName", "");
        if (appName.empty())
        {
            AppError error;
            error.http_code = 400;
            error.error = "invalid_request";
            error.message = "Application name cannot be empty.";
            return error;
        }

        sessionInactivityTimeout = JSON_ASUINT(root, "sessionInactivityTimeout", 0);
        signAlgorithm = JSON_ASSTRING(root, "tokenType", "");
        allowRefreshTokenRenovation = JSON_ASBOOL(root, "allowRefreshTokenRenovation", false);
        includeApplicationScopes = JSON_ASBOOL(root, "includeApplicationScopes", false);
        includeBasicAccountInfo = JSON_ASBOOL(root, "includeBasicAccountInfo", false);
        maintainRevocationAndLogoutInfo = JSON_ASBOOL(root, "maintainRevocationAndLogoutInfo", false);
        tokensConfiguration = root["tokensConfiguration"];

        return std::nullopt;
    }

    std::string appName;
    uint32_t sessionInactivityTimeout;
    std::string signAlgorithm;
    bool allowRefreshTokenRenovation;
    bool includeApplicationScopes;
    bool includeBasicAccountInfo;
    bool maintainRevocationAndLogoutInfo;
    Json::Value tokensConfiguration;
};
struct ApplicationScopeDetails
{
    ApplicationScopeDetails() {}

    json toJSON() const
    {
        json r;
        r["id"] = id;
        r["description"] = description;
        return r;
    }

    std::string id;
    std::string description;
};
