#pragma once

#include <Mantids30/Helpers/json.h>
#include <cstdint>
#include <optional>
#include <set>
#include <string>

struct AppError
{
    uint16_t http_code = 999;
    std::string error;
    std::string message;
};

struct ApplicationDef
{
    bool isAppAdmin = false;
    std::set<std::string> roles;
    std::set<std::string> scopes;
};

struct AccountApplicationInfo
{
    [[nodiscard]] Json::Value toJSON() const
    {
        Json::Value app;
        app["name"] = appName;
        app["description"] = appDescription;
        app["isAppAdmin"] = isAppAdmin;
        app["enrollmentDate"] = static_cast<Json::Int64>(enrollmentDate);
        app["defaultReturnURL"] = defaultReturnURL;

        // Roles as array
        Json::Value rolesArray(Json::arrayValue);
        for (const std::string &role : roles)
        {
            rolesArray.append(role);
        }
        app["roles"] = rolesArray;

        // Direct scopes as array
        Json::Value directScopesArray(Json::arrayValue);
        for (const std::string &scope : directScopes)
        {
            directScopesArray.append(scope);
        }
        app["directScopes"] = directScopesArray;

        // All scopes (union) as array
        Json::Value allScopesArray(Json::arrayValue);
        for (const std::string &scope : allScopes)
        {
            allScopesArray.append(scope);
        }
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

struct ApplicationAuthSettings
{
    [[nodiscard]] Json::Value toJSON() const
    {
        Json::Value root(Json::objectValue);
        root["appName"] = appName;
        root["tokenType"] = signAlgorithm;
        root["allowRefreshTokenRenovation"] = allowRefreshTokenRenovation;
        root["includeApplicationScopes"] = includeApplicationScopes;
        root["includeBasicAccountInfo"] = includeBasicAccountInfo;
        root["maintainRevocationAndLogoutInfo"] = maintainRevocationAndLogoutInfo;
        root["tokensConfiguration"] = tokensConfiguration;
        root["sessionConfiguration"] = sessionConfiguration;
        return root;
    }
    std::optional<AppError> fromJSON(const Json::Value &root)
    {
        appName = Mantids30::Helpers::JSON::ASSTRING(root, "appName", "");
        if (appName.empty())
        {
            AppError error;
            error.http_code = 400;
            error.error = "invalid_request";
            error.message = "Application name cannot be empty.";
            return error;
        }

        signAlgorithm = Mantids30::Helpers::JSON::ASSTRING(root, "tokenType", "");
        allowRefreshTokenRenovation = Mantids30::Helpers::JSON::ASBOOL(root, "allowRefreshTokenRenovation", false);
        includeApplicationScopes = Mantids30::Helpers::JSON::ASBOOL(root, "includeApplicationScopes", false);
        includeBasicAccountInfo = Mantids30::Helpers::JSON::ASBOOL(root, "includeBasicAccountInfo", false);
        maintainRevocationAndLogoutInfo = Mantids30::Helpers::JSON::ASBOOL(root, "maintainRevocationAndLogoutInfo", false);
        tokensConfiguration = root["tokensConfiguration"];
        sessionConfiguration = root["sessionConfiguration"];

        return std::nullopt;
    }

    std::string appName;
    std::string signAlgorithm;
    bool allowRefreshTokenRenovation;
    bool includeApplicationScopes;
    bool includeBasicAccountInfo;
    bool maintainRevocationAndLogoutInfo;
    Json::Value tokensConfiguration;
    Json::Value sessionConfiguration;
};
struct ApplicationScopeDetails
{
    ApplicationScopeDetails() = default;

    [[nodiscard]] Json::Value toJSON() const
    {
        Json::Value r;
        r["id"] = id;
        r["description"] = description;
        return r;
    }

    std::string id;
    std::string description;
};