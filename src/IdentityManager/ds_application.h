#pragma once

#include <Mantids30/Helpers/json.h>
#include <stdint.h>
#include <string>
#include <optional>

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


struct ApplicationTokenProperties
{
    Json::Value toJSON() const
    {
        Json::Value root(Json::objectValue);
        root["appName"] = appName;
        root["sessionInactivityTimeout"] = sessionInactivityTimeout;
        root["tokenType"] = tokenType;
        root["allowRefreshTokenRenovation"] = allowRefreshTokenRenovation;
        root["includeApplicationScopes"] = includeApplicationScopes;
        root["includeBasicAccountInfo"] = includeBasicAccountInfo;
        root["maintainRevocationAndLogoutInfo"] = maintainRevocationAndLogoutInfo;
        root["tokensConfiguration"] = tokensConfiguration;
        return root;
    }
    std::optional<AppError> fromJSON(const Json::Value& root)
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
        tokenType = JSON_ASSTRING(root, "tokenType", "");
        allowRefreshTokenRenovation = JSON_ASBOOL(root, "allowRefreshTokenRenovation", false);
        includeApplicationScopes = JSON_ASBOOL(root, "includeApplicationScopes", false);
        includeBasicAccountInfo = JSON_ASBOOL(root, "includeBasicAccountInfo", false);
        maintainRevocationAndLogoutInfo = JSON_ASBOOL(root, "maintainRevocationAndLogoutInfo", false);
        tokensConfiguration = root["tokensConfiguration"];
        
        return std::nullopt;
    }

    std::string appName;
    uint32_t sessionInactivityTimeout;
    std::string tokenType;
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
