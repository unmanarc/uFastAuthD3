#pragma once

#include <Mantids30/Helpers/json.h>
#include <boost/json/value.hpp>
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
    [[nodiscard]] boost::json::object toJSON() const
    {
        // Roles as array
        boost::json::array rolesArray;
        for (const std::string &role : roles)
        {
            rolesArray.push_back(boost::json::value(role));
        }

        // Direct scopes as array
        boost::json::array directScopesArray;
        for (const std::string &scope : directScopes)
        {
            directScopesArray.push_back(boost::json::value(scope));
        }

        // All scopes (union) as array
        boost::json::array allScopesArray;
        for (const std::string &scope : allScopes)
        {
            allScopesArray.push_back(boost::json::value(scope));
        }

        return boost::json::object{
            {"name",           appName},
            {"description",    appDescription},
            {"isAppAdmin",     isAppAdmin},
            {"enrollmentDate", static_cast<int64_t>(enrollmentDate)},
            {"defaultReturnURL", defaultReturnURL},
            {"roles",          std::move(rolesArray)},
            {"directScopes",   std::move(directScopesArray)},
            {"allScopes",      std::move(allScopesArray)},
        };
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
    // Getters that read from tokensConfiguration (no data duplication)
    [[nodiscard]] std::string getSignAlgorithm() const
    {
        return std::string(Mantids30::Helpers::JSON::ASSTRING(tokensConfiguration,"signAlgorithm","HS256"));
    }

    [[nodiscard]] bool getAllowRefreshTokenRenovation() const
    {
        return Mantids30::Helpers::JSON::ASBOOL(tokensConfiguration,"allowRefreshTokenRenovation",false);
    }

    [[nodiscard]] bool getIncludeApplicationScopes() const
    {
        return Mantids30::Helpers::JSON::ASBOOL(tokensConfiguration,"includeApplicationScopes",true);
    }

    [[nodiscard]] bool getIncludeApplicationRoles() const
    {
        return Mantids30::Helpers::JSON::ASBOOL(tokensConfiguration,"includeApplicationRoles",true);
    }

    [[nodiscard]] bool getIncludeBasicAccountInfo() const
    {
        return Mantids30::Helpers::JSON::ASBOOL(tokensConfiguration,"includeBasicAccountInfo",true);
    }

    [[nodiscard]] boost::json::object toJSON() const
    {
        return boost::json::object{
            {"appName",              appName},
            {"tokensConfiguration",  tokensConfiguration},
            {"sessionConfiguration", sessionConfiguration},
        };
    }

    std::optional<AppError> fromJSON(const boost::json::value &root)
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

        tokensConfiguration = Mantids30::Helpers::JSON::MEMBER_OR_NULL(root, "tokensConfiguration");
        sessionConfiguration = Mantids30::Helpers::JSON::MEMBER_OR_NULL(root, "sessionConfiguration");
        return std::nullopt;
    }

    std::string appName;
    boost::json::value tokensConfiguration;
    boost::json::value sessionConfiguration;
};
struct ApplicationScopeDetails
{
    ApplicationScopeDetails() = default;

    [[nodiscard]] boost::json::object toJSON() const
    {
        return boost::json::object{
            {"id",          id},
            {"description", description},
        };
    }

    std::string id;
    std::string description;
};