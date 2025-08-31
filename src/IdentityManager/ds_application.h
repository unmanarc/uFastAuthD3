#pragma once

#include "json/value.h"
#include <stdint.h>
#include <string>

struct ApplicationDetails
{
    ApplicationDetails() {}
    std::string applicationName;
    std::string appCreator;
    std::string description;
};
struct ApplicationTokenProperties
{
    Json::Value toJSON() const
    {
        Json::Value root(Json::objectValue);
        root["appName"] = appName;
        root["tempMFATokenTimeout"] = tempMFATokenTimeout;
        root["sessionInactivityTimeout"] = sessionInactivityTimeout;
        root["tokenType"] = tokenType;
        root["allowRefreshTokenRenovation"] = allowRefreshTokenRenovation;
        root["includeApplicationScopes"] = includeApplicationScopes;
        root["includeBasicAccountInfo"] = includeBasicAccountInfo;
        root["maintainRevocationAndLogoutInfo"] = maintainRevocationAndLogoutInfo;
        root["tokensConfiguration"] = tokensConfiguration;
        return root;
    }

    std::string appName;
    uint32_t tempMFATokenTimeout;
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
    std::string id;
    std::string description;
};
