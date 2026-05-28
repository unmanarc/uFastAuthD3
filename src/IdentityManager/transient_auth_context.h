#pragma once

#include <Mantids30/DataFormat_JWT/jwt.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Helpers/random.h>
#include <Mantids30/Protocol_HTTP/api_return.h>
#include <Mantids30/Protocol_HTTP/rsp_status.h>

#include "IdentityManager/ds_authentication.h"
#include "defs.h"

#include <optional>

struct TransientAuthenticationContext
{
    bool validateAndMerge_AccessTokenIfExist(const std::string &cookieAccessTokenStr, Mantids30::API::APIReturn &response, const std::shared_ptr<Mantids30::DataFormat::JWT> jwtValidator)
    {
        Mantids30::DataFormat::JWT::Token accessToken;
        //std::string cookieAccessTokenStr = request.clientRequest->getCookie("AccessToken");

        if (!cookieAccessTokenStr.empty())
        {
            if (!jwtValidator->verify(cookieAccessTokenStr, &accessToken))
            {
                // Failed to load the intermediary...
                response.setError(Mantids30::Network::Protocols::HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                                  authResultToString(AuthenticationResult::UNAUTHENTICATED));
                return false;
            }
            if (accessToken.getClaim("app") != IAM_LOGINPORTAL_APPNAME || accessToken.getClaim("type") != "access")
            {
                // This Token is not for this cookie...
                response.setError(Mantids30::Network::Protocols::HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                                  authResultToString(AuthenticationResult::UNAUTHENTICATED));
                return false;
            }
            if (accessToken.getSubject() != accountName)
            {
                // This Token is not for this cookie... (other username... logout first please!)
                response.setError(Mantids30::Network::Protocols::HTTP::Status::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                                  authResultToString(AuthenticationResult::UNAUTHENTICATED));
                return false;
            }

            // We have an access token!
            std::set<uint32_t> authenticatedSlotsOnAccessToken = Mantids30::Helpers::jsonToUInt32Set(accessToken.getClaim("slotIds"));
            // Merge.
            for (const auto &i : authenticatedSlotsOnAccessToken)
            {
                authenticatedSlots.insert(i);
            }
        }

        return true;
    }

    bool validateAndMerge_TransientAuthTokenIfExist(const std::string &transientAuthTokenStr, const Json::Value *inputJSON, const std::shared_ptr<Mantids30::DataFormat::JWT> jwtValidator)
    {
        // Validate the token
        if (!transientAuthTokenStr.empty() && transientAuthTokenStr != "null")
        {
            if (!jwtValidator->verify(transientAuthTokenStr, &transientAuthToken))
            {
                return false;
            }

            // Extract JWT Signed Parameters:
            accountName = JSON_ASSTRING_D(transientAuthToken.getClaim("preAuthUser"), "");
            fillVarsFromTransientTokenClaims();
        }
        else
        {
            // When there is no token, override initial token parameters with the input parameters...
            accountName = JSON_ASSTRING(*inputJSON, "preAuthUser", "");
            fillVarsFromInitialJSONPOST(*inputJSON);
        }

        return true;
    }

    std::string issueSignedTransientTokenFromValues(const uint32_t &loginAuthenticationTimeout, std::optional<uint32_t> nextSlotId, std::shared_ptr<Mantids30::DataFormat::JWT> jwtSigner)
    {
        Mantids30::DataFormat::JWT::Token newTransientAuthToken;

        if (doesTransientTokenNotExist)
        {
            newTransientAuthToken.setJwtId(Mantids30::Helpers::Random::createRandomString(16));
            newTransientAuthToken.setExpirationTime(time(nullptr) + loginAuthenticationTimeout);
        }
        else
        {
            newTransientAuthToken.setExpirationTime(transientAuthToken.getExpirationTime());
        }

        newTokenExpirationTime = newTransientAuthToken.getExpirationTime();

        newTransientAuthToken.setIssuedAt(time(nullptr));
        newTransientAuthToken.setNotBefore(time(nullptr) - 30);
        newTransientAuthToken.setClaim("app", appName);
        newTransientAuthToken.setClaim("preAuthUser", accountName);
        newTransientAuthToken.setClaim("slotSchemeHash", slotSchemeHash);
        newTransientAuthToken.setClaim("schemeId", schemeId);
        newTransientAuthToken.setClaim("keepAuthenticated", keepAuthenticated);
        newTransientAuthToken.setClaim("type", "transient");
        newTransientAuthToken.setClaim("authenticatedSlots", Mantids30::Helpers::setToJSON(authenticatedSlots));
        newTransientAuthToken.setClaim("mustChangeSlots", Mantids30::Helpers::setToJSON(mustChangeSlots));

        if (nextSlotId.has_value())
            newTransientAuthToken.setClaim("currentSlotId", nextSlotId.value()); // Enforce this with authentication.

        return jwtSigner->signFromToken(newTransientAuthToken, false);
    }

    std::string issueSignedTransientTokenFromCurrentToken(std::shared_ptr<Mantids30::DataFormat::JWT> jwtSigner)
    {
        newTokenExpirationTime = transientAuthToken.getExpirationTime();
        return jwtSigner->signFromToken(transientAuthToken, false);
    }

    void fillVarsFromTransientTokenClaims()
    {
        auto claims = transientAuthToken.getAllClaimsAsJSON();

        appName = JSON_ASSTRING(claims, "app", "");
        slotSchemeHash = JSON_ASSTRING(claims, "slotSchemeHash", "");
        schemeId = JSON_ASUINT(claims, "schemeId", UINT32_MAX);
        keepAuthenticated = JSON_ASBOOL(claims, "keepAuthenticated", false);
        currentSlotId = JSON_ASUINT(claims, "currentSlotId", 0);
        authenticatedSlots = Mantids30::Helpers::jsonToUInt32Set(claims, "authenticatedSlots");
        mustChangeSlots = Mantids30::Helpers::jsonToUInt32Set(claims, "mustChangeSlots");
    }

    void fillVarsFromInitialJSONPOST(const json &inputJSON)
    {
        keepAuthenticated = JSON_ASBOOL(inputJSON, "keepAuthenticated", false);
        appName = JSON_ASSTRING(inputJSON, "app", "");
        schemeId = JSON_ASUINT(inputJSON, "schemeId", UINT32_MAX);
        currentSlotId = JSON_ASUINT(inputJSON, "currentSlotId", 0);
        doesTransientTokenNotExist = true;
    }

    void removeSlotFromMustChangeInTheTransientAuthToken(const uint32_t &slotId)
    {
        mustChangeSlots.erase(slotId);
        // Update the claim
        transientAuthToken.setClaim("mustChangeSlots", Mantids30::Helpers::setToJSON(mustChangeSlots));
    }

    time_t newTokenExpirationTime = 0;

    bool doesTransientTokenNotExist = false;
    bool keepAuthenticated = false;
    std::string appName;
    std::string accountName;
    uint32_t schemeId = UINT32_MAX;
    std::optional<uint32_t> currentSlotId = std::nullopt;
    std::string slotSchemeHash;
    std::set<uint32_t> authenticatedSlots;
    std::set<uint32_t> mustChangeSlots;

    Mantids30::DataFormat::JWT::Token transientAuthToken;
};
