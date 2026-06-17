#pragma once

#include "json/value.h"
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
    bool validateAndMerge_LPTokenIfExist(const std::string &cookieLPTokenStr, Mantids30::API::APIReturn &response, const std::shared_ptr<Mantids30::DataFormat::JWT> &jwtValidator)
    {
        Mantids30::DataFormat::JWT::Token lpToken;
        //std::string cookieAccessTokenStr = request.clientRequest->getCookie("AccessToken");

        if (!cookieLPTokenStr.empty())
        {
            if (!jwtValidator->verify(cookieLPTokenStr, &lpToken))
            {
                // Failed to load the intermediary...
                response.setError(Mantids30::Network::Protocol::HTTP::Status::Code::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                                  authResultToString(AuthenticationResult::UNAUTHENTICATED));
                return false;
            }
            if (lpToken.getClaim("app") != IAM_LOGINPORTAL_APPNAME || lpToken.getClaim("type") != "access")
            {
                // This Token is not for this cookie...
                response.setError(Mantids30::Network::Protocol::HTTP::Status::Code::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                                  authResultToString(AuthenticationResult::UNAUTHENTICATED));
                return false;
            }
            if (lpToken.getSubject() != accountName)
            {
                // This Token is not for this cookie... (other username... logout first please!)
                response.setError(Mantids30::Network::Protocol::HTTP::Status::Code::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::BAD_ACCOUNT)),
                                  authResultToString(AuthenticationResult::BAD_ACCOUNT));
                return false;
            }

            // We have an LPToken!
            std::set<uint32_t> authenticatedSlotsOnLPToken = Mantids30::Helpers::jsonToUInt32Set(lpToken.getClaim("slotIds"));
            // Merge auth slots.
            for (const uint32_t &i : authenticatedSlotsOnLPToken)
            {
                authenticatedSlots.insert(i);
            }
            // Merge schemes and apps also...
            jAuthenticatedSchemes = lpToken.getClaim("authenticatedSchemes");
            jAuthenticatedAppsCallbackURLs = lpToken.getClaim("authenticatedAppsCallbackURLs");
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
            fillVars_FromTransientTokenClaims();
        }
        else
        {
            // When there is no token, override initial token parameters with the input parameters...
            fillVars_FromInitialJSONPOST(*inputJSON);
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
        newTransientAuthToken.setClaim("authenticatedSchemes", jAuthenticatedSchemes);
        newTransientAuthToken.setClaim("authenticatedAppsCallbackURLs", jAuthenticatedAppsCallbackURLs);

        if (nextSlotId.has_value())
        {
            newTransientAuthToken.setClaim("currentSlotId", nextSlotId.value()); // Enforce this with authentication.
        }

        return jwtSigner->signFromToken(newTransientAuthToken, false);
    }

    std::string issueSignedTransientTokenFromCurrentToken(std::shared_ptr<Mantids30::DataFormat::JWT> jwtSigner)
    {
        newTokenExpirationTime = transientAuthToken.getExpirationTime();
        return jwtSigner->signFromToken(transientAuthToken, false);
    }

    void fillVars_FromTransientTokenClaims()
    {
        Json::Value claims = transientAuthToken.getAllClaimsAsJSON();

        accountName = JSON_ASSTRING(claims, "preAuthUser", "");
        appName = JSON_ASSTRING(claims, "app", "");
        slotSchemeHash = JSON_ASSTRING(claims, "slotSchemeHash", "");
        schemeId = JSON_ASUINT(claims, "schemeId", UINT32_MAX);
        keepAuthenticated = JSON_ASBOOL(claims, "keepAuthenticated", false);
        currentSlotId = JSON_ASUINT(claims, "currentSlotId", 0);
        authenticatedSlots = Mantids30::Helpers::jsonToUInt32Set(claims, "authenticatedSlots");
        jAuthenticatedSchemes = transientAuthToken.getClaim("authenticatedSchemes");
        jAuthenticatedAppsCallbackURLs = transientAuthToken.getClaim("authenticatedAppsCallbackURLs");
    }

    void fillVars_FromInitialJSONPOST(const json &inputJSON)
    {
        accountName = JSON_ASSTRING(inputJSON, "preAuthUser", "");
        keepAuthenticated = JSON_ASBOOL(inputJSON, "keepAuthenticated", false);
        appName = JSON_ASSTRING(inputJSON, "app", "");
        schemeId = JSON_ASUINT(inputJSON, "schemeId", UINT32_MAX);
        currentSlotId = JSON_ASUINT(inputJSON, "currentSlotId", 0);
        doesTransientTokenNotExist = true;
    }

    Json::Value getAllAuthenticatedSlotsIds()
    {
        std::set<uint32_t> r = authenticatedSlots;
        if (currentSlotId.has_value())
        {
            r.insert(currentSlotId.value());
        }
        return Mantids30::Helpers::setToJSON(r);
    }

    Json::Value getAllAuthenticatedSchemes()
    {
        Json::Value r_jAuthenticatedSchemes = jAuthenticatedSchemes;
        if (schemeId != UINT32_MAX)
        {
            r_jAuthenticatedSchemes.append(schemeId);
        }
        return r_jAuthenticatedSchemes;
    }

    Json::Value getAllAuthenticatedAppsCallbackURLs()
    {
        Json::Value r_jAuthenticatedAppsCallbackURLs = jAuthenticatedAppsCallbackURLs;
        r_jAuthenticatedAppsCallbackURLs.append(appCallbackURL);
        return r_jAuthenticatedAppsCallbackURLs;
    }

    time_t newTokenExpirationTime = 0;

    bool doesTransientTokenNotExist = false;
    bool keepAuthenticated = false;

    std::string appName;
    std::string appCallbackURL;
    std::string accountName;
    uint32_t schemeId = UINT32_MAX;
    std::optional<uint32_t> currentSlotId = std::nullopt;
    std::string slotSchemeHash;
    std::set<uint32_t> authenticatedSlots;

    Json::Value jAuthenticatedSchemes = Json::arrayValue;
    Json::Value jAuthenticatedAppsCallbackURLs = Json::arrayValue;

    Mantids30::DataFormat::JWT::Token transientAuthToken;
};
