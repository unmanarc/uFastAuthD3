#pragma once

#include <Mantids30/DataFormat/JSON/json.h>
#include <Mantids30/DataFormat/JWT/jwt.h>
#include <Mantids30/DataFormat/JSON/json.h>
#include <Mantids30/Core/Helpers/random.h>
#include <Mantids30/Protocol/HTTP/api_return.h>
#include <Mantids30/Protocol/HTTP/rsp_status.h>
#include "IdentityManager/ds_authentication.h"

#include <Mantids30/DataFormat/JSON/json_accessors_array.h>
#include "defs.h"

#include <optional>

using namespace Mantids30;
using namespace Mantids30::Protocol::HTTP;

struct TransientAuthenticationContext
{
    bool validateAndMerge_LPTokenIfExist(std::string_view cookieLPTokenStr, APIReturn &response, const std::shared_ptr<Mantids30::DataFormat::JWT> &jwtValidator)
    {
        Mantids30::DataFormat::JWT::Token lpToken;
        //std::string cookieAccessTokenStr = request.clientRequest->getCookie("AccessToken");

        if (!cookieLPTokenStr.empty())
        {
            if (!jwtValidator->verify(cookieLPTokenStr, &lpToken))
            {
                // Failed to load the intermediary...
                response.setError(Mantids30::Protocol::HTTP::Status::Code::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                                  authResultToString(AuthenticationResult::UNAUTHENTICATED));
                return false;
            }
            if (lpToken.getClaim("app") != IAM_LOGINPORTAL_APPNAME || lpToken.getClaim("type") != "access")
            {
                // This Token is not for this cookie...
                response.setError(Mantids30::Protocol::HTTP::Status::Code::S_403_FORBIDDEN, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::UNAUTHENTICATED)),
                                  authResultToString(AuthenticationResult::UNAUTHENTICATED));
                return false;
            }
            if (lpToken.getSubject() != accountUUID)
            {
                // This Token is not for this cookie... (other username... logout first please!)
                response.setError(Mantids30::Protocol::HTTP::Status::Code::S_401_UNAUTHORIZED, "AUTH_ERR_" + std::to_string(static_cast<uint16_t>(AuthenticationResult::INVALID_ACCOUNT)),
                                  authResultToString(AuthenticationResult::INVALID_ACCOUNT));
                return false;
            }

            // We have an LPToken!
            std::set<uint32_t> authenticatedSlotsOnLPToken = DataFormat::JSON::toUInt32Set(lpToken.getClaim("slotIds"));
            // Merge auth slots.
            for (const uint32_t &i : authenticatedSlotsOnLPToken)
            {
                authenticatedSlots.insert(i);
            }
            // Merge schemes and apps also...
            jAuthenticatedSchemes = DataFormat::JSON::ASARRAY_OR_EMPTY(lpToken.getClaim("authenticatedSchemes"));
            jAuthenticatedAppsCallbackURLs = DataFormat::JSON::ASARRAY_OR_EMPTY(lpToken.getClaim("authenticatedAppsCallbackURLs"));
        }

        return true;
    }

    bool validateAndMerge_TransientAuthTokenIfExist(std::string_view transientAuthTokenStr, const boost::json::value *inputJSON, const std::shared_ptr<Mantids30::DataFormat::JWT>& jwtValidator)
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

    std::string issueSignedTransientTokenFromValues(const uint32_t &loginAuthenticationTimeout, std::optional<uint32_t> nextSlotId, const std::shared_ptr<Mantids30::DataFormat::JWT>& jwtSigner)
    {
        Mantids30::DataFormat::JWT::Token newTransientAuthToken;

        if (doesTransientTokenNotExist)
        {
            newTransientAuthToken.setJwtId(Core::Helpers::Random::createRandomString(16));
            newTransientAuthToken.setExpirationTime(time(nullptr) + loginAuthenticationTimeout);
        }
        else
        {
            newTransientAuthToken.setExpirationTime(transientAuthToken.getExpirationTime());
        }

        newTokenExpirationTime = newTransientAuthToken.getExpirationTime();

        newTransientAuthToken.setIssuedAt(time(nullptr));
        newTransientAuthToken.setNotBefore(time(nullptr) - 30);
        newTransientAuthToken.setClaim("app", boost::json::value(appName));
        newTransientAuthToken.setClaim("accountName", boost::json::value(accountName));
        newTransientAuthToken.setClaim("slotSchemeHash", boost::json::value(slotSchemeHash));
        newTransientAuthToken.setClaim("schemeId", schemeId);
        newTransientAuthToken.setClaim("keepAuthenticated", keepAuthenticated);
        newTransientAuthToken.setClaim("type", "transient");
        newTransientAuthToken.setClaim("authenticatedSlots", DataFormat::JSON::fromSet(authenticatedSlots));
        newTransientAuthToken.setClaim("authenticatedSchemes", jAuthenticatedSchemes);
        newTransientAuthToken.setClaim("authenticatedAppsCallbackURLs", jAuthenticatedAppsCallbackURLs);

        if (nextSlotId.has_value())
        {
            newTransientAuthToken.setClaim("currentSlotId", nextSlotId.value()); // Enforce this with authentication.
        }

        return jwtSigner->signFromToken(newTransientAuthToken, false);
    }

    std::string issueSignedTransientTokenFromCurrentToken(const std::shared_ptr<Mantids30::DataFormat::JWT>& jwtSigner)
    {
        newTokenExpirationTime = transientAuthToken.getExpirationTime();
        return jwtSigner->signFromToken(transientAuthToken, false);
    }

    void fillVars_FromTransientTokenClaims()
    {
        boost::json::value claims = transientAuthToken.getAllClaimsAsJSON();

        accountName = DataFormat::JSON::ASSTRING(claims, "accountName", "");
        appName = DataFormat::JSON::ASSTRING(claims, "app", "");
        slotSchemeHash = DataFormat::JSON::ASSTRING(claims, "slotSchemeHash", "");
        schemeId = DataFormat::JSON::ASUINT(claims, "schemeId", UINT32_MAX);
        keepAuthenticated = DataFormat::JSON::ASBOOL(claims, "keepAuthenticated", false);
        currentSlotId = DataFormat::JSON::ASUINT(claims, "currentSlotId", 0);
        authenticatedSlots = DataFormat::JSON::toUInt32Set(claims, "authenticatedSlots");
        jAuthenticatedSchemes = DataFormat::JSON::ASARRAY_OR_EMPTY(transientAuthToken.getClaim("authenticatedSchemes"));
        jAuthenticatedAppsCallbackURLs = DataFormat::JSON::ASARRAY_OR_EMPTY(transientAuthToken.getClaim("authenticatedAppsCallbackURLs"));

        loadUUIDFromAccountName();
    }

    void fillVars_FromInitialJSONPOST(const boost::json::value &inputJSON)
    {
        accountName = DataFormat::JSON::ASSTRING(inputJSON, "accountName", "");
        keepAuthenticated = DataFormat::JSON::ASBOOL(inputJSON, "keepAuthenticated", false);
        appName = DataFormat::JSON::ASSTRING(inputJSON, "app", "");
        schemeId = DataFormat::JSON::ASUINT(inputJSON, "schemeId", UINT32_MAX);
        currentSlotId = DataFormat::JSON::ASUINT(inputJSON, "currentSlotId", 0);
        doesTransientTokenNotExist = true;

        loadUUIDFromAccountName();
    }

    [[nodiscard]] boost::json::value getAllAuthenticatedSlotsIds() const
    {
        std::set<uint32_t> result = authenticatedSlots;
        if (currentSlotId.has_value())
        {
            result.insert(currentSlotId.value());
        }
        return DataFormat::JSON::fromSet(result);
    }

    [[nodiscard]] boost::json::array getAllAuthenticatedSchemes() const
    {
        boost::json::array r_jAuthenticatedSchemes = jAuthenticatedSchemes;
        if (schemeId != UINT32_MAX)
        {
            r_jAuthenticatedSchemes.push_back(boost::json::value(schemeId));
        }
        return r_jAuthenticatedSchemes;
    }

    [[nodiscard]] boost::json::array getAllAuthenticatedAppsCallbackURLs() const
    {
        boost::json::array r_jAuthenticatedAppsCallbackURLs = jAuthenticatedAppsCallbackURLs;
        r_jAuthenticatedAppsCallbackURLs.push_back(boost::json::value(appCallbackURL));
        return r_jAuthenticatedAppsCallbackURLs;
    }

    void loadUUIDFromAccountName();


    time_t newTokenExpirationTime = 0;

    bool doesTransientTokenNotExist = false;
    bool keepAuthenticated = false;

    std::string appName;
    std::string appCallbackURL;
    std::string accountName;
    std::string accountUUID;
    uint32_t schemeId = UINT32_MAX;
    std::optional<uint32_t> currentSlotId = std::nullopt;
    std::string slotSchemeHash;
    std::set<uint32_t> authenticatedSlots;

    boost::json::array jAuthenticatedSchemes;
    boost::json::array jAuthenticatedAppsCallbackURLs;

    Mantids30::DataFormat::JWT::Token transientAuthToken;
};
