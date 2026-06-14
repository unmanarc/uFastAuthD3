#include "tokensmanager.h"

#include "IdentityManager/identitymanager.h"
#include "globals.h"
#include <memory>

using namespace Mantids30;
using namespace Mantids30::Network::Protocols;
using namespace API::RESTful;

void TokensManager::configureApplicationAccessToken(Mantids30::DataFormat::JWT::Token &accessToken, const std::string &refreshTokenId, const std::string &jwtAccountName, const std::string &appName,
                                         const ApplicationTokenProperties &tokenProperties, const std::set<uint32_t> &slotIds)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    std::string tokenId = Mantids30::Helpers::Random::createRandomString(16);
    accessToken.setSubject(jwtAccountName);
    accessToken.setIssuedAt(time(nullptr));
    time_t expectedExpirationTime = time(nullptr) + JSON_ASUINT64(tokenProperties.tokensConfiguration["accessToken"], "timeout", 300);
    time_t accountExpirationTime = identityManager->accounts->getAccountExpirationTime(jwtAccountName);

    if (accountExpirationTime == 0 || accountExpirationTime >= expectedExpirationTime)
    {
        // We can safely use the expected token expiration time
        accessToken.setExpirationTime(expectedExpirationTime);
    }
    else
    {
        // The account expires before, so the tokens need to expire before:
        accessToken.setExpirationTime(accountExpirationTime);
    }

    accessToken.setNotBefore(time(nullptr) - 30);
    accessToken.setClaim("sessionInactivityTimeout", tokenProperties.sessionInactivityTimeout);
    accessToken.setClaim("slotIds", Mantids30::Helpers::setToJSON(slotIds));
    accessToken.setJwtId(tokenId);
    accessToken.setClaim("parentTokenId", refreshTokenId);
    accessToken.setClaim("app", appName);
    accessToken.setClaim("type", "access");
    //accessToken.setClaim( "tokensConfig", tokenProperties.tokensConfiguration["accessToken"] );

    // Get the user scope if needed for this application...
    if (tokenProperties.includeApplicationScopes)
    {
        auto x = identityManager->authController->getAccountUsableApplicationScopes(appName, jwtAccountName);
        for (const auto &i : x)
        {
            accessToken.addScope(i.id);
        }
    }
    // Get the user basic info if needed for this application...
    if (tokenProperties.includeBasicAccountInfo)
    {
        if (auto info = identityManager->accounts->getAccountDetails(jwtAccountName, ACCOUNT_DETAILS_TOKEN))
        {
            accessToken.setClaim("accountInfo", info->toJSON());
        }
    }

    // Application Admin
    if (identityManager->applications->isApplicationAdmin(appName, jwtAccountName))
    {
        accessToken.setClaim("isAdmin", true);
    }
}

void TokensManager::configureApplicationRefreshToken(Mantids30::DataFormat::JWT::Token &refreshToken, const std::string &refreshTokenId, const std::string &jwtAccountName, const std::string &appName,
                                          const ApplicationTokenProperties &tokenProperties, const std::set<uint32_t> &slotIds, const bool & keepAuthenticated)
{
    IdentityManager *identityManager = Globals::getIdentityManager();


    auto expectedExpirationTime = time(nullptr) + JSON_ASUINT64(tokenProperties.tokensConfiguration["refreshToken"], "timeout", 2592000);
    auto accountExpirationTime = identityManager->accounts->getAccountExpirationTime(jwtAccountName);

    if (accountExpirationTime == 0 || accountExpirationTime >= expectedExpirationTime)
    {
        // We can safely use the expected token expiration time
        refreshToken.setExpirationTime(expectedExpirationTime);
    }
    else
    {
        // The account expires before, so the tokens need to expire before:
        refreshToken.setExpirationTime(accountExpirationTime);
    }

    refreshToken.setSubject(jwtAccountName);
    refreshToken.setIssuedAt(time(nullptr));
    refreshToken.setNotBefore(time(nullptr) - 30);
    refreshToken.setClaim("slotIds", Mantids30::Helpers::setToJSON(slotIds));
    refreshToken.setJwtId(refreshTokenId);
    refreshToken.setClaim("app", appName);
    refreshToken.setClaim("keepAuthenticated", keepAuthenticated);
    refreshToken.setClaim("type", "refresher");
}

/*
void TokensManager::configureLogoutToken(const Mantids30::DataFormat::JWT::Token &refreshToken, Mantids30::DataFormat::JWT::Token &logoutToken)
{
    logoutToken = refreshToken;
    logoutToken.setClaim("type", "logout");
}*/

void TokensManager::issueLPTokenCookie(APIReturn &response, const RequestParameters &request, std::shared_ptr<TransientAuthenticationContext> authContext)
{
    IdentityManager *identityManager = Globals::getIdentityManager();
    Mantids30::DataFormat::JWT::Token lpToken;
    auto accountExpirationTime = identityManager->accounts->getAccountExpirationTime(authContext->accountName);
    authContext->appCallbackURL = identityManager->applications->getApplicationCallbackURI(authContext->appName);
    time_t expectedRefresherTokenTimeoutTime = safeAdd(time(nullptr), Globals::pConfig.get<time_t>("LoginPortal.IAMTokenTimeout", 2592000));

    if (!authContext->keepAuthenticated)
    {
        expectedRefresherTokenTimeoutTime = authContext->newTokenExpirationTime;
    }

    lpToken.setSubject(authContext->accountName);
    lpToken.setIssuedAt(time(nullptr));
    lpToken.setExpirationTime(accountExpirationTime == 0 ? expectedRefresherTokenTimeoutTime :       // Token does not expire.
                                      std::min(accountExpirationTime, expectedRefresherTokenTimeoutTime) // Token expires, take the min time between two...
    );
    lpToken.setNotBefore(time(nullptr) - 30);
    lpToken.setClaim("slotIds",                 authContext->getAllAuthenticatedSlotsIds());
    lpToken.setClaim("authenticatedSchemes",    authContext->getAllAuthenticatedSchemes());
    lpToken.setClaim("authenticatedAppsCallbackURLs",    authContext->getAllAuthenticatedAppsCallbackURLs());
    lpToken.setClaim("type", "access");
    lpToken.setClaim("app", IAM_LOGINPORTAL_APPNAME);
    lpToken.setClaim("keepAuthenticated", authContext->keepAuthenticated);

    lpToken.setJwtId(Mantids30::Helpers::Random::createRandomString(16));

    std::string sAuthToken = request.jwtSigner->signFromToken(lpToken, false);

    // Keep the auth refresher token here:
    response.cookiesMap["LPToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["LPToken"].setExpiration(lpToken.getExpirationTime());
    response.cookiesMap["LPToken"].secure = true;
    response.cookiesMap["LPToken"].httpOnly = true;
    response.cookiesMap["LPToken"].value = sAuthToken;

    Json::Value authenticationPublicData;
    authenticationPublicData["exp"] = std::to_string(lpToken.getExpirationTime());
    authenticationPublicData["subject"] = authContext->accountName;
    authenticationPublicData["slotIds"] = Mantids30::Helpers::setToJSON(authContext->authenticatedSlots);
    authenticationPublicData["authenticatedSchemes"] = authContext->getAllAuthenticatedSchemes();
    authenticationPublicData["authenticatedAppsCallbackURLs"] = authContext->getAllAuthenticatedAppsCallbackURLs();

    // TODO: account data?
    if (authContext->keepAuthenticated)
    {
        response.cookiesMap["loggedIn"] = HTTP::Headers::Cookie();
        response.cookiesMap["loggedIn"].setExpiration(lpToken.getExpirationTime());
        response.cookiesMap["loggedIn"].secure = true;
        response.cookiesMap["loggedIn"].httpOnly = false;
        response.cookiesMap["loggedIn"].path = "/";
        response.cookiesMap["loggedIn"].value = Helpers::Encoders::encodeToBase64(authenticationPublicData.toStyledString());
    }
}
