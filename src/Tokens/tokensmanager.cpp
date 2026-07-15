#include "tokensmanager.h"

#include "globals.h"
#include <memory>

using namespace Mantids30;
using namespace Mantids30::Network::Protocol;
using namespace API::RESTful;

time_t TokensManager::getExpirationTime(const ApplicationTokenCommonParams &commonParams, IdentityManager *identityManager, const std::string &tokenType, time_t defaultTimeout)
{
    time_t expectedExpirationTime = time(nullptr) + Helpers::JSON::ASINT64(commonParams.appAuthSettings.tokensConfiguration[tokenType], "timeout", defaultTimeout);
    time_t accountExpirationTime = identityManager->accounts->getAccountExpirationTime(commonParams.jwtAccountName);

    if (accountExpirationTime == 0 || accountExpirationTime >= expectedExpirationTime)
    {
        // We can safely use the expected token expiration time
        return expectedExpirationTime;
    }
    else
    {
        // The account expires before, so the tokens need to expire before:
        return accountExpirationTime;
    }
}

void TokensManager::configureApplicationAccessToken(Mantids30::DataFormat::JWT::Token &accessToken, const ApplicationTokenCommonParams &commonParams)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    std::string tokenId = Mantids30::Helpers::Random::createRandomString(16);
    accessToken.setSubject(commonParams.jwtAccountName);
    accessToken.setIssuedAt(time(nullptr));
    accessToken.setExpirationTime(TokensManager::getExpirationTime(commonParams, identityManager, "accessToken", 300));
    accessToken.setNotBefore(time(nullptr) - 30);
    accessToken.setClaim("slotIds", Helpers::JSON::fromSet(commonParams.slotIds));
    accessToken.setJwtId(tokenId);
    accessToken.setClaim("parentTokenId", commonParams.refreshTokenId);
    accessToken.setClaim("app", commonParams.appName);
    accessToken.setClaim("type", "access");
    //accessToken.setClaim( "tokensConfig", appAuthSettings.tokensConfiguration["accessToken"] );

    // Get the user scope if needed for this application...
    if (commonParams.appAuthSettings.includeApplicationScopes)
    {
        std::set<ApplicationScope> x = identityManager->applicationScopes->getAccountUsableApplicationScopes(commonParams.appName, commonParams.jwtAccountName);
        for (const ApplicationScope &appScope : x)
        {
            accessToken.addScope(appScope.id);
        }
    }
    // Get the user basic info if needed for this application...
    if (commonParams.appAuthSettings.includeBasicAccountInfo)
    {
        if (std::optional<AccountDetails> info = identityManager->accounts->getAccountDetails(commonParams.jwtAccountName, AccountDetailsToShow::TOKEN))
        {
            accessToken.setClaim("accountInfo", info->toJSON());
        }
    }

    // Application Admin
    if (identityManager->applications->isApplicationAdmin(commonParams.appName, commonParams.jwtAccountName))
    {
        accessToken.setClaim("isAdmin", true);
    }
}

void TokensManager::configureApplicationRefreshToken(Mantids30::DataFormat::JWT::Token &refreshToken, const ApplicationTokenCommonParams &commonParams, const RefreshTokenParams &refreshParams)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    refreshToken.setExpirationTime(TokensManager::getExpirationTime(commonParams, identityManager, "refreshToken", 2592000));
    refreshToken.setSubject(commonParams.jwtAccountName);
    refreshToken.setIssuedAt(time(nullptr));
    refreshToken.setNotBefore(time(nullptr) - 30);
    refreshToken.setClaim("slotIds", Helpers::JSON::fromSet(commonParams.slotIds));
    refreshToken.setJwtId(commonParams.refreshTokenId);
    refreshToken.setClaim("app", commonParams.appName);
    refreshToken.setClaim("activity", refreshParams.activity);
    refreshToken.setClaim("keepAuthenticated", refreshParams.keepAuthenticated);
    refreshToken.setClaim("useEmbeddedInPortalAuthentication", refreshParams.useEmbeddedInPortalAuthentication);
    refreshToken.setClaim("type", "refresher");
}

void TokensManager::configureLPToken(Mantids30::DataFormat::JWT::Token &lpToken, const std::shared_ptr<TransientAuthenticationContext> &authContext)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    time_t accountExpirationTime = identityManager->accounts->getAccountExpirationTime(authContext->accountUUID);
    time_t expectedRefresherTokenTimeoutTime = safe_add(time(nullptr), Globals::pConfig.get<time_t>("LoginPortal.IAMTokenTimeout", 2592000));

    if (!authContext->keepAuthenticated)
    {
        expectedRefresherTokenTimeoutTime = authContext->newTokenExpirationTime;
    }

    lpToken.setSubject(authContext->accountUUID);
    lpToken.setIssuedAt(time(nullptr));
    lpToken.setExpirationTime(accountExpirationTime == 0 ? expectedRefresherTokenTimeoutTime :       // Token does not expire.
                                  std::min(accountExpirationTime, expectedRefresherTokenTimeoutTime) // Token expires, take the min time between two...
    );
    lpToken.setNotBefore(time(nullptr) - 30);
    lpToken.setClaim("slotIds", authContext->getAllAuthenticatedSlotsIds());
    lpToken.setClaim("authenticatedSchemes", authContext->getAllAuthenticatedSchemes());
    lpToken.setClaim("authenticatedAppsCallbackURLs", authContext->getAllAuthenticatedAppsCallbackURLs());
    lpToken.setClaim("type", "access");
    lpToken.setClaim("app", IAM_LOGINPORTAL_APPNAME);
    lpToken.setClaim("keepAuthenticated", authContext->keepAuthenticated);
    lpToken.setJwtId(Mantids30::Helpers::Random::createRandomString(16));
}

void TokensManager::issueLPTokenCookie(APIReturn &response, const RequestContext &request, const std::shared_ptr<TransientAuthenticationContext> &authContext)
{
    IdentityManager *identityManager = Globals::getIdentityManager();
    Mantids30::DataFormat::JWT::Token lpToken;
    authContext->appCallbackURL = identityManager->applications->getApplicationCallbackURI(authContext->appName);

    TokensManager::configureLPToken(lpToken, authContext);

    std::string sAuthToken = request.jwtSigner->signFromToken(lpToken, false);

    // Keep the auth refresher token here:
    response.cookiesMap["LPToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["LPToken"].setExpiration(lpToken.getExpirationTime());
    response.cookiesMap["LPToken"].secure = true;
    response.cookiesMap["LPToken"].httpOnly = true;
    response.cookiesMap["LPToken"].value = sAuthToken;

    Json::Value authenticationPublicData;
    authenticationPublicData["exp"] = std::to_string(lpToken.getExpirationTime());
    authenticationPublicData["subject"] = authContext->accountUUID;
    authenticationPublicData["displayName"] =  identityManager->accounts->getAccountDisplayName(authContext->accountUUID);
    authenticationPublicData["slotIds"] = Helpers::JSON::fromSet(authContext->authenticatedSlots);
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
