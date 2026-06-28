#include "credentialvalidator.h"
#include "IdentityManager/ds_authentication.h"
#include <Mantids30/Helpers/totp.h>

#include <Mantids30/Helpers/crypto.h>
#include <Mantids30/Helpers/encoders.h>

CredentialValidator::CredentialValidator()
{
    usedTokensCacheGC.setGarbageCollectorInterval(5000);
    usedTokensCacheGC.startGarbageCollector(cleanupExpiredTokens, this, "GC:TokensCache");
}

void CredentialValidator::cleanupExpiredTokens()
{
    std::unique_lock<std::mutex> lock(cacheMutex);

    if (useTokenCache)
    {
        time_t now = time(nullptr);
        while (!expirationQueue.empty() && (now - expirationQueue.begin()->first) >= 90)
        {
            usedTokensCache.erase(expirationQueue.begin()->second);
            expirationQueue.erase(expirationQueue.begin());
        }
    }
}

void CredentialValidator::cleanupExpiredTokens(void *asv)
{
    CredentialValidator *_asv = static_cast<CredentialValidator *>(asv);
    _asv->cleanupExpiredTokens();
}

AuthenticationResult CredentialValidator::validateStoredCredential(const std::string &accountUUID, const Credential &storedCredential, const std::string &passwordInput,
                                                                   const std::string &challengeSalt, Mode authMode)
{
    AuthenticationResult r = AuthenticationResult::NOT_IMPLEMENTED;
    //  bool saltedHash = false;
    std::string toCompare;

    if (!storedCredential.slotDetails.passwordFunction.has_value())
    {
        return AuthenticationResult::INTERNAL_ERROR;
    }

    switch (static_cast<HashFunction>(storedCredential.slotDetails.passwordFunction.value()))
    {
    case HashFunction::PLAIN:
    {
        toCompare = passwordInput;
    }
    break;
    case HashFunction::SHA256:
    {
        toCompare = Mantids30::Helpers::Crypto::calcSHA256(passwordInput);
    }
    break;
    case HashFunction::SHA512:
    {
        toCompare = Mantids30::Helpers::Crypto::calcSHA512(passwordInput);
    }
    break;
    case HashFunction::SSHA256:
    {
        toCompare = Mantids30::Helpers::Crypto::calcSSHA256(passwordInput, storedCredential.ssalt);
        // saltedHash = true;
    }
    break;
    case HashFunction::SSHA512:
    {
        toCompare = Mantids30::Helpers::Crypto::calcSSHA512(passwordInput, storedCredential.ssalt);
        //saltedHash = true;
    }
    break;
    case HashFunction::GAUTHTIME:
        r = validateGAuth(accountUUID, storedCredential.hash, passwordInput); // GAuth Time Based Token comparisson (seed,token)
        goto skipAuthMode;
    }

    switch (authMode)
    {
    case Mode::PLAIN:
        r = storedCredential.hash == toCompare ? AuthenticationResult::AUTHENTICATED : AuthenticationResult::AUTHENTICATION_FAILED; // 1-1 comparisson
        break;
    case Mode::CHALLENGE:
        r = validateChallenge(storedCredential.hash, passwordInput, challengeSalt);
        break;
    }

skipAuthMode:;

    if (storedCredential.isExpired() && r == AuthenticationResult::AUTHENTICATED)
    {
        r = AuthenticationResult::EXPIRED_CREDENTIAL;
    }

    if (storedCredential.mustChange && r == AuthenticationResult::AUTHENTICATED)
    {
        r = AuthenticationResult::MUST_CHANGE_CREDENTIAL;
    }

    return r;
}

AuthenticationResult CredentialValidator::validateChallenge(const std::string &passwordFromDB, const std::string &challengeInput, const std::string &challengeSalt)
{
    return challengeInput == Mantids30::Helpers::Crypto::calcSHA256(passwordFromDB + challengeSalt) ? AuthenticationResult::AUTHENTICATED : AuthenticationResult::AUTHENTICATION_FAILED;
}

AuthenticationResult CredentialValidator::validateGAuth(const std::string &accountUUID, const std::string &seed, const std::string &tokenInput)
{
    // Use the mutex to synchronize access to the cache and expirationQueue
    std::unique_lock<std::mutex> lock(cacheMutex);
    TokenCacheKey accountTokenKey = {accountUUID, tokenInput};

    // Check if the token is already in the cache and within the time limit

    if (useTokenCache)
    {
        std::unordered_map<TokenCacheKey, time_t>::iterator cacheEntry = usedTokensCache.find(accountTokenKey);
        if (cacheEntry != usedTokensCache.end())
        {
            time_t tokenTimestamp = cacheEntry->second;
            time_t now = time(nullptr);
            time_t elapsedSeconds = now - tokenTimestamp;

            if (elapsedSeconds < 90)
            {
                // Token Already Used.
                return AuthenticationResult::AUTHENTICATION_FAILED;
            }
        }
    }

    // Verify the token and update the cache and expirationQueue if successful
    if (Mantids30::Helpers::OTP::TOTP::verifyToken(seed, tokenInput))
    {
        // Add token to cache:
        if (useTokenCache)
        {
            time_t now = time(nullptr);
            usedTokensCache[accountTokenKey] = now;
            expirationQueue.insert({now, accountTokenKey});
        }
        return AuthenticationResult::AUTHENTICATED;
    }
    else
    {
        return AuthenticationResult::AUTHENTICATION_FAILED;
    }
}

bool CredentialValidator::getUseTokenCache()
{
    std::unique_lock<std::mutex> lock(cacheMutex);
    return useTokenCache;
}

void CredentialValidator::setUseTokenCache(bool newUseTokenCache)
{
    std::unique_lock<std::mutex> lock(cacheMutex);
    useTokenCache = newUseTokenCache;
    if (!useTokenCache)
    {
        usedTokensCache.clear();
        expirationQueue.clear();
    }
}
