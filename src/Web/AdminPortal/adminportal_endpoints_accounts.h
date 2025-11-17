#pragma once

#include <Mantids30/API_EndpointsAndSessions/api_restful_endpoints.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class AdminPortalMethods_Accounts
{
public:
    using Endpoints = Mantids30::API::RESTful::Endpoints;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

protected:
    static void addEndpoints_Accounts(std::shared_ptr<Endpoints> endpoints);

    // Accounts:
    static APIReturn addAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn doesAccountExist(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn searchAccounts(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn removeAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

    // Fields:
    static APIReturn searchFields(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn addAccountDetailField(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateAccountDetailField(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn removeAccountDetailField(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getAccountDetailField(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getAccountDetailFieldsValues(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateAccountDetailFieldsValues(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

    // Flags:
    static APIReturn getAccountFlags(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn changeAccountFlags(void *context, const RequestParameters &request, ClientDetails &authClientDetails);

    // Accounts-Applications
    static APIReturn getAccountApplications(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn addAccountToApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn removeAccountFromApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails);


    /*
    static APIReturn changeCredential(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn disableAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn confirmAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateAccountInfo(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn changeAccountDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn changeAccoungGivenName(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn changeAccountLastName(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn changeAccountEmail(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn changeAccountExtraData(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn changeAccountExpiration(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn updateAccountRoles(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getAccountInfo(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getAccountDetails(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getAccountLastAccess(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn resetBadAttemptsOnCredential(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getAccountExpirationTime(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn isAccountExpired(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn validateAccountApplicationScope(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getAccountBlockToken(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn blockAccountUsingToken(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn listAccounts(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getAccountRoles(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getAccountDirectApplicationScopes(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
    static APIReturn getAccountUsableApplicationScopes(void *context, const RequestParameters &request, ClientDetails &authClientDetails);
*/
private:
    static std::map<std::string, std::string> jsonToMap(const json &jValue);
};
