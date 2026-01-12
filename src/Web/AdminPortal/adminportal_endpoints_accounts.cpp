#include "adminportal_endpoints_accounts.h"
#include "IdentityManager/ds_account.h"
#include "IdentityManager/ds_authentication.h"
#include <json/value.h>
#include <Mantids30/Program_Logs/applog.h>

#include "defs.h"
#include "globals.h"
#include <regex>

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocols;

std::map<std::string, std::string> AdminPortalMethods_Accounts::jsonToMap(const json &jValue)
{
    std::map<std::string, std::string> r;
    for (const std::string &memberName : jValue.getMemberNames())
    {
        if (jValue[memberName].isString())
            r[memberName] = JSON_ASSTRING(jValue, memberName, "");
    }
    return r;
}

void AdminPortalMethods_Accounts::addEndpoints_Accounts(std::shared_ptr<Endpoints> endpoints)
{
    using SecurityOptions = Mantids30::API::RESTful::Endpoints::SecurityOptions;

    // Accounts:
    endpoints->addEndpoint(Endpoints::POST, "addAccount",            SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &addAccount);
    endpoints->addEndpoint(Endpoints::GET,  "doesAccountExist",      SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"},   nullptr, &doesAccountExist);
    endpoints->addEndpoint(Endpoints::GET,  "searchAccounts",        SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"},   nullptr, &searchAccounts);
    endpoints->addEndpoint(Endpoints::GET,  "getAccountDetailFieldsValues", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"},   nullptr, &getAccountDetailFieldsValues);
    endpoints->addEndpoint(Endpoints::PUT,  "updateAccountDetailFieldsValues", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &updateAccountDetailFieldsValues);
    endpoints->addEndpoint(Endpoints::GET,  "getAccountFlags",       SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"},   nullptr, &getAccountFlags);
    endpoints->addEndpoint(Endpoints::PATCH, "changeAccountFlags",   SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &changeAccountFlags);
    endpoints->addEndpoint(Endpoints::DELETE, "removeAccount",       SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_DELETE"}, nullptr, &removeAccount);

    // Accounts-Applications:
    endpoints->addEndpoint(Endpoints::GET,  "getAccountApplications", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"},   nullptr, &getAccountApplications);
    endpoints->addEndpoint(Endpoints::POST, "addAccountToApplication", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &addAccountToApplication);
    endpoints->addEndpoint(Endpoints::DELETE, "removeAccountFromApplication", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &removeAccountFromApplication);
    // Fields
    endpoints->addEndpoint(Endpoints::GET,  "searchFields",          SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"CONFIG_READ"},    nullptr, &searchFields);
    endpoints->addEndpoint(Endpoints::POST, "addAccountDetailField", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"CONFIG_WRITE"},   nullptr, &addAccountDetailField);
    endpoints->addEndpoint(Endpoints::PUT, "updateAccountDetailField", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"CONFIG_WRITE"},   nullptr, &updateAccountDetailField);
    endpoints->addEndpoint(Endpoints::DELETE, "removeAccountDetailField", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"CONFIG_WRITE"},   nullptr, &removeAccountDetailField);
    endpoints->addEndpoint(Endpoints::GET,  "getAccountDetailField", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"CONFIG_READ"},    nullptr, &getAccountDetailField);


    // Accounts
    /* endpoints->addEndpoint(Endpoints::POST, "addAccount", &addAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    endpoints->addEndpoint(Endpoints::POST, "changeAccountExpiration", &changeAccountExpiration, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    endpoints->addEndpoint(Endpoints::POST, "changeCredential", &changeCredential, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_PWDDCHANGE"});
    endpoints->addEndpoint(Endpoints::POST, "confirmAccount", &confirmAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    endpoints->addEndpoint(Endpoints::POST, "disableAccount", &disableAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_DISABLE"});
    endpoints->addEndpoint(Endpoints::GET, "doesAccountExist", &doesAccountExist, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    endpoints->addEndpoint(Endpoints::GET, "getAccountBlockToken", &getAccountBlockToken, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    endpoints->addEndpoint(Endpoints::GET, "getAccountDirectApplicationScopes", &getAccountDirectApplicationScopes, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    endpoints->addEndpoint(Endpoints::GET, "getAccountDetails", &getAccountDetails, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    endpoints->addEndpoint(Endpoints::GET, "getAccountExpirationTime", &getAccountExpirationTime, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    endpoints->addEndpoint(Endpoints::GET, "getAccountInfo", &getAccountInfo, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    endpoints->addEndpoint(Endpoints::GET, "getAccountLastAccess", &getAccountLastAccess, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    endpoints->addEndpoint(Endpoints::GET, "getAccountRoles", &getAccountRoles, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    endpoints->addEndpoint(Endpoints::GET, "getAccountUsableApplicationScopes", &getAccountUsableApplicationScopes, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    endpoints->addEndpoint(Endpoints::GET, "isAccountExpired", &isAccountExpired, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    endpoints->addEndpoint(Endpoints::GET, "listAccounts", &listAccounts, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    endpoints->addEndpoint(Endpoints::POST, "resetBadAttemptsOnCredential", &resetBadAttemptsOnCredential, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    endpoints->addEndpoint(Endpoints::GET, "searchAccounts", &searchAccounts, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    endpoints->addEndpoint(Endpoints::POST, "updateAccountInfo", &updateAccountInfo, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    endpoints->addEndpoint(Endpoints::POST, "updateAccountRoles", &updateAccountRoles, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    endpoints->addEndpoint(Endpoints::GET, "validateAccountApplicationScope", &validateAccountApplicationScope, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    endpoints->addEndpoint(Endpoints::POST, "blockAccountUsingToken", &blockAccountUsingToken, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});*/
}



API::APIReturn AdminPortalMethods_Accounts::addAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    // Extract account name from request
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    // Check if account already exists
    if (Globals::getIdentityManager()->accounts->doesAccountExist(accountName))
    {
        response.setError(HTTP::Status::S_406_NOT_ACCEPTABLE, "unacceptable_request", "Account Already Exist");
        return response;
    }

    // Validate that account name is not empty
    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty");
        return response;
    }

    // Validate account name format using regex (alphanumeric only)
    std::regex accountNameExpr("[a-zA-Z0-9]+");
    if (!regex_match(accountName, accountNameExpr))
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account name have invalid characters");
        return response;
    }

    // Initialize account flags from request
    AccountFlags accountFlags;
    accountFlags.fromJSON(request.inputJSON);

    // Add the new account to the system with specified expiration and flags
    if (!Globals::getIdentityManager()->accounts->addAccount(accountName, JSON_ASUINT64(*request.inputJSON, "expirationDate", 0), accountFlags,
                                                             request.jwtToken->getSubject()))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the new account. Check if user already exists");
        return response;
    }

    // Extract credential information from request
    json tempCredential = (*request.inputJSON)["tempCredential"];
    std::string secretTempPass = JSON_ASSTRING(*request.inputJSON, "secretTempPass", "");

    Credential newCredentialData;
    uint32_t slotId = JSON_ASUINT(*request.inputJSON, "slotId", 1);

    // Either tempCredential or secretTempPass must be provided
    if (tempCredential != Json::nullValue)
    {
        newCredentialData = Credential::createFromJSON(tempCredential);
    }
    else if (!secretTempPass.empty())
    {
        newCredentialData = Credential::createSHA256TemporalCredential(secretTempPass);
    }
    else
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Either tempCredential or secretTempPass must be provided");
        return response;
    }

    // Apply the credential to the new account
    if (!Globals::getIdentityManager()->authController->changeCredential(accountName, newCredentialData, slotId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to change the credential on the new user.");
        return response;
    }

    AccountFlags flags;
    flags.fromJSON((*request.inputJSON)["flags"]);

    // Apply the credential to the new account
    if (!Globals::getIdentityManager()->accounts->changeAccountFlags(accountName, flags))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to change the credential on the new user.");
        return response;
    }

    if (!Globals::getIdentityManager()->applications->addAccountToApplication(IAM_USRPORTAL_APPNAME, accountName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to assign user with GENERIC_USER in app '" IAM_USRPORTAL_APPNAME "'.");
        return response;
    }

    if (!Globals::getIdentityManager()->applicationRoles->addAccountToRole(IAM_USRPORTAL_APPNAME, "GENERIC_USER", accountName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to assign user with GENERIC_USER in app '" IAM_USRPORTAL_APPNAME "'.");
        return response;
    }


    return response;
}

API::APIReturn AdminPortalMethods_Accounts::getAccountFlags(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    APIReturn response;
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return response;
    }

    return Globals::getIdentityManager()->accounts->getAccountFlags(accountName).toJSON();
}

API::APIReturn AdminPortalMethods_Accounts::changeAccountFlags(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    APIReturn response;
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (!(*request.inputJSON).isMember("flags"))
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account flags are required");
        return response;
    }

    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return response;
    }

    AccountFlags flags;
    flags.fromJSON((*request.inputJSON)["flags"]);

    bool changed = Globals::getIdentityManager()->accounts->changeAccountFlags(accountName, flags);

    if (!changed)
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error",
                          "The account flags could not be updated. It may be that no other admin exists or there was a database issue.");
        return response;
    }
    return response;
}

API::APIReturn AdminPortalMethods_Accounts::doesAccountExist(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty");
        return response;
    }

    if (!Globals::getIdentityManager()->accounts->doesAccountExist(accountName))
    {
        response.setError(HTTP::Status::S_404_NOT_FOUND, "not_found", "The Account does not exist in the system.");
        return response;
    }
    return response;
}

API::APIReturn AdminPortalMethods_Accounts::searchAccounts(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    return Globals::getIdentityManager()->accounts->searchAccounts(*request.inputJSON);
}

API::APIReturn AdminPortalMethods_Accounts::getAccountApplications(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    const std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    int i = 0;

    std::set<std::string> listAccountApplications = Globals::getIdentityManager()->applications->listAccountApplications(accountName);
    std::set<ApplicationScope> directScopes = Globals::getIdentityManager()->authController->getAccountDirectApplicationScopes(accountName);

    for (const auto &applicationName : listAccountApplications)
    {
        std::set<ApplicationScope> usableScopes = Globals::getIdentityManager()->authController->getAccountUsableApplicationScopes(applicationName,accountName);

        (*response.responseJSON())["applications"][i]["name"] = applicationName;
        // TODO: optimize:
        (*response.responseJSON())["applications"][i]["description"] = Globals::getIdentityManager()->applications->getApplicationDescription(applicationName);

        std::set<ApplicationRole> allAppRoles = Globals::getIdentityManager()->applicationRoles->getApplicationRolesList(applicationName);
        std::set<ApplicationRole> usedAppRoles = Globals::getIdentityManager()->accounts->getAccountRoles(applicationName,accountName);

        // Add used roles
        for (const auto &role : usedAppRoles)
        {
            (*response.responseJSON())["applications"][i]["usedRoles"].append(role.toJSON());
        }

        // Add available roles (roles that can be added)
        std::set<ApplicationRole> availableRoles;
        for (const auto &role : allAppRoles)
        {
            if (usedAppRoles.find(role) == usedAppRoles.end())
            {
                availableRoles.insert(role);
            }
        }

        for (const auto &role : availableRoles)
        {
            (*response.responseJSON())["applications"][i]["availableRoles"].append(role.toJSON());
        }


        int j = 0;
        for (const auto &directApplicationScope : directScopes)
        {
            if (directApplicationScope.appName == applicationName)
            {
                (*response.responseJSON())["applications"][i]["directScopes"][j] = directApplicationScope.toJSON();
                j++;
            }
        }

        j = 0;
        for (const auto &scope : Globals::getIdentityManager()->authController->listApplicationScopes(applicationName))
        {
            if (directScopes.find(scope) == directScopes.end())
            {
                (*response.responseJSON())["applications"][i]["directScopesLeft"][j] = scope.toJSON();
                j++;
            }
        }

        j = 0;
        for (const auto &usableScope : usableScopes)
        {
            (*response.responseJSON())["applications"][i]["usableScopes"][j] = usableScope.toJSON();
            j++;
        }
        i++;
    }

    i = 0;

    for (const auto &applicationName : Globals::getIdentityManager()->applications->listApplications())
    {
        if (listAccountApplications.find(applicationName) == listAccountApplications.end())
        {
            (*response.responseJSON())["applicationsLeft"][i]["name"] = applicationName;
            (*response.responseJSON())["applicationsLeft"][i]["description"] = Globals::getIdentityManager()->applications->getApplicationDescription(
                applicationName);
            i++;
        }
    }
    return response;
}

API::APIReturn AdminPortalMethods_Accounts::addAccountToApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return response;
    }

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applications->addAccountToApplication(appName, accountName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the account to the application.");
        return response;
    }

    return response;
}

API::APIReturn AdminPortalMethods_Accounts::removeAccountFromApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return response;
    }

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return response;
    }

    if (!Globals::getIdentityManager()->applications->removeAccountFromApplication(appName, accountName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the account from the application.");
    }
    return response;
}

API::APIReturn AdminPortalMethods_Accounts::searchFields(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    return Globals::getIdentityManager()->accounts->searchFields(*request.inputJSON);
}

API::APIReturn AdminPortalMethods_Accounts::addAccountDetailField(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    AccountDetailField fieldDetails;
    fieldDetails.fromJSON(*request.inputJSON);
    std::string fieldName = JSON_ASSTRING((*request.inputJSON), "fieldName", "");
    if (fieldName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Field Name is Empty");
        return response;
    }
    if (!Globals::getIdentityManager()->accounts->addAccountDetailField(fieldName, fieldDetails))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "field_already_exists", "Field already exists");
    }

    return response;
}

AdminPortalMethods_Accounts::APIReturn AdminPortalMethods_Accounts::updateAccountDetailField(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    AccountDetailField fieldDetails;
    fieldDetails.fromJSON(*request.inputJSON);
    std::string fieldName = JSON_ASSTRING((*request.inputJSON), "fieldName", "");
    if (fieldName.empty())
    {
        return API::APIReturn(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Field Name is Empty");
    }
    if (!Globals::getIdentityManager()->accounts->updateAccountDetailField(fieldName, fieldDetails))
    {
        return API::APIReturn(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "field_already_exists", "Field already exists");
    }

    return API::APIReturn();
}

API::APIReturn AdminPortalMethods_Accounts::removeAccountDetailField(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string fieldName = JSON_ASSTRING((*request.inputJSON), "fieldName", "");
    if (fieldName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Field Name is Empty");
        return response;
    }
    if (!Globals::getIdentityManager()->accounts->removeAccountDetailField(fieldName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "field_not_found", "Field not found");
    }

    return response;
}

API::APIReturn AdminPortalMethods_Accounts::getAccountDetailField(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string fieldName = JSON_ASSTRING((*request.inputJSON), "fieldName", "");
    if (fieldName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Field Name is Empty");
        return response;
    }
    auto field = Globals::getIdentityManager()->accounts->getAccountDetailField(fieldName);
    if (!field)
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "field_not_found", "Field not found");
        return response;
    }

    return field.value().toJSON();
}

API::APIReturn AdminPortalMethods_Accounts::getAccountDetailFieldsValues(void *context, const RequestParameters &request,
                                                            ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string accountName = JSON_ASSTRING((*request.inputJSON), "accountName", "");
    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty");
        return response;
    }

    std::map<std::string,AccountDetailFieldValue> fieldValues = Globals::getIdentityManager()->accounts->getAccountDetailFieldValues(accountName);

    Json::Value result(Json::arrayValue);
    for (const auto &fieldValue : fieldValues)
    {
        result.append(fieldValue.second.toJSON());
    }

    return result;
}

API::APIReturn AdminPortalMethods_Accounts::updateAccountDetailFieldsValues(void *context, const RequestParameters &request,
                                                               ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string accountName = JSON_ASSTRING((*request.inputJSON), "accountName", "");
    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty");
        return response;
    }

    // Get the list of field values from input
    Json::Value fieldValuesArray = (*request.inputJSON)["fieldValues"];
    if (!fieldValuesArray.isArray())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Field values must be an array");
        return response;
    }

    std::list<AccountDetailFieldValue> fieldValues;

    // Process each field value in the array
    for (Json::ArrayIndex i = 0; i < fieldValuesArray.size(); ++i)
    {
        AccountDetailFieldValue fieldValue;
        fieldValue.fromJSON(fieldValuesArray[i]);
        fieldValues.push_back(fieldValue);
    }

    // Update account detail fields values
    if (!Globals::getIdentityManager()->accounts->updateAccountDetailFieldValues(accountName, fieldValues))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update account detail fields values");
        return response;
    }
    // Return 200.

    return response;
}

API::APIReturn AdminPortalMethods_Accounts::removeAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return response;
    }

    if (!Globals::getIdentityManager()->accounts->removeAccount(accountName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the account.");
    }

    return response;
}


/*
API::APIReturn AdminPortalMethods_Accounts::updateAccountInfo(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    AccountFlags accountFlags;
    accountFlags.fromJSON(request.inputJSON);
    // TODO: set account details granularly...
    if (!Globals::getIdentityManager()->accounts->changeAccountFlags(JSON_ASSTRING(*request.inputJSON, "accountName", ""), accountFlags))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }

    //  Globals::getIdentityManager()->accounts->changeAccountDescription(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"description","")) &&
      //  Globals::getIdentityManager()->accounts->changeAccoungGivenName(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"givenName","")) &&
      //  Globals::getIdentityManager()->accounts->changeAccountLastName(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"lastName","")) &&
      //  Globals::getIdentityManager()->accounts->changeAccountEmail(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"email","")) &&
      //  Globals::getIdentityManager()->accounts->changeAccountExtraData(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"extraData","")) &&
}*/

/*
API::APIReturn AdminPortalMethods_Accounts::changeAccountDescription(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->accounts->changeAccountDescription(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"description",""));
}

API::APIReturn AdminPortalMethods_Accounts::changeAccoungGivenName(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->accounts->changeAccoungGivenName(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"givenName",""));
}

API::APIReturn AdminPortalMethods_Accounts::changeAccountLastName(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->accounts->changeAccountLastName(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"lastName",""));
}

API::APIReturn AdminPortalMethods_Accounts::changeAccountEmail(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->accounts->changeAccountEmail(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"email",""));
}

API::APIReturn AdminPortalMethods_Accounts::changeAccountExtraData(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->accounts->changeAccountExtraData(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"extraData",""));
}*/
/*
API::APIReturn AdminPortalMethods_Accounts::updateAccountRoles(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::set<std::string> roleSet;

    if (!(*request.inputJSON)["roles"].isArray())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Invalid Parameters");
        return response;
    }

    for (size_t i = 0; i < (*request.inputJSON)["roles"].size(); i++)
    {
        roleSet.insert((*request.inputJSON)["roles"][(int) i].asString());
    }

    if (!Globals::getIdentityManager()->accounts->updateAccountRoles(JSON_ASSTRING(*request.inputJSON, "accountName", ""), roleSet))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
        return response;
    }
}

API::APIReturn AdminPortalMethods_Accounts::validateAccountApplicationScope(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->authController->validateAccountApplicationScope(JSON_ASSTRING(*request.inputJSON, "accountName", ""),
                                                                                                                     {JSON_ASSTRING(*request.inputJSON, "appName", ""),
                                                                                                                      JSON_ASSTRING(*request.inputJSON, "id", "")});
}

API::APIReturn AdminPortalMethods_Accounts::blockAccountUsingToken(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->accounts->blockAccountUsingToken(JSON_ASSTRING(*request.inputJSON, "accountName", ""), JSON_ASSTRING(*request.inputJSON, "blockToken", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}*/

/*
API::APIReturn AdminPortalMethods_Accounts::changeAccountExpiration(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->accounts->changeAccountExpiration(JSON_ASSTRING(*request.inputJSON, "accountName", ""), JSON_ASUINT64(*request.inputJSON, "expiration", 0)))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

API::APIReturn AdminPortalMethods_Accounts::changeCredential(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    Credential credentialData;
    credentialData.fromJSON((*request.inputJSON)["credentialData"]);
    if (!Globals::getIdentityManager()->authController->changeCredential(JSON_ASSTRING(*request.inputJSON, "accountName", ""), credentialData, JSON_ASUINT(*request.inputJSON, "slotId", 0)))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

API::APIReturn AdminPortalMethods_Accounts::confirmAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->accounts->disableAccount(JSON_ASSTRING(*request.inputJSON, "accountName", ""), JSON_ASBOOL(*request.inputJSON, "disabled", false)))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

API::APIReturn AdminPortalMethods_Accounts::disableAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->accounts->disableAccount(JSON_ASSTRING(*request.inputJSON, "accountName", ""), JSON_ASBOOL(*request.inputJSON, "disabled", false)))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}*/
/*
API::APIReturn AdminPortalMethods_Accounts::getAccountBlockToken(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->accounts->getAccountBlockToken(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
}

API::APIReturn AdminPortalMethods_Accounts::getAccountDirectApplicationScopes(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = AdminPortal_Endpoints::scopeListToJSON(
        Globals::getIdentityManager()->authController->getAccountDirectApplicationScopes(JSON_ASSTRING(*request.inputJSON, "accountName", "")));
}

API::APIReturn AdminPortalMethods_Accounts::getAccountDetails(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    auto getAccountDetails = Globals::getIdentityManager()->accounts->getAccountDetails(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
    // Llenar el payloadOut con los detalles de la cuenta
    (*response.responseJSON()) = getAccountDetails.toJSON();
}

API::APIReturn AdminPortalMethods_Accounts::getAccountExpirationTime(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Json::Int64(Globals::getIdentityManager()->accounts->getAccountExpirationTime(JSON_ASSTRING(*request.inputJSON, "accountName", "")));
}



API::APIReturn AdminPortalMethods_Accounts::getAccountInfo(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    getAccountDetails(context, response, request, authClientDetails);

    int i = 0;
    auto getAccountRoles = Globals::getIdentityManager()->accounts->getAccountRoles(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
    for (const auto &roleName : getAccountRoles)
    {
        (*response.responseJSON())["roles"][i]["name"] = roleName;
        // TODO: optimize:
        (*response.responseJSON())["roles"][i]["description"] = Globals::getIdentityManager()->roles->getApplicationRoleDescription(roleName);
        i++;
    }

    i = 0;
    for (const auto &roleName : Globals::getIdentityManager()->roles->getApplicationRolesList())
    {
        if (getAccountRoles.find(roleName) == getAccountRoles.end())
        {
            (*response.responseJSON())["rolesLeft"][i]["name"] = roleName;
            (*response.responseJSON())["rolesLeft"][i]["description"] = Globals::getIdentityManager()->roles->getApplicationRoleDescription(roleName);
            i++;
        }
    }


}

API::APIReturn AdminPortalMethods_Accounts::getAccountLastAccess(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->authController->getAccountLastAccess(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
}

API::APIReturn AdminPortalMethods_Accounts::getAccountRoles(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->accounts->getAccountRoles(JSON_ASSTRING(*request.inputJSON, "accountName", "")));
}

API::APIReturn AdminPortalMethods_Accounts::getAccountUsableApplicationScopes(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = AdminPortal_Endpoints::scopeListToJSON(
        Globals::getIdentityManager()->authController->getAccountUsableApplicationScopes(JSON_ASSTRING(*request.inputJSON, "accountName", "")));
}

API::APIReturn AdminPortalMethods_Accounts::isAccountExpired(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->accounts->isAccountExpired(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
}

API::APIReturn AdminPortalMethods_Accounts::listAccounts(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->accounts->listAccounts());
}


API::APIReturn AdminPortalMethods_Accounts::resetBadAttemptsOnCredential(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    Globals::getIdentityManager()->authController->resetBadAttemptsOnCredential(JSON_ASSTRING(*request.inputJSON, "accountName", ""), JSON_ASUINT(*request.inputJSON, "slotId", 0));
}
*/
