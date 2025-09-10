#include "webadmin_methods_accounts.h"

#include "IdentityManager/ds_account.h"
#include "webadmin_methods.h"

#include "IdentityManager/ds_authentication.h"
#include "json/value.h"
#include <Mantids30/Program_Logs/applog.h>

#include "../globals.h"
#include <regex>

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocols;

std::map<std::string, std::string> WebAdminMethods_Accounts::jsonToMap(const json &jValue)
{
    std::map<std::string, std::string> r;
    for (const std::string &memberName : jValue.getMemberNames())
    {
        if (jValue[memberName].isString())
            r[memberName] = JSON_ASSTRING(jValue, memberName, "");
    }
    return r;
}

void WebAdminMethods_Accounts::addMethods_Accounts(std::shared_ptr<MethodsHandler> methods)
{
    using SecurityOptions = Mantids30::API::RESTful::MethodsHandler::SecurityOptions;

    // Accounts:
    methods->addResource(MethodsHandler::POST, "addAccount", &addAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::GET, "doesAccountExist", &doesAccountExist, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "searchAccounts", &searchAccounts, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountDetailFieldsValues", &getAccountDetailFieldsValues, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH,
                         {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::PUT, "updateAccountDetailFieldsValues", &updateAccountDetailFieldsValues, nullptr,
                         SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::GET, "getAccountFlags", &getAccountFlags, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::PATCH, "changeAccountFlags", &changeAccountFlags, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH,
                         {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::DELETE, "removeAccount", &removeAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_DELETE"});


    //Accounts-Applications:
    methods->addResource(MethodsHandler::GET, "getAccountApplications", &getAccountApplications, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH,
                         {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::POST, "addAccountToApplication", &addAccountToApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH,
                         {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::DELETE, "removeAccountFromApplication", &removeAccountFromApplication, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH,
                         {"ACCOUNT_MODIFY"});

    // Fields
    methods->addResource(MethodsHandler::GET, "searchFields", &searchFields, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"CONFIG_READ"});
    methods->addResource(MethodsHandler::POST, "addAccountDetailField", &addAccountDetailField, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH,
                         {"CONFIG_WRITE"});
    methods->addResource(MethodsHandler::DELETE, "removeAccountDetailField", &removeAccountDetailField, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH,
                         {"CONFIG_WRITE"});
    methods->addResource(MethodsHandler::GET, "getAccountDetailField", &getAccountDetailField, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH,
                         {"CONFIG_READ"});


    // Accounts
    /* methods->addResource(MethodsHandler::POST, "addAccount", &addAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::POST, "changeAccountExpiration", &changeAccountExpiration, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::POST, "changeCredential", &changeCredential, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_PWDDCHANGE"});
    methods->addResource(MethodsHandler::POST, "confirmAccount", &confirmAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::POST, "disableAccount", &disableAccount, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_DISABLE"});
    methods->addResource(MethodsHandler::GET, "doesAccountExist", &doesAccountExist, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountBlockToken", &getAccountBlockToken, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::GET, "getAccountDirectApplicationScopes", &getAccountDirectApplicationScopes, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountDetails", &getAccountDetails, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountExpirationTime", &getAccountExpirationTime, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountInfo", &getAccountInfo, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountLastAccess", &getAccountLastAccess, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountRoles", &getAccountRoles, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "getAccountUsableApplicationScopes", &getAccountUsableApplicationScopes, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "isAccountExpired", &isAccountExpired, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::GET, "listAccounts", &listAccounts, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::POST, "resetBadAttemptsOnCredential", &resetBadAttemptsOnCredential, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::GET, "searchAccounts", &searchAccounts, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::POST, "updateAccountInfo", &updateAccountInfo, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::POST, "updateAccountRoles", &updateAccountRoles, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});
    methods->addResource(MethodsHandler::GET, "validateAccountApplicationScope", &validateAccountApplicationScope, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"});
    methods->addResource(MethodsHandler::POST, "blockAccountUsingToken", &blockAccountUsingToken, nullptr, SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"});*/
}

void WebAdminMethods_Accounts::addAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    // Extract account name from request
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    // Check if account already exists
    if (Globals::getIdentityManager()->accounts->doesAccountExist(accountName))
    {
        response.setError(HTTP::Status::S_406_NOT_ACCEPTABLE, "unacceptable_request", "Account Already Exist");
        return;
    }

    // Validate that account name is not empty
    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty");
        return;
    }

    // Validate account name format using regex (alphanumeric only)
    std::regex accountNameExpr("[a-zA-Z0-9]+");
    if (!regex_match(accountName, accountNameExpr))
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account name have invalid characters");
        return;
    }

    // Initialize account flags from request
    AccountFlags accountFlags;
    accountFlags.fromJSON(request.inputJSON);

    // Add the new account to the system with specified expiration and flags
    if (!Globals::getIdentityManager()->accounts->addAccount(accountName, JSON_ASUINT64(*request.inputJSON, "expirationDate", 0), accountFlags,
                                                             request.jwtToken->getSubject()))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the new account. Check if user already exists");
        return;
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
        return;
    }

    // Apply the credential to the new account
    if (!Globals::getIdentityManager()->authController->changeCredential(accountName, newCredentialData, slotId))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to change the credential on the new user.");
        return;
    }

    AccountFlags flags;
    flags.fromJSON((*request.inputJSON)["flags"]);

    // Apply the credential to the new account
    if (!Globals::getIdentityManager()->accounts->changeAccountFlags(accountName, flags))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to change the credential on the new user.");
        return;
    }
}

void WebAdminMethods_Accounts::getAccountFlags(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return;
    }

    (*response.responseJSON()) = Globals::getIdentityManager()->accounts->getAccountFlags(accountName).toJSON();
}

void WebAdminMethods_Accounts::changeAccountFlags(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (!(*request.inputJSON).isMember("flags"))
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account flags are required");
        return;
    }

    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return;
    }

    AccountFlags flags;
    flags.fromJSON((*request.inputJSON)["flags"]);

    bool changed = Globals::getIdentityManager()->accounts->changeAccountFlags(accountName, flags);

    if (!changed)
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error",
                          "The account flags could not be updated. It may be that no other admin exists or there was a database issue.");
        return;
    }
}

void WebAdminMethods_Accounts::doesAccountExist(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty");
        return;
    }

    if (!Globals::getIdentityManager()->accounts->doesAccountExist(accountName))
    {
        response.setError(HTTP::Status::S_404_NOT_FOUND, "not_found", "The Account does not exist in the system.");
        return;
    }
}

void WebAdminMethods_Accounts::searchAccounts(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->accounts->searchAccounts(*request.inputJSON);
}

void WebAdminMethods_Accounts::getAccountApplications(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
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

        std::set<ApplicationRole> allAppRoles = Globals::getIdentityManager()->applicationRoles->getRolesList(applicationName);
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
}

void WebAdminMethods_Accounts::addAccountToApplication(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return;
    }

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return;
    }

    if (!Globals::getIdentityManager()->applications->addAccountToApplication(appName, accountName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the account to the application.");
        return;
    }
}

void WebAdminMethods_Accounts::removeAccountFromApplication(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return;
    }

    if (appName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Application name is required");
        return;
    }

    if (!Globals::getIdentityManager()->applications->removeAccountFromApplication(appName, accountName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the account from the application.");
        return;
    }
}

void WebAdminMethods_Accounts::searchFields(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->accounts->searchFields(*request.inputJSON);
}

void WebAdminMethods_Accounts::addAccountDetailField(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    AccountDetailField fieldDetails;
    fieldDetails.fromJSON(*request.inputJSON);
    std::string fieldName = JSON_ASSTRING((*request.inputJSON), "fieldName", "");
    if (fieldName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Field Name is Empty");
        return;
    }
    if (!Globals::getIdentityManager()->accounts->addAccountDetailField(fieldName, fieldDetails))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "field_already_exists", "Field already exists");
    }
}

void WebAdminMethods_Accounts::removeAccountDetailField(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string fieldName = JSON_ASSTRING((*request.inputJSON), "fieldName", "");
    if (fieldName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Field Name is Empty");
        return;
    }
    if (!Globals::getIdentityManager()->accounts->removeAccountDetailField(fieldName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "field_not_found", "Field not found");
    }
}

void WebAdminMethods_Accounts::getAccountDetailField(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string fieldName = JSON_ASSTRING((*request.inputJSON), "fieldName", "");
    if (fieldName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Field Name is Empty");
        return;
    }
    auto field = Globals::getIdentityManager()->accounts->getAccountDetailField(fieldName);
    if (!field)
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "field_not_found", "Field not found");
        return;
    }
    (*response.responseJSON()) = field.value().toJSON();
}

void WebAdminMethods_Accounts::getAccountDetailFieldsValues(void *context, APIReturn &response, const RequestParameters &request,
                                                            ClientDetails &authClientDetails)
{
    std::string accountName = JSON_ASSTRING((*request.inputJSON), "accountName", "");
    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty");
        return;
    }

    std::list<IdentityManager::Accounts::AccountDetailFieldValue> fieldValues = Globals::getIdentityManager()->accounts->getAccountDetailFieldValues(
        accountName);

    Json::Value result(Json::arrayValue);
    for (const auto &fieldValue : fieldValues)
    {
        result.append(fieldValue.getJSON());
    }
    (*response.responseJSON()) = result;
}

void WebAdminMethods_Accounts::updateAccountDetailFieldsValues(void *context, APIReturn &response, const RequestParameters &request,
                                                               ClientDetails &authClientDetails)
{
    std::string accountName = JSON_ASSTRING((*request.inputJSON), "accountName", "");
    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty");
        return;
    }

    // Get the list of field values from input
    Json::Value fieldValuesArray = (*request.inputJSON)["fieldValues"];
    if (!fieldValuesArray.isArray())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Field values must be an array");
        return;
    }

    std::list<IdentityManager::Accounts::AccountDetailFieldValue> fieldValues;

    // Process each field value in the array
    for (Json::ArrayIndex i = 0; i < fieldValuesArray.size(); ++i)
    {
        IdentityManager::Accounts::AccountDetailFieldValue fieldValue;
        fieldValue.fromJSON(fieldValuesArray[i]);
        fieldValues.push_back(fieldValue);
    }

    // Update account detail fields values
    if (!Globals::getIdentityManager()->accounts->updateAccountDetailFieldValues(accountName, fieldValues))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update account detail fields values");
        return;
    }
    // Return 200.
}

void WebAdminMethods_Accounts::removeAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (accountName.empty())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Account name is required");
        return;
    }

    if (!Globals::getIdentityManager()->accounts->removeAccount(accountName))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the account.");
    }
}


/*
void WebAdminMethods_Accounts::updateAccountInfo(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
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
void WebAdminMethods_Accounts::changeAccountDescription(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->accounts->changeAccountDescription(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"description",""));
}

void WebAdminMethods_Accounts::changeAccoungGivenName(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->accounts->changeAccoungGivenName(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"givenName",""));
}

void WebAdminMethods_Accounts::changeAccountLastName(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->accounts->changeAccountLastName(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"lastName",""));
}

void WebAdminMethods_Accounts::changeAccountEmail(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->accounts->changeAccountEmail(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"email",""));
}

void WebAdminMethods_Accounts::changeAccountExtraData(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{

    return Globals::getIdentityManager()->accounts->changeAccountExtraData(JSON_ASSTRING(*request.inputJSON,"accountName",""), JSON_ASSTRING(*request.inputJSON,"extraData",""));
}*/
/*
void WebAdminMethods_Accounts::updateAccountRoles(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::set<std::string> roleSet;

    if (!(*request.inputJSON)["roles"].isArray())
    {
        response.setError(HTTP::Status::S_400_BAD_REQUEST, "invalid_request", "Invalid Parameters");
        return;
    }

    for (size_t i = 0; i < (*request.inputJSON)["roles"].size(); i++)
    {
        roleSet.insert((*request.inputJSON)["roles"][(int) i].asString());
    }

    if (!Globals::getIdentityManager()->accounts->updateAccountRoles(JSON_ASSTRING(*request.inputJSON, "accountName", ""), roleSet))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
        return;
    }
}

void WebAdminMethods_Accounts::validateAccountApplicationScope(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->authController->validateAccountApplicationScope(JSON_ASSTRING(*request.inputJSON, "accountName", ""),
                                                                                                                     {JSON_ASSTRING(*request.inputJSON, "appName", ""),
                                                                                                                      JSON_ASSTRING(*request.inputJSON, "id", "")});
}

void WebAdminMethods_Accounts::blockAccountUsingToken(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->accounts->blockAccountUsingToken(JSON_ASSTRING(*request.inputJSON, "accountName", ""), JSON_ASSTRING(*request.inputJSON, "blockToken", "")))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}*/

/*
void WebAdminMethods_Accounts::changeAccountExpiration(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->accounts->changeAccountExpiration(JSON_ASSTRING(*request.inputJSON, "accountName", ""), JSON_ASUINT64(*request.inputJSON, "expiration", 0)))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Accounts::changeCredential(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    Credential credentialData;
    credentialData.fromJSON((*request.inputJSON)["credentialData"]);
    if (!Globals::getIdentityManager()->authController->changeCredential(JSON_ASSTRING(*request.inputJSON, "accountName", ""), credentialData, JSON_ASUINT(*request.inputJSON, "slotId", 0)))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Accounts::confirmAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->accounts->disableAccount(JSON_ASSTRING(*request.inputJSON, "accountName", ""), JSON_ASBOOL(*request.inputJSON, "disabled", false)))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}

void WebAdminMethods_Accounts::disableAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    if (!Globals::getIdentityManager()->accounts->disableAccount(JSON_ASSTRING(*request.inputJSON, "accountName", ""), JSON_ASBOOL(*request.inputJSON, "disabled", false)))
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal Error");
    }
}*/
/*
void WebAdminMethods_Accounts::getAccountBlockToken(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->accounts->getAccountBlockToken(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
}

void WebAdminMethods_Accounts::getAccountDirectApplicationScopes(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = WebAdmin_Methods::scopeListToJSON(
        Globals::getIdentityManager()->authController->getAccountDirectApplicationScopes(JSON_ASSTRING(*request.inputJSON, "accountName", "")));
}

void WebAdminMethods_Accounts::getAccountDetails(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    auto getAccountDetails = Globals::getIdentityManager()->accounts->getAccountDetails(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
    // Llenar el payloadOut con los detalles de la cuenta
    (*response.responseJSON()) = getAccountDetails.toJSON();
}

void WebAdminMethods_Accounts::getAccountExpirationTime(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Json::Int64(Globals::getIdentityManager()->accounts->getAccountExpirationTime(JSON_ASSTRING(*request.inputJSON, "accountName", "")));
}



void WebAdminMethods_Accounts::getAccountInfo(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    getAccountDetails(context, response, request, authClientDetails);

    int i = 0;
    auto getAccountRoles = Globals::getIdentityManager()->accounts->getAccountRoles(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
    for (const auto &roleName : getAccountRoles)
    {
        (*response.responseJSON())["roles"][i]["name"] = roleName;
        // TODO: optimize:
        (*response.responseJSON())["roles"][i]["description"] = Globals::getIdentityManager()->roles->getRoleDescription(roleName);
        i++;
    }

    i = 0;
    for (const auto &roleName : Globals::getIdentityManager()->roles->getRolesList())
    {
        if (getAccountRoles.find(roleName) == getAccountRoles.end())
        {
            (*response.responseJSON())["rolesLeft"][i]["name"] = roleName;
            (*response.responseJSON())["rolesLeft"][i]["description"] = Globals::getIdentityManager()->roles->getRoleDescription(roleName);
            i++;
        }
    }


}

void WebAdminMethods_Accounts::getAccountLastAccess(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->authController->getAccountLastAccess(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
}

void WebAdminMethods_Accounts::getAccountRoles(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->accounts->getAccountRoles(JSON_ASSTRING(*request.inputJSON, "accountName", "")));
}

void WebAdminMethods_Accounts::getAccountUsableApplicationScopes(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = WebAdmin_Methods::scopeListToJSON(
        Globals::getIdentityManager()->authController->getAccountUsableApplicationScopes(JSON_ASSTRING(*request.inputJSON, "accountName", "")));
}

void WebAdminMethods_Accounts::isAccountExpired(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Globals::getIdentityManager()->accounts->isAccountExpired(JSON_ASSTRING(*request.inputJSON, "accountName", ""));
}

void WebAdminMethods_Accounts::listAccounts(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    (*response.responseJSON()) = Helpers::setToJSON(Globals::getIdentityManager()->accounts->listAccounts());
}


void WebAdminMethods_Accounts::resetBadAttemptsOnCredential(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails)
{
    Globals::getIdentityManager()->authController->resetBadAttemptsOnCredential(JSON_ASSTRING(*request.inputJSON, "accountName", ""), JSON_ASUINT(*request.inputJSON, "slotId", 0));
}
*/
