#include "adminportal_endpoints_accounts.h"
#include "IdentityManager/ds_account.h"
#include "IdentityManager/ds_authentication.h"
#include <Mantids30/Program_Logs/applog.h>
#include <json/value.h>

#include "defs.h"
#include "globals.h"
#include <regex>

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocol;

std::map<std::string, std::string> AdminPortal_Endpoints_Accounts::jsonToMap(const json &jValue)
{
    std::map<std::string, std::string> r;
    for (const std::string &memberName : jValue.getMemberNames())
    {
        if (jValue[memberName].isString())
        {
            r[memberName] = JSON_ASSTRING(jValue, memberName, "");
        }
    }
    return r;
}

void AdminPortal_Endpoints_Accounts::addEndpoints_Accounts(const std::shared_ptr<Endpoints> &endpoints)
{
    using SecurityRequirements = API::Security::Requirements;

    // Accounts:
    endpoints->addEndpoint(HTTP::Method::POST, "addAccount", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &addAccount);
    endpoints->addEndpoint(HTTP::Method::GET, "doesAccountExist", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_READ"}, nullptr, &doesAccountExist);
    endpoints->addEndpoint(HTTP::Method::GET, "searchAccounts", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_READ"}, nullptr, &searchAccounts);
    endpoints->addEndpoint(HTTP::Method::GET, "getAccountDetailFieldsValues", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_READ"}, nullptr, &getAccountDetailFieldsValues);
    endpoints->addEndpoint(HTTP::Method::PUT, "updateAccountDetailFieldsValues", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &updateAccountDetailFieldsValues);
    endpoints->addEndpoint(HTTP::Method::GET, "getAccountFlags", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_READ"}, nullptr, &getAccountFlags);
    endpoints->addEndpoint(HTTP::Method::PATCH, "changeAccountFlags", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &changeAccountFlags);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeAccount", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_DELETE"}, nullptr, &removeAccount);

    // Accounts-Applications:
    endpoints->addEndpoint(HTTP::Method::GET, "getAccountApplications", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_READ"}, nullptr, &getAccountApplications);
    endpoints->addEndpoint(HTTP::Method::POST, "addAccountToApplication", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &addAccountToApplication);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeAccountFromApplication", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &removeAccountFromApplication);
    // Fields
    endpoints->addEndpoint(HTTP::Method::GET, "searchFields", SecurityRequirements::JWT_COOKIE_AUTH, {"CONFIG_READ"}, nullptr, &searchFields);
    endpoints->addEndpoint(HTTP::Method::POST, "addAccountDetailField", SecurityRequirements::JWT_COOKIE_AUTH, {"CONFIG_WRITE"}, nullptr, &addAccountDetailField);
    endpoints->addEndpoint(HTTP::Method::PUT, "updateAccountDetailField", SecurityRequirements::JWT_COOKIE_AUTH, {"CONFIG_WRITE"}, nullptr, &updateAccountDetailField);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeAccountDetailField", SecurityRequirements::JWT_COOKIE_AUTH, {"CONFIG_WRITE"}, nullptr, &removeAccountDetailField);
    endpoints->addEndpoint(HTTP::Method::GET, "getAccountDetailField", SecurityRequirements::JWT_COOKIE_AUTH, {"CONFIG_READ"}, nullptr, &getAccountDetailField);
}

API::APIReturn AdminPortal_Endpoints_Accounts::addAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    // Extract account name from request
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    // Check if account already exists
    if (Globals::getIdentityManager()->accounts->doesAccountExist(accountName))
    {
        return {HTTP::Status::Code::S_406_NOT_ACCEPTABLE, "unacceptable_request", "Account Already Exist"};
    }

    // Validate that account name is not empty
    if (accountName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty"};
    }

    // Validate account name format using regex (alphanumeric only)
    std::regex accountNameExpr("[a-zA-Z0-9]+");
    if (!regex_match(accountName, accountNameExpr))
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name have invalid characters"};
    }

    // Initialize account flags from request
    AccountFlags accountFlags;
    accountFlags.fromJSON(request.inputJSON);

    // Add the new account to the system with specified expiration and flags
    if (!Globals::getIdentityManager()->accounts->addAccount(accountName, JSON_ASUINT64(*request.inputJSON, "expirationDate", 0), accountFlags, authClientDetails, request.jwtToken->getSubject()))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the new account. Check if user already exists"};
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
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Either tempCredential or secretTempPass must be provided"};
    }

    newCredentialData.setExpirationTimeAutomatically();

    // Apply the credential to the new account
    if (!Globals::getIdentityManager()->authController->changeAccountCredential(authClientDetails, request.jwtToken->getSubject(), accountName, newCredentialData, slotId))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to change the credential on the new user."};
    }

    AccountFlags flags;
    flags.fromJSON((*request.inputJSON)["flags"]);

    // Apply the credential to the new account
    if (!Globals::getIdentityManager()->accounts->changeAccountFlags(authClientDetails, request.jwtToken->getSubject(), accountName, flags))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to change the credential on the new user."};
    }

    if (!Globals::getIdentityManager()->applications->addAccountToApplication(authClientDetails, request.jwtToken->getSubject(), IAM_USRPORTAL_APPNAME, accountName))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to assign user with GENERIC_USER in app '" IAM_USRPORTAL_APPNAME "'."};
    }

    if (!Globals::getIdentityManager()->applicationRoles->addAccountToRole(authClientDetails, request.jwtToken->getSubject(), IAM_USRPORTAL_APPNAME, "GENERIC_USER", accountName))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to assign user with GENERIC_USER in app '" IAM_USRPORTAL_APPNAME "'."};
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_Accounts::getAccountFlags(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    APIReturn response;
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (accountName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    return Globals::getIdentityManager()->accounts->getAccountFlags(accountName).toJSON();
}

API::APIReturn AdminPortal_Endpoints_Accounts::changeAccountFlags(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    APIReturn response;
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (!(*request.inputJSON).isMember("flags"))
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account flags are required"};
    }

    if (accountName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    AccountFlags flags;
    flags.fromJSON((*request.inputJSON)["flags"]);

    bool changed = Globals::getIdentityManager()->accounts->changeAccountFlags(authClientDetails, request.jwtToken->getSubject(), accountName, flags);

    if (!changed)
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "The account flags could not be updated. It may be that no other admin exists or there was a database issue."};
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_Accounts::doesAccountExist(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (accountName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty"};
    }

    if (!Globals::getIdentityManager()->accounts->doesAccountExist(accountName))
    {
        return {HTTP::Status::Code::S_404_NOT_FOUND, "not_found", "The Account does not exist in the system."};
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_Accounts::searchAccounts(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    return Globals::getIdentityManager()->accounts->searchAccounts(*request.inputJSON);
}

API::APIReturn AdminPortal_Endpoints_Accounts::getAccountApplications(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    const std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    int i = 0;

    std::set<std::string> listAccountApplications = Globals::getIdentityManager()->applications->listAccountApplications(accountName);
    std::set<ApplicationScope> directScopes = Globals::getIdentityManager()->authController->getAccountDirectApplicationScopes(accountName);

    for (const std::string &applicationName : listAccountApplications)
    {
        std::set<ApplicationScope> usableScopes = Globals::getIdentityManager()->authController->getAccountUsableApplicationScopes(applicationName, accountName);

        (*response.responseJSON())["applications"][i]["name"] = applicationName;
        // TODO: optimize:
        (*response.responseJSON())["applications"][i]["description"] = Globals::getIdentityManager()->applications->getApplicationDescription(applicationName);

        std::set<ApplicationRole> allAppRoles = Globals::getIdentityManager()->applicationRoles->getApplicationRolesList(applicationName);
        std::set<ApplicationRole> usedAppRoles = Globals::getIdentityManager()->accounts->getAccountApplicationRoles(applicationName, accountName);

        // Add used roles
        for (const ApplicationRole &role : usedAppRoles)
        {
            (*response.responseJSON())["applications"][i]["usedRoles"].append(role.toJSON());
        }

        // Add available roles (roles that can be added)
        std::set<ApplicationRole> availableRoles;
        for (const ApplicationRole &role : allAppRoles)
        {
            if (usedAppRoles.find(role) == usedAppRoles.end())
            {
                availableRoles.insert(role);
            }
        }

        for (const ApplicationRole &role : availableRoles)
        {
            (*response.responseJSON())["applications"][i]["availableRoles"].append(role.toJSON());
        }

        int j = 0;
        for (const ApplicationScope &directApplicationScope : directScopes)
        {
            if (directApplicationScope.appName == applicationName)
            {
                (*response.responseJSON())["applications"][i]["directScopes"][j] = directApplicationScope.toJSON();
                j++;
            }
        }

        j = 0;
        for (const ApplicationScope &scope : Globals::getIdentityManager()->authController->listApplicationScopes(applicationName))
        {
            if (directScopes.find(scope) == directScopes.end())
            {
                (*response.responseJSON())["applications"][i]["directScopesLeft"][j] = scope.toJSON();
                j++;
            }
        }

        j = 0;
        for (const ApplicationScope &usableScope : usableScopes)
        {
            (*response.responseJSON())["applications"][i]["usableScopes"][j] = usableScope.toJSON();
            j++;
        }
        i++;
    }

    i = 0;

    for (const std::string &applicationName : Globals::getIdentityManager()->applications->listApplications())
    {
        if (listAccountApplications.find(applicationName) == listAccountApplications.end())
        {
            (*response.responseJSON())["applicationsLeft"][i]["name"] = applicationName;
            (*response.responseJSON())["applicationsLeft"][i]["description"] = Globals::getIdentityManager()->applications->getApplicationDescription(applicationName);
            i++;
        }
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_Accounts::addAccountToApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (accountName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required"};
    }

    if (!Globals::getIdentityManager()->applications->addAccountToApplication(authClientDetails, request.jwtToken->getSubject(), appName, accountName))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the account to the application."};
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_Accounts::removeAccountFromApplication(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");
    std::string appName = JSON_ASSTRING(*request.inputJSON, "appName", "");

    if (accountName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required"};
    }

    if (!Globals::getIdentityManager()->applications->removeAccountFromApplication(authClientDetails, request.jwtToken->getSubject(), appName, accountName))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the account from the application."};
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_Accounts::searchFields(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    return Globals::getIdentityManager()->accounts->searchFields(*request.inputJSON);
}

API::APIReturn AdminPortal_Endpoints_Accounts::addAccountDetailField(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    AccountDetailField fieldDetails;
    fieldDetails.fromJSON(*request.inputJSON);
    std::string fieldName = JSON_ASSTRING((*request.inputJSON), "fieldName", "");
    if (fieldName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Field Name is Empty"};
    }
    if (!Globals::getIdentityManager()->accounts->addAccountDetailField(authClientDetails, request.jwtToken->getSubject(), fieldName, fieldDetails))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "field_already_exists", "Field already exists"};
    }

    return response;
}

AdminPortal_Endpoints_Accounts::APIReturn AdminPortal_Endpoints_Accounts::updateAccountDetailField(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    AccountDetailField fieldDetails;
    fieldDetails.fromJSON(*request.inputJSON);
    std::string fieldName = JSON_ASSTRING((*request.inputJSON), "fieldName", "");
    if (fieldName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Field Name is Empty"};
    }
    if (!Globals::getIdentityManager()->accounts->updateAccountDetailField(authClientDetails, request.jwtToken->getSubject(), fieldName, fieldDetails))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "field_already_exists", "Field already exists"};
    }

    return {};
}

API::APIReturn AdminPortal_Endpoints_Accounts::removeAccountDetailField(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    std::string fieldName = JSON_ASSTRING((*request.inputJSON), "fieldName", "");
    if (fieldName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Field Name is Empty"};
    }
    if (!Globals::getIdentityManager()->accounts->removeAccountDetailField(authClientDetails, request.jwtToken->getSubject(), fieldName))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "field_not_found", "Field not found"};
    }

    return {};
}

API::APIReturn AdminPortal_Endpoints_Accounts::getAccountDetailField(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string fieldName = JSON_ASSTRING((*request.inputJSON), "fieldName", "");
    if (fieldName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Field Name is Empty"};
    }
    std::optional<AccountDetailField> field = Globals::getIdentityManager()->accounts->getAccountDetailField(fieldName);
    if (!field)
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "field_not_found", "Field not found"};
    }

    return field.value().toJSON();
}

API::APIReturn AdminPortal_Endpoints_Accounts::getAccountDetailFieldsValues(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string accountName = JSON_ASSTRING((*request.inputJSON), "accountName", "");
    if (accountName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty"};
    }

    std::map<std::string, AccountDetailFieldValue> fieldValues = Globals::getIdentityManager()->accounts->getAccountDetailFieldValues(accountName);

    Json::Value result(Json::arrayValue);
    for (const auto &fieldValue : fieldValues)
    {
        result.append(fieldValue.second.toJSON());
    }

    return result;
}

API::APIReturn AdminPortal_Endpoints_Accounts::updateAccountDetailFieldsValues(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string accountName = JSON_ASSTRING((*request.inputJSON), "accountName", "");
    if (accountName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty"};
    }

    // Get the list of field values from input
    Json::Value fieldValuesArray = (*request.inputJSON)["fieldValues"];
    if (!fieldValuesArray.isArray())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Field values must be an array"};
    }

    std::list<AccountDetailFieldValue> fieldValues;

    // Process each field value in the array
    for (const auto &i : fieldValuesArray)
    {
        AccountDetailFieldValue fieldValue;
        fieldValue.fromJSON(i);
        fieldValues.push_back(fieldValue);
    }

    // Update account detail fields values
    if (!Globals::getIdentityManager()->accounts->updateAccountDetailFieldValues(authClientDetails, request.jwtToken->getSubject(), accountName, fieldValues, true))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to update account detail fields values"};
    }
    // Return 200.

    return response;
}

API::APIReturn AdminPortal_Endpoints_Accounts::removeAccount(void *context, const RequestParameters &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::string accountName = JSON_ASSTRING(*request.inputJSON, "accountName", "");

    if (accountName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    if (!Globals::getIdentityManager()->accounts->removeAccount(authClientDetails, request.jwtToken->getSubject(), accountName))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the account."};
    }

    return response;
}
