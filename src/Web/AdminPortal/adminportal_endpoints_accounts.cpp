#include "adminportal_endpoints_accounts.h"
#include "IdentityManager/ds_account.h"
#include "IdentityManager/ds_application.h"
#include "IdentityManager/ds_authentication.h"
#include <Mantids30/Program_Logs/applog.h>
#include <json/value.h>

#include "globals.h"
#include <Mantids30/Helpers/json.h>
#include <boost/algorithm/string/join.hpp>

using namespace Mantids30::Program;
using namespace Mantids30;
using namespace Mantids30::Network::Protocol;

void AdminPortal_Endpoints_Accounts::addEndpoints_Accounts(const std::shared_ptr<Endpoints> &endpoints)
{
    using SecurityRequirements = API::Security::Requirements;

    // Accounts:
    endpoints->addEndpoint(HTTP::Method::POST, "createAccount", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &createAccount);
    endpoints->addEndpoint(HTTP::Method::GET, "getAccountDisplayName", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_READ"}, nullptr, &getAccountDisplayName);
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
    endpoints->addEndpoint(HTTP::Method::GET, "listDetailFields", SecurityRequirements::JWT_COOKIE_AUTH, {"CONFIG_READ"}, nullptr, &listDetailFields);
    endpoints->addEndpoint(HTTP::Method::GET, "searchFields", SecurityRequirements::JWT_COOKIE_AUTH, {"CONFIG_READ"}, nullptr, &searchFields);
    endpoints->addEndpoint(HTTP::Method::POST, "createAccountDetailField", SecurityRequirements::JWT_COOKIE_AUTH, {"CONFIG_WRITE"}, nullptr, &createAccountDetailField);
    endpoints->addEndpoint(HTTP::Method::PUT, "updateAccountDetailField", SecurityRequirements::JWT_COOKIE_AUTH, {"CONFIG_WRITE"}, nullptr, &updateAccountDetailField);
    endpoints->addEndpoint(HTTP::Method::DELETE, "removeAccountDetailField", SecurityRequirements::JWT_COOKIE_AUTH, {"CONFIG_WRITE"}, nullptr, &removeAccountDetailField);
    endpoints->addEndpoint(HTTP::Method::GET, "getAccountDetailField", SecurityRequirements::JWT_COOKIE_AUTH, {"CONFIG_READ"}, nullptr, &getAccountDetailField);

    endpoints->addEndpoint(HTTP::Method::POST, "extendAccountInactivity", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &extendInactivity);
}

AdminPortal_Endpoints_Accounts::APIReturn AdminPortal_Endpoints_Accounts::extendInactivity(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    std::string accountUUID = Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", "");
    time_t validUntil = Helpers::JSON::ASINT64(*request.inputJSON, "validUntil", 0);

    // Validate that account name is not empty
    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty"};
    }

    if (!Globals::getIdentityManager()->accounts->extendInactivity(accountUUID, validUntil))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed extend inactivity"};
    }

    return {};
}

API::APIReturn AdminPortal_Endpoints_Accounts::createAccount(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    // Extract account name from request

    // Initialize account flags from request
    AccountFlags accountFlags;
    accountFlags.fromJSON(request.inputJSON);

    // Can't create admin from non-admin account:
    if (accountFlags.admin && !request.jwtToken->isAdmin())
    {
        accountFlags.admin = false;
    }

    // Parse application definitions from request
    std::map<std::string,ApplicationDef> applicationDefs;
    if ((*request.inputJSON).isMember("applications") && (*request.inputJSON)["applications"].isArray())
    {
        for (const auto &app : (*request.inputJSON)["applications"])
        {
            ApplicationDef appDef;
            std::string appName = Helpers::JSON::ASSTRING(app, "name", "");
            appDef.isAppAdmin = Helpers::JSON::ASBOOL(app, "isAppAdmin", false);

            // Can't create application admin without APP_MODIFY scope.
            if (appDef.isAppAdmin && !request.jwtToken->hasScope("APP_MODIFY"))
            {
                appDef.isAppAdmin = false;
            }

            // Parse roles
            if (app.isMember("roles") && app["roles"].isArray())
            {
                for (const auto &role : app["roles"])
                {
                    appDef.roles.insert(Helpers::JSON::ASSTRING_D(role, ""));
                }
            }

            // Parse scopes
            if (app.isMember("scopes") && app["scopes"].isArray())
            {
                for (const auto &scope : app["scopes"])
                {
                    appDef.scopes.insert(Helpers::JSON::ASSTRING_D(scope, ""));
                }
            }

            if (!applicationDefs.count(appName))
            {
                applicationDefs[appName]= appDef;
            }
        }
    }

    // Parse detail field values from request
    std::map<std::string, std::string> fieldValues;
    if ((*request.inputJSON).isMember("fieldValues") && (*request.inputJSON)["fieldValues"].isArray())
    {
        for (const auto &fv : (*request.inputJSON)["fieldValues"])
        {
            std::string fieldName = Helpers::JSON::ASSTRING(fv, "name", "");
            std::string fieldValue = Helpers::JSON::ASSTRING(fv, "value", "");
            if (!fieldName.empty())
            {
                fieldValues[fieldName] = fieldValue;
            }
        }
    }

    // Add the new account to the system with specified expiration and flags
    int64_t expirationDate = Helpers::JSON::ASINT64(*request.inputJSON, "expirationDate", 0);
    CreateAccountResult createResult = Globals::getIdentityManager()->accounts->createAccount(expirationDate, accountFlags, authClientDetails, request.jwtToken->getSubject(), applicationDefs,
                                                                                                                 fieldValues);
    if (!createResult.success)
    {
        // Check if the failure is due to detail field validation
        auto detailStatus = createResult.detailResult.status;
        if (detailStatus != UpdateAccountDetailFieldValuesResult::Status::SUCCESS)
        {
            switch (detailStatus)
            {
            case UpdateAccountDetailFieldValuesResult::Status::INVALID_FIELD:
                return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_field",
                        "One or more field names do not exist: " + boost::algorithm::join(createResult.detailResult.duplicateFields, ", ")};

            case UpdateAccountDetailFieldValuesResult::Status::PERMISSION_DENIED:
                return {HTTP::Status::Code::S_403_FORBIDDEN, "permission_denied",
                        "User lacks permission to edit one or more detail fields"};

            case UpdateAccountDetailFieldValuesResult::Status::REGEX_VALIDATION_FAILED:
                return {HTTP::Status::Code::S_400_BAD_REQUEST, "regex_validation_failed",
                        "One or more field values failed regex validation: " + boost::algorithm::join(createResult.detailResult.regexInvalidFields, ", ")};

            case UpdateAccountDetailFieldValuesResult::Status::DUPLICATE_LOGIN_IDENTIFIER:
                return {HTTP::Status::Code::S_409_CONFLICT, "duplicate_login_identifier",
                        "Login identifier conflict for field(s): " + boost::algorithm::join(createResult.detailResult.duplicateFields, ", ")};

            case UpdateAccountDetailFieldValuesResult::Status::DUPLICATE_UNIQUE_FIELD:
                return {HTTP::Status::Code::S_409_CONFLICT, "duplicate_unique_field",
                        "Unique field conflict for field(s): " + boost::algorithm::join(createResult.detailResult.uniqueInvalidFields, ", ")};

            case UpdateAccountDetailFieldValuesResult::Status::DB_ERROR:
            default:
                return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "db_error",
                        "Database error while setting account detail field values"};
            }
        }

        // General database/transaction failure (account insert, activation token, application association, roles, scopes, or transaction commit)
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "db_error",
                "Failed to create the account in the database. The transaction was rolled back."};
    }

    const std::string &accountUUID = createResult.accountUUID;

    // Extract credential information from request
    Json::Value tempCredential = (*request.inputJSON)["tempCredential"];
    std::string secretTempPass = Helpers::JSON::ASSTRING(*request.inputJSON, "secretTempPass", "");

    Credential newCredentialData;
    uint32_t slotId = Helpers::JSON::ASUINT(*request.inputJSON, "slotId", 1);

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
    if (!Globals::getIdentityManager()->authController->changeAccountCredential(authClientDetails, request.jwtToken->getSubject(), accountUUID, newCredentialData, slotId))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to change the credential on the new user."};
    }

    AccountFlags flags;
    flags.fromJSON((*request.inputJSON)["flags"]);

    // Apply the credential to the new account
    if (!Globals::getIdentityManager()->accounts->changeAccountFlags(authClientDetails, request.jwtToken->getSubject(), accountUUID, flags))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to change the credential on the new user."};
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_Accounts::getAccountFlags(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    APIReturn response;
    std::string accountUUID = Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", "");

    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    return Globals::getIdentityManager()->accounts->getAccountFlags(accountUUID).toJSON();
}

API::APIReturn AdminPortal_Endpoints_Accounts::changeAccountFlags(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    APIReturn response;
    std::string accountUUID = Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", "");

    if (!(*request.inputJSON).isMember("flags"))
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account flags are required"};
    }

    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    AccountFlags flags;
    flags.fromJSON((*request.inputJSON)["flags"]);

    bool changed = Globals::getIdentityManager()->accounts->changeAccountFlags(authClientDetails, request.jwtToken->getSubject(), accountUUID, flags);

    if (!changed)
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "The account flags could not be updated. It may be that no other admin exists or there was a database issue."};
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_Accounts::getAccountDisplayName(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::string accountUUID = Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", "");

    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account UUID is required"};
    }

    if (!Globals::getIdentityManager()->accounts->doesAccountExist(accountUUID))
    {
        return {HTTP::Status::Code::S_404_NOT_FOUND, "not_found", "The Account does not exist in the system."};
    }

    std::string displayName = Globals::getIdentityManager()->accounts->getAccountDisplayName(accountUUID);
    (*response.responseJSON())["displayName"] = displayName;
    return response;
}

API::APIReturn AdminPortal_Endpoints_Accounts::searchAccounts(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    return Globals::getIdentityManager()->accounts->searchAccounts(*request.inputJSON);
}

API::APIReturn AdminPortal_Endpoints_Accounts::getAccountApplications(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    const std::string accountUUID = Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", "");

    int i = 0;

    std::set<std::string> listAccountApplications = Globals::getIdentityManager()->applications->listAccountApplications(accountUUID);
    std::set<ApplicationScope> directScopes = Globals::getIdentityManager()->applicationScopes->getAccountDirectApplicationScopes(accountUUID);

    for (const std::string &applicationName : listAccountApplications)
    {
        std::set<ApplicationScope> usableScopes = Globals::getIdentityManager()->applicationScopes->getAccountUsableApplicationScopes(applicationName, accountUUID);

        (*response.responseJSON())["applications"][i]["name"] = applicationName;
        // TODO: optimize:
        (*response.responseJSON())["applications"][i]["description"] = Globals::getIdentityManager()->applications->getApplicationDescription(applicationName);

        std::set<ApplicationRole> allAppRoles = Globals::getIdentityManager()->applicationRoles->getApplicationRolesList(applicationName);
        std::set<ApplicationRole> usedAppRoles = Globals::getIdentityManager()->accounts->getAccountApplicationRoles(applicationName, accountUUID);

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
        for (const ApplicationScope &scope : Globals::getIdentityManager()->applicationScopes->listApplicationScopes(applicationName))
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

API::APIReturn AdminPortal_Endpoints_Accounts::addAccountToApplication(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string accountUUID = Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", "");
    std::string appName = Helpers::JSON::ASSTRING(*request.inputJSON, "appName", "");

    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required"};
    }

    if (!Globals::getIdentityManager()->applications->addAccountToApplication(authClientDetails, request.jwtToken->getSubject(), appName, accountUUID))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to add the account to the application."};
    }

    return response;
}

API::APIReturn AdminPortal_Endpoints_Accounts::removeAccountFromApplication(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string accountUUID = Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", "");
    std::string appName = Helpers::JSON::ASSTRING(*request.inputJSON, "appName", "");

    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    if (appName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Application name is required"};
    }

    if (!Globals::getIdentityManager()->applications->removeAccountFromApplication(authClientDetails, request.jwtToken->getSubject(), appName, accountUUID))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the account from the application."};
    }
    return response;
}

API::APIReturn AdminPortal_Endpoints_Accounts::listDetailFields(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    Json::Value fieldsArray(Json::arrayValue);

    std::map<std::string, AccountDetailField> fields = Globals::getIdentityManager()->accounts->listAccountDetailFields();
    for (const auto &fieldPair : fields)
    {
        Json::Value item = fieldPair.second.toJSON();
        item["fieldName"] = fieldPair.first;
        fieldsArray.append(item);
    }

    *response.responseJSON() = fieldsArray;
    return response;
}

API::APIReturn AdminPortal_Endpoints_Accounts::searchFields(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    return Globals::getIdentityManager()->accounts->searchFields(*request.inputJSON);
}

API::APIReturn AdminPortal_Endpoints_Accounts::createAccountDetailField(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    AccountDetailField fieldDetails;
    fieldDetails.fromJSON(*request.inputJSON);
    std::string fieldName = Helpers::JSON::ASSTRING((*request.inputJSON), "fieldName", "");
    if (fieldName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Field Name is Empty"};
    }
    if (!Globals::getIdentityManager()->accounts->createAccountDetailField(authClientDetails, request.jwtToken->getSubject(), fieldName, fieldDetails))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "field_already_exists", "Field already exists"};
    }

    return response;
}

AdminPortal_Endpoints_Accounts::APIReturn AdminPortal_Endpoints_Accounts::updateAccountDetailField(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    AccountDetailField fieldDetails;
    fieldDetails.fromJSON(*request.inputJSON);
    std::string fieldName = Helpers::JSON::ASSTRING((*request.inputJSON), "fieldName", "");
    if (fieldName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Field Name is Empty"};
    }

    auto result = Globals::getIdentityManager()->accounts->updateAccountDetailField(authClientDetails, request.jwtToken->getSubject(), fieldName, fieldDetails);
    switch (result)
    {
    case IdentityManager::Accounts::UpdateAccountDetailFieldResult::SUCCESS:
        return {};
    case IdentityManager::Accounts::UpdateAccountDetailFieldResult::FIELD_NOT_FOUND:
        return {HTTP::Status::Code::S_404_NOT_FOUND, "field_not_found", "Field not found"};
    case IdentityManager::Accounts::UpdateAccountDetailFieldResult::LAST_LOGIN_IDENTIFIER:
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "last_login_identifier", "Cannot disable the last login identifier field"};
    case IdentityManager::Accounts::UpdateAccountDetailFieldResult::DUPLICATE_VALUES_FOR_UNIQUE_FIELD:
        return {HTTP::Status::Code::S_409_CONFLICT, "duplicate_values_for_unique_field", "Cannot enable unique constraint: duplicate values already exist for this field"};
    case IdentityManager::Accounts::UpdateAccountDetailFieldResult::LOGIN_IDENTIFIER_VALUE_CONFLICT:
        return {HTTP::Status::Code::S_409_CONFLICT, "login_identifier_value_conflict", "Cannot enable isLoginIdentifier: value would conflict with existing login identifier values across accounts"};
    case IdentityManager::Accounts::UpdateAccountDetailFieldResult::DB_ERROR:
    default:
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "db_error", "Failed to update account detail field"};
    }
}

API::APIReturn AdminPortal_Endpoints_Accounts::removeAccountDetailField(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    std::string fieldName = Helpers::JSON::ASSTRING((*request.inputJSON), "fieldName", "");
    if (fieldName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Field Name is Empty"};
    }

    auto result = Globals::getIdentityManager()->accounts->removeAccountDetailField(authClientDetails, request.jwtToken->getSubject(), fieldName);
    switch (result)
    {
    case IdentityManager::Accounts::RemoveAccountDetailFieldResult::SUCCESS:
        return {};
    case IdentityManager::Accounts::RemoveAccountDetailFieldResult::FIELD_NOT_FOUND:
        return {HTTP::Status::Code::S_404_NOT_FOUND, "field_not_found", "Field not found"};
    case IdentityManager::Accounts::RemoveAccountDetailFieldResult::LAST_LOGIN_IDENTIFIER:
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "last_login_identifier", "Cannot remove the last login identifier field"};
    case IdentityManager::Accounts::RemoveAccountDetailFieldResult::DB_ERROR:
    default:
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "db_error", "Failed to remove account detail field"};
    }
}

API::APIReturn AdminPortal_Endpoints_Accounts::getAccountDetailField(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string fieldName = Helpers::JSON::ASSTRING((*request.inputJSON), "fieldName", "");
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

API::APIReturn AdminPortal_Endpoints_Accounts::getAccountDetailFieldsValues(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string accountUUID = Helpers::JSON::ASSTRING((*request.inputJSON), "accountUUID", "");
    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty"};
    }

    std::map<std::string, AccountDetailFieldValue> fieldValues = Globals::getIdentityManager()->accounts->getAccountDetailFieldValues(accountUUID);

    Json::Value result(Json::arrayValue);
    for (const auto &fieldValue : fieldValues)
    {
        result.append(fieldValue.second.toJSON());
    }

    return result;
}

API::APIReturn AdminPortal_Endpoints_Accounts::updateAccountDetailFieldsValues(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string accountUUID = Helpers::JSON::ASSTRING((*request.inputJSON), "accountUUID", "");
    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty"};
    }

    // Get the list of field values from input
    Json::Value fieldValuesArray = (*request.inputJSON)["fieldValues"];
    if (!fieldValuesArray.isArray())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Field values must be an array"};
    }

    std::map<std::string, std::string> fieldValues;

    // Process each field value in the array
    for (const auto &i : fieldValuesArray)
    {
        std::string fieldName = Helpers::JSON::ASSTRING(i, "name", "");
        std::string fieldValue = Helpers::JSON::ASSTRING(i, "value", "");
        if (!fieldName.empty())
        {
            fieldValues[fieldName] = fieldValue;
        }
    }

    // Update account detail fields values
    UpdateAccountDetailFieldValuesResult result = Globals::getIdentityManager()->accounts->updateAccountDetailFieldValues(authClientDetails, request.jwtToken->getSubject(), accountUUID, fieldValues,
                                                                                                                          true);

    switch (result.status)
    {
    case UpdateAccountDetailFieldValuesResult::Status::SUCCESS:
        return response;

    case UpdateAccountDetailFieldValuesResult::Status::INVALID_FIELD:
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_field", "One or more field names do not exist: " + boost::algorithm::join(result.duplicateFields, ", ")};

    case UpdateAccountDetailFieldValuesResult::Status::PERMISSION_DENIED:
        return {HTTP::Status::Code::S_403_FORBIDDEN, "permission_denied", "User lacks permission to edit one or more fields"};

    case UpdateAccountDetailFieldValuesResult::Status::REGEX_VALIDATION_FAILED:
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "regex_validation_failed", "One or more values failed regex validation: " + boost::algorithm::join(result.regexInvalidFields, ", ")};

    case UpdateAccountDetailFieldValuesResult::Status::DUPLICATE_LOGIN_IDENTIFIER:
        return {HTTP::Status::Code::S_409_CONFLICT, "duplicate_login_identifier", "Login identifier conflict for fields: " + boost::algorithm::join(result.duplicateFields, ", ")};

    case UpdateAccountDetailFieldValuesResult::Status::DUPLICATE_UNIQUE_FIELD:
        return {HTTP::Status::Code::S_409_CONFLICT, "duplicate_unique_field", "Unique field conflict for fields: " + boost::algorithm::join(result.uniqueInvalidFields, ", ")};

    case UpdateAccountDetailFieldValuesResult::Status::DB_ERROR:
    default:
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "db_error", "Database error while updating account detail fields values"};
    }
}

API::APIReturn AdminPortal_Endpoints_Accounts::removeAccount(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;
    std::string accountUUID = Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", "");

    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    if (!Globals::getIdentityManager()->accounts->removeAccount(authClientDetails, request.jwtToken->getSubject(), accountUUID))
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to remove the account."};
    }

    return response;
}
