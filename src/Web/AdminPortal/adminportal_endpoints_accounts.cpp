#include "adminportal_endpoints_accounts.h"
#include "IdentityManager/ds_account.h"
#include "IdentityManager/ds_application.h"
#include "IdentityManager/ds_authentication.h"
#include <Mantids30/DataFormat_JSON/json.h>
#include <Mantids30/Program_Logs/applog.h>

#include "Mantids30/DataFormat_JSON/json_accessors.h"
#include "Mantids30/DataFormat_JSON/json_accessors_array.h"
#include "Mantids30/DataFormat_JSON/json_detail.h"
#include "defs.h"
#include "globals.h"
#include <Mantids30/Helpers/json.h>
#include <algorithm>
#include <boost/algorithm/string/join.hpp>
#include <boost/json/array.hpp>
#include <boost/json/object.hpp>
#include <string>

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
    endpoints->addEndpoint(HTTP::Method::PATCH, "moveAccountDetailFieldUp", SecurityRequirements::JWT_COOKIE_AUTH, {"CONFIG_WRITE"}, nullptr, &moveAccountDetailFieldUp);
    endpoints->addEndpoint(HTTP::Method::PATCH, "moveAccountDetailFieldDown", SecurityRequirements::JWT_COOKIE_AUTH, {"CONFIG_WRITE"}, nullptr, &moveAccountDetailFieldDown);

    endpoints->addEndpoint(HTTP::Method::POST, "extendAccountInactivity", SecurityRequirements::JWT_COOKIE_AUTH, {"ACCOUNT_MODIFY"}, nullptr, &extendInactivity);
}

AdminPortal_Endpoints_Accounts::APIReturn AdminPortal_Endpoints_Accounts::extendInactivity(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    std::string accountUUID(Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", ""));
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
    accountFlags.fromJSON(Helpers::JSON::MEMBER_OR_NULL(*request.inputJSON, "flags"));

    // Can't create admin from non-admin account:
    if (accountFlags.admin && !request.jwtToken->isAdmin())
    {
        accountFlags.admin = false;
    }

    // Parse application definitions from request
    std::map<std::string, ApplicationDef> applicationDefs;
    for (const auto &app : Helpers::JSON::ASARRAY_OR_EMPTY(*request.inputJSON, "applications"))
    {
        ApplicationDef appDef;
        std::string appName(Helpers::JSON::ASSTRING(app, "name", ""));
        appDef.isAppAdmin = Helpers::JSON::ASBOOL(app, "isAppAdmin", false);

        // Can't create application admin without APP_MODIFY scope.
        if (appDef.isAppAdmin && !request.jwtToken->hasScope("APP_MODIFY"))
        {
            appDef.isAppAdmin = false;
        }

        // Parse roles
        for (const auto &role : Helpers::JSON::ASARRAY_OR_EMPTY(app, "roles"))
        {
            appDef.roles.insert(std::string(Helpers::JSON::ASSTRING_D(role, "")));
        }

        // Parse scopes
        for (const auto &scope : Helpers::JSON::ASARRAY_OR_EMPTY(app, "scopes"))
        {
            appDef.scopes.insert(std::string(Helpers::JSON::ASSTRING_D(scope, "")));
        }

        if (!applicationDefs.count(appName))
        {
            applicationDefs[appName] = appDef;
        }
    }

    // Add default applications (Login Portal and User Portal) if not already provided in input
    if (!applicationDefs.count(IAM_LOGINPORTAL_APPNAME))
    {
        applicationDefs[IAM_LOGINPORTAL_APPNAME] = {accountFlags.admin};
    }
    if (!applicationDefs.count(IAM_USRPORTAL_APPNAME))
    {
        applicationDefs[IAM_USRPORTAL_APPNAME] = {accountFlags.admin, {"GENERIC_USER"}};
    }
    if (accountFlags.admin && !applicationDefs.count(IAM_ADMPORTAL_APPNAME))
    {
        applicationDefs[IAM_ADMPORTAL_APPNAME] = {accountFlags.admin};
    }

    // Parse detail field values from request
    std::map<std::string, std::string> fieldValues;

    for (const auto &fv : Helpers::JSON::ASARRAY_OR_EMPTY(*request.inputJSON, "fieldValues"))
    {
        std::string fieldName(Helpers::JSON::ASSTRING(fv, "name", ""));
        std::string fieldValue(Helpers::JSON::ASSTRING(fv, "value", ""));

        if (!fieldName.empty())
        {
            fieldValues[fieldName] = fieldValue;
        }
    }

    // Add the new account to the system with specified expiration and flags
    int64_t expirationDate = Helpers::JSON::ASINT64(*request.inputJSON, "expirationDate", 0);
    CreateAccountResult createResult = Globals::getIdentityManager()
                                           ->accounts->createAccount(expirationDate, accountFlags, authClientDetails, request.jwtToken->getSubject(), applicationDefs, fieldValues);
    if (!createResult.success)
    {
        // Check if the failure is due to detail field validation
        auto detailStatus = createResult.detailResult.status;
        if (detailStatus != UpdateAccountDetailFieldValuesResult::Status::SUCCESS)
        {
            switch (detailStatus)
            {
            case UpdateAccountDetailFieldValuesResult::Status::INVALID_FIELD:
                return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_field", "One or more field names do not exist: " + boost::algorithm::join(createResult.detailResult.duplicateFields, ", ")};

            case UpdateAccountDetailFieldValuesResult::Status::PERMISSION_DENIED:
                return {HTTP::Status::Code::S_403_FORBIDDEN, "permission_denied", "User lacks permission to edit one or more detail fields"};

            case UpdateAccountDetailFieldValuesResult::Status::REGEX_VALIDATION_FAILED:
                return {HTTP::Status::Code::S_400_BAD_REQUEST,
                        "regex_validation_failed",
                        "One or more field values failed regex validation: " + boost::algorithm::join(createResult.detailResult.regexInvalidFields, ", ")};

            case UpdateAccountDetailFieldValuesResult::Status::DUPLICATE_LOGIN_IDENTIFIER:
                return {HTTP::Status::Code::S_409_CONFLICT,
                        "duplicate_login_identifier",
                        "Login identifier conflict for field(s): " + boost::algorithm::join(createResult.detailResult.duplicateFields, ", ")};

            case UpdateAccountDetailFieldValuesResult::Status::DUPLICATE_UNIQUE_FIELD:
                return {HTTP::Status::Code::S_409_CONFLICT,
                        "duplicate_unique_field",
                        "Unique field conflict for field(s): " + boost::algorithm::join(createResult.detailResult.uniqueInvalidFields, ", ")};

            case UpdateAccountDetailFieldValuesResult::Status::DB_ERROR:
            default:
                return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "db_error", "Database error while setting account detail field values"};
            }
        }

        // General database/transaction failure (account insert, activation token, application association, roles, scopes, or transaction commit)
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "db_error", "Failed to create the account in the database. The transaction was rolled back."};
    }

    const std::string &accountUUID = createResult.accountUUID;

    // Extract credential information from request
    boost::json::value tempCredential = Helpers::JSON::MEMBER_OR_NULL(*request.inputJSON, "tempCredential");
    std::string secretTempPass(Helpers::JSON::ASSTRING(*request.inputJSON, "secretTempPass", ""));

    Credential newCredentialData;
    uint32_t slotId = Helpers::JSON::ASUINT(*request.inputJSON, "slotId", 1);

    // Either tempCredential or secretTempPass must be provided
    if (tempCredential != boost::json::value{})
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

    return response;
}

API::APIReturn AdminPortal_Endpoints_Accounts::getAccountFlags(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    APIReturn response;
    std::string accountUUID(Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", ""));

    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    return Globals::getIdentityManager()->accounts->getAccountFlags(accountUUID).toJSON();
}

API::APIReturn AdminPortal_Endpoints_Accounts::changeAccountFlags(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    APIReturn response;
    std::string accountUUID(Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", ""));

    if (!Helpers::JSON::HAS_MEMBER(*request.inputJSON, "flags"))
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account flags are required"};
    }

    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account name is required"};
    }

    AccountFlags flags;
    flags.fromJSON(Helpers::JSON::MEMBER_OR_NULL(*request.inputJSON, "flags"));

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
    std::string accountUUID(Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", ""));

    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account UUID is required"};
    }

    if (!Globals::getIdentityManager()->accounts->doesAccountExist(accountUUID))
    {
        return {HTTP::Status::Code::S_404_NOT_FOUND, "not_found", "The Account does not exist in the system."};
    }

    std::string displayName = Globals::getIdentityManager()->accounts->getAccountDisplayName(accountUUID);

    return boost::json::value(boost::json::object{
        {"displayName", displayName},
    });
}

API::APIReturn AdminPortal_Endpoints_Accounts::searchAccounts(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    return Globals::getIdentityManager()->accounts->searchAccounts(*request.inputJSON);
}

API::APIReturn AdminPortal_Endpoints_Accounts::getAccountApplications(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    const std::string accountUUID(Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", ""));

    std::set<std::string> listAccountApplications = Globals::getIdentityManager()->applications->listAccountApplications(accountUUID);
    std::set<ApplicationScope> directScopes = Globals::getIdentityManager()->applicationScopes->getAccountDirectApplicationScopes(accountUUID);

    // Build the applications the account already belongs to
    boost::json::array applications{};
    for (const std::string &applicationName : listAccountApplications)
    {
        std::set<ApplicationScope> usableScopes = Globals::getIdentityManager()->applicationScopes->getAccountUsableApplicationScopes(applicationName, accountUUID);

        std::set<ApplicationRole> allAppRoles = Globals::getIdentityManager()->applicationRoles->getApplicationRolesList(applicationName);
        std::set<ApplicationRole> usedAppRoles = Globals::getIdentityManager()->accounts->getAccountApplicationRoles(applicationName, accountUUID);

        // Add used roles
        boost::json::array usedRoles{};
        for (const ApplicationRole &role : usedAppRoles)
        {
            Helpers::JSON::ARRAY_APPEND(usedRoles, role.toJSON());
        }

        // Add available roles (roles that can be added)
        boost::json::array availableRoles{};
        for (const ApplicationRole &role : allAppRoles)
        {
            if (usedAppRoles.find(role) == usedAppRoles.end())
            {
                Helpers::JSON::ARRAY_APPEND(availableRoles, role.toJSON());
            }
        }

        // Direct scopes assigned to this account
        boost::json::array directScopesOut{};
        for (const ApplicationScope &directApplicationScope : directScopes)
        {
            if (directApplicationScope.appName == applicationName)
            {
                Helpers::JSON::ARRAY_APPEND(directScopesOut, directApplicationScope.toJSON());
            }
        }

        // Direct scopes not yet assigned (available)
        boost::json::array directScopesLeft{};
        for (const ApplicationScope &scope : Globals::getIdentityManager()->applicationScopes->listApplicationScopes(applicationName))
        {
            if (directScopes.find(scope) == directScopes.end())
            {
                Helpers::JSON::ARRAY_APPEND(directScopesLeft, scope.toJSON());
            }
        }

        // Usable scopes
        boost::json::array usableScopesOut{};
        for (const ApplicationScope &usableScope : usableScopes)
        {
            Helpers::JSON::ARRAY_APPEND(usableScopesOut, usableScope.toJSON());
        }

        boost::json::object application{
            {"name",             applicationName},
            // TODO: optimize:
            {"description",      Globals::getIdentityManager()->applications->getApplicationDescription(applicationName)},
            {"usedRoles",        usedRoles},
            {"availableRoles",   availableRoles},
            {"directScopes",     directScopesOut},
            {"directScopesLeft", directScopesLeft},
            {"usableScopes",     usableScopesOut},
        };
        Helpers::JSON::ARRAY_APPEND(applications, application);
    }

    // Build the applications the account does not belong to yet
    boost::json::array applicationsLeft{};
    for (const std::string &applicationName : Globals::getIdentityManager()->applications->listApplications())
    {
        if (listAccountApplications.find(applicationName) == listAccountApplications.end())
        {
            boost::json::object application{
                {"name",        applicationName},
                {"description", Globals::getIdentityManager()->applications->getApplicationDescription(applicationName)},
            };
            Helpers::JSON::ARRAY_APPEND(applicationsLeft, application);
        }
    }

    return boost::json::object{
        {"applications",      applications},
        {"applicationsLeft",  applicationsLeft},
    };
}

API::APIReturn AdminPortal_Endpoints_Accounts::addAccountToApplication(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string accountUUID(Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", ""));
    std::string appName(Helpers::JSON::ASSTRING(*request.inputJSON, "appName", ""));

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

    std::string accountUUID(Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", ""));
    std::string appName(Helpers::JSON::ASSTRING(*request.inputJSON, "appName", ""));

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
    boost::json::array fieldsArray{};

    std::map<std::string, AccountDetailField> fields = Globals::getIdentityManager()->accounts->listAccountDetailFields();
    for (const auto &fieldPair : fields)
    {
        boost::json::object accountDetailFieldJSON = fieldPair.second.toJSON();
        accountDetailFieldJSON["fieldName"] = fieldPair.first;
        fieldsArray.push_back(accountDetailFieldJSON);
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
    std::string fieldName(Helpers::JSON::ASSTRING((*request.inputJSON), "fieldName", ""));
    if (fieldName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Field Key Name is Empty"};
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
    std::string fieldName(Helpers::JSON::ASSTRING((*request.inputJSON), "fieldName", ""));
    if (fieldName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Field Key Name is Empty"};
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
    std::string fieldName(Helpers::JSON::ASSTRING((*request.inputJSON), "fieldName", ""));
    if (fieldName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Field Key Name is Empty"};
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

    std::string fieldName(Helpers::JSON::ASSTRING((*request.inputJSON), "fieldName", ""));
    if (fieldName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Field Key Name is Empty"};
    }
    std::optional<AccountDetailField> field = Globals::getIdentityManager()->accounts->getAccountDetailField(fieldName);
    if (!field)
    {
        return {HTTP::Status::Code::S_500_INTERNAL_SERVER_ERROR, "field_not_found", "Field not found"};
    }

    return field.value().toJSON();
}

API::APIReturn AdminPortal_Endpoints_Accounts::moveAccountDetailFieldUp(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    std::string fieldName(Helpers::JSON::ASSTRING((*request.inputJSON), "fieldName", ""));
    if (fieldName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Field Key Name is Empty"};
    }

    if (!Globals::getIdentityManager()->accounts->moveAccountDetailFieldUp(authClientDetails, request.jwtToken->getSubject(), fieldName))
    {
        return {HTTP::Status::Code::S_404_NOT_FOUND, "field_not_found", "Field not found"};
    }

    return {};
}

API::APIReturn AdminPortal_Endpoints_Accounts::moveAccountDetailFieldDown(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    std::string fieldName(Helpers::JSON::ASSTRING((*request.inputJSON), "fieldName", ""));
    if (fieldName.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Field Key Name is Empty"};
    }

    if (!Globals::getIdentityManager()->accounts->moveAccountDetailFieldDown(authClientDetails, request.jwtToken->getSubject(), fieldName))
    {
        return {HTTP::Status::Code::S_404_NOT_FOUND, "field_not_found", "Field not found"};
    }

    return {};
}

API::APIReturn AdminPortal_Endpoints_Accounts::getAccountDetailFieldsValues(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string accountUUID(Helpers::JSON::ASSTRING((*request.inputJSON), "accountUUID", ""));
    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty"};
    }

    std::map<std::string, AccountDetailFieldValue> fieldValues = Globals::getIdentityManager()->accounts->getAccountDetailFieldValues(accountUUID);

    std::vector<std::pair<std::string, AccountDetailFieldValue>> sortedFieldValues(fieldValues.begin(), fieldValues.end());
    std::sort(sortedFieldValues.begin(),
              sortedFieldValues.end(),
              [](const std::pair<std::string, AccountDetailFieldValue> &a, const std::pair<std::string, AccountDetailFieldValue> &b) { return a.second.orderPriority < b.second.orderPriority; });

    boost::json::array result{};
    for (const auto &fieldValue : sortedFieldValues)
    {
        Helpers::JSON::ARRAY_APPEND(result, fieldValue.second.toJSON());
    }
    return result;
}

API::APIReturn AdminPortal_Endpoints_Accounts::updateAccountDetailFieldsValues(void *context, const RequestContext &request, ClientDetails &authClientDetails)
{
    API::APIReturn response;

    std::string accountUUID(Helpers::JSON::ASSTRING((*request.inputJSON), "accountUUID", ""));
    if (accountUUID.empty())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Account Name is Empty"};
    }

    // Get the list of field values from input
    boost::json::value fieldValuesArray = Helpers::JSON::MEMBER_OR_NULL(*request.inputJSON, "fieldValues");
    if (!fieldValuesArray.is_array())
    {
        return {HTTP::Status::Code::S_400_BAD_REQUEST, "invalid_request", "Field values must be an array"};
    }

    std::map<std::string, std::string> fieldValues;

    // Process each field value in the array
    for (const auto &i : fieldValuesArray.as_array())
    {
        std::string fieldName(Helpers::JSON::ASSTRING(i, "name", ""));
        std::string fieldValue(Helpers::JSON::ASSTRING(i, "value", ""));
        if (!fieldName.empty())
        {
            fieldValues[fieldName] = fieldValue;
        }
    }

    // Update account detail fields values
    UpdateAccountDetailFieldValuesResult result = Globals::getIdentityManager()->accounts->updateAccountDetailFieldValues(authClientDetails,
                                                                                                                          request.jwtToken->getSubject(),
                                                                                                                          accountUUID,
                                                                                                                          fieldValues,
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
    std::string accountUUID(Helpers::JSON::ASSTRING(*request.inputJSON, "accountUUID", ""));

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
