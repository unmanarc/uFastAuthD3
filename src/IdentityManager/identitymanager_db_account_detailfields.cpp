#include "IdentityManager/identitymanager.h"
#include "identitymanager_db.h"
#include <Mantids30/Helpers/json.h>

#include <Mantids30/DB/transaction.h>
#include <Mantids30/Helpers/datatables.h>
#include <Mantids30/Helpers/random.h>
#include <Mantids30/Threads/lock_shared.h>
#include <boost/algorithm/string/join.hpp>
#include <boost/regex.hpp>
#include <json/value.h>
#include <optional>
#include <regex>

#include <Mantids30/Memory/a_bool.h>
#include <Mantids30/Memory/a_datetime.h>
#include <Mantids30/Memory/a_int32.h>
#include <Mantids30/Memory/a_string.h>
#include <Mantids30/Memory/a_uint32.h>
#include <Mantids30/Memory/a_uint64.h>
#include <Mantids30/Memory/a_var.h>

using namespace Mantids30;
using namespace Mantids30::Memory;
using namespace Mantids30::Database;

std::optional<AccountDetails> IdentityManager_DB::Accounts_DB::getAccountDetails(const std::string &accountUUID, const AccountDetailsToShow &detailsToShow)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    // Definir las variables para capturar los valores de la base de datos
    Abstract::STRING creator;
    Abstract::BOOL isAdmin, isEnabled, isAccountConfirmed;
    Abstract::DATETIME creation, expiration;

    std::map<std::string, AccountDetailField> allFields = listAccountDetailFields();
    AccountDetails details;

    {
        if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `isAdmin`,`creation`, `creator`, `expiration`, `isEnabled`, `isAccountConfirmed` "
                                                      "FROM iam.accounts WHERE `accountUUID`=:accountUUID LIMIT 1;",
                                                      {{":accountUUID", MAKE_VAR(STRING, accountUUID)}}, {&isAdmin, &creation, &creator, &expiration, &isEnabled, &isAccountConfirmed}))
        {
            details.accountUUID = accountUUID;
            details.creator = creator.getValue();
            details.accountFlags.admin = isAdmin.getValue();
            details.accountFlags.enabled = isEnabled.getValue();
            details.accountFlags.confirmed = isAccountConfirmed.getValue();
            details.expirationDate = expiration.getValue();
            details.creationDate = creation.getValue();
            details.expired = std::time(nullptr) > details.expirationDate;
        }
        else
        {
            return std::nullopt;
        }
    }

    details.fields = getAccountDetailFieldValues(accountUUID, detailsToShow);

    return details;
}

Json::Value IdentityManager_DB::Accounts_DB::searchFields(const Json::Value &dataTablesFilters)
{
    Json::Value ret;
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    // DataTables:
    ret["draw"] = dataTablesFilters["draw"];

    uint64_t offset = Helpers::JSON::ASUINT64(dataTablesFilters, "start", 0);
    uint64_t limit = Helpers::JSON::ASUINT64(dataTablesFilters, "length", 0);

    // Manejo de ordenamiento (order);
    std::string orderByStatement = Helpers::DataTables::getOrderByStatement(dataTablesFilters);

    // Extract the search value from dataTablesFilters
    std::string searchValue = Helpers::JSON::ASSTRING(dataTablesFilters["search"], "value", "");
    std::string whereFilters;

    // Build the SQL query with WHERE clause for DataTables search
    std::string sqlQueryStr = R"(
    SELECT
        fieldName,
        fieldDescription,
        fieldType,
        isOptionalField,
        isUnique,
        isLoginIdentifier,
        orderPriority
    FROM accountDetailFields
    )";

    // Add WHERE clause for search term if provided
    if (!searchValue.empty())
    {
        searchValue = "%" + searchValue + "%";
        whereFilters += "fieldName LIKE :SEARCHWORDS OR fieldDescription LIKE :SEARCHWORDS";
    }

    {
        Abstract::INT32 orderPriority;
        Abstract::STRING fieldName, fieldDescription, fieldType;
        Abstract::BOOL isOptionalField, isUnique, isLoginIdentifier;
        std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelectWithFilters(sqlQueryStr, whereFilters, {{":SEARCHWORDS", MAKE_VAR(STRING, searchValue)}},
                                                                               {&fieldName, &fieldDescription, &fieldType, &isOptionalField, &isUnique, &isLoginIdentifier, &orderPriority},
                                                                               orderByStatement, // Order by
                                                                               limit,            // LIMIT
                                                                               offset            // OFFSET
        );

        while (i && i->isSuccessful() && i->step())
        {
            Json::Value row;

            // fieldName
            row["fieldName"] = fieldName.toJSON();
            // fieldDescription
            row["fieldDescription"] = fieldDescription.toJSON();
            // fieldType
            row["fieldType"] = fieldType.toJSON();
            // isOptionalField
            row["isOptionalField"] = isOptionalField.getValue();
            // isUnique
            row["isUnique"] = isUnique.getValue();
            // isLoginIdentifier
            row["isLoginIdentifier"] = isLoginIdentifier.getValue();
            // orderPriority
            row["orderPriority"] = orderPriority.getValue();

            ret["data"].append(row);
        }

        if (i)
        {
            ret["recordsTotal"] = i->getTotalRecordsCount();
            ret["recordsFiltered"] = i->getFilteredRecordsCount();
        }
    }

    return ret;
}

bool IdentityManager_DB::Accounts_DB::createAccountDetailField(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &fieldName, const AccountDetailField &details)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);

    // Invalid condition.
    if (details.isLoginIdentifier && !details.isUnique)
    {
        return false;
    }

    if (_parent->m_sqlConnector
            ->qExecuteEx("INSERT INTO iam.accountDetailFields (`fieldName`, `fieldDescription`, `fieldType`, `isOptionalField`, `isUnique`,`isLoginIdentifier`, `jsonExtendedAttribs`, `orderPriority`)"
                         " VALUES (:fieldName, :fieldDescription, :fieldType, :isOptionalField, :isUnique, :isLoginIdentifier, :jsonExtendedAttribs, :orderPriority);",
                         {{":fieldName", MAKE_VAR(STRING, fieldName)},
                          {":fieldDescription", MAKE_VAR(STRING, details.description)},
                          {":fieldType", MAKE_VAR(STRING, details.fieldType)},
                          {":isOptionalField", MAKE_VAR(BOOL, details.isOptionalField)},
                          {":isUnique", MAKE_VAR(BOOL, details.isUnique)},
                          {":isLoginIdentifier", MAKE_VAR(BOOL, details.isLoginIdentifier)},
                          {":jsonExtendedAttribs", MAKE_VAR(STRING, details.extendedAttributes.toStyledString())},
                          {":orderPriority", MAKE_VAR(INT32, details.orderPriority)}}))
    {
        _parent->logSecurityEventOnAccountDetailFields(fieldName, SecurityEventAction::CREATE, "Account detail field created", performedBy, clientDetails);
        return true;
    }

    return false;
}

IdentityManager::Accounts::UpdateAccountDetailFieldResult IdentityManager_DB::Accounts_DB::updateAccountDetailField(const ClientDetails &clientDetails, const std::string &performedBy,
                                                                                                                    const std::string &fieldName, const AccountDetailField &details)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);

    // Invalid condition.
    if (details.isLoginIdentifier && !details.isUnique)
    {
        return UpdateAccountDetailFieldResult::FIELD_NOT_FOUND;
    }

    // Step 1: Check if the field exists and retrieve its current isLoginIdentifier and isUnique values.
    Abstract::BOOL currentIsLoginIdentifier;
    Abstract::BOOL currentIsUnique;
    bool fieldExists = _parent->m_sqlConnector->qSelectSingleRow("SELECT `isLoginIdentifier`, `isUnique` FROM iam.accountDetailFields WHERE `fieldName` = :fieldName;",
                                                                 {{":fieldName", MAKE_VAR(STRING, fieldName)}}, {&currentIsLoginIdentifier, &currentIsUnique});

    if (!fieldExists)
    {
        return UpdateAccountDetailFieldResult::FIELD_NOT_FOUND;
    }

    // Step 2: If this field is currently a login identifier and the update tries to disable it,
    // check if it's the last one.
    if (currentIsLoginIdentifier.getValue() && !details.isLoginIdentifier)
    {
        Abstract::INT32 loginIdentifierCount;
        if (_parent->m_sqlConnector->qSelectSingleRow("SELECT COUNT(*) FROM iam.accountDetailFields WHERE `isLoginIdentifier` = 1;", {}, {&loginIdentifierCount}))
        {
            if (loginIdentifierCount.getValue() <= 1)
            {
                // This is the last login identifier, cannot disable it.
                return UpdateAccountDetailFieldResult::LAST_LOGIN_IDENTIFIER;
            }
        }
    }

    // Step 2b: If isUnique is being enabled (and was previously disabled), check for duplicate values.
    if (details.isUnique && !currentIsUnique.getValue())
    {
        // isUnique is being enabled on a field that was not unique. Check for duplicates.
        Abstract::INT32 duplicateCount;
        if (_parent->m_sqlConnector->qSelectSingleRow(
                R"(SELECT COUNT(*) FROM (
                   SELECT value FROM iam.accountDetailValues
                   WHERE f_fieldName = :fieldName
                   AND value IS NOT NULL
                   GROUP BY value
                   HAVING COUNT(*) > 1
                   LIMIT 1))",
                {{":fieldName", MAKE_VAR(STRING, fieldName)}}, {&duplicateCount}))
        {
            if (duplicateCount.getValue() > 0)
            {
                // Duplicate values exist, cannot enable isUnique.
                return UpdateAccountDetailFieldResult::DUPLICATE_VALUES_FOR_UNIQUE_FIELD;
            }
        }
    }

    // Step 2c: If isLoginIdentifier is being enabled (and was previously disabled), check for value
    // conflicts across all login-identifier fields (existing ones plus this new one).
    if (!currentIsLoginIdentifier.getValue() && details.isLoginIdentifier)
    {
        // Collect all current login identifier field names.
        std::vector<std::string> loginIdentifierFields;
        {
            Abstract::STRING liFieldName;
            std::shared_ptr<Query> liQuery = _parent->m_sqlConnector->qSelect("SELECT `fieldName` FROM iam.accountDetailFields WHERE `isLoginIdentifier` = 1;", {}, {&liFieldName});
            if (liQuery && liQuery->isSuccessful())
            {
                while (liQuery->step())
                {
                    loginIdentifierFields.push_back(liFieldName.getValue());
                }
            }
        }

        // Add the new field to the list.
        loginIdentifierFields.push_back(fieldName);

        // Build a dynamic SQL query that checks for duplicate values across all these fields.
        if (!loginIdentifierFields.empty())
        {
            // Build the IN clause placeholders and parameters.
            std::vector<std::string> placeholders;
            std::map<std::string, std::shared_ptr<Mantids30::Memory::Abstract::Var>> params;
            for (size_t i = 0; i < loginIdentifierFields.size(); ++i)
            {
                std::string placeholder = ":field" + std::to_string(i);
                placeholders.push_back(placeholder);
                params[placeholder] = MAKE_VAR(STRING, loginIdentifierFields[i]);
            }

            // The query checks if any non-null value exists in more than one account
            // across all login-identifier fields (including the one being enabled).
            std::string sqlQuery = "SELECT COUNT(*) FROM ("
                                   "  SELECT value FROM iam.accountDetailValues"
                                   "  WHERE f_fieldName IN ("
                                   + boost::algorithm::join(placeholders, ", ")
                                   + ")"
                                     "    AND value IS NOT NULL"
                                     "    AND value != ''"
                                     "  GROUP BY value"
                                     "  HAVING COUNT(DISTINCT f_accountUUID) > 1"
                                     "  LIMIT 1"
                                     ") AS duplicates";

            Abstract::INT32 conflictCount;
            if (_parent->m_sqlConnector->qSelectSingleRow(sqlQuery, params, {&conflictCount}))
            {
                if (conflictCount.getValue() > 0)
                {
                    // Duplicate values found across login-identifier fields.
                    return UpdateAccountDetailFieldResult::LOGIN_IDENTIFIER_VALUE_CONFLICT;
                }
            }
        }
    }

    // Step 3: Update the field.
    if (!_parent->m_sqlConnector->qExecuteEx("UPDATE iam.accountDetailFields SET `fieldDescription`=:fieldDescription, `fieldType`=:fieldType, `isOptionalField`=:isOptionalField, "
                                             "`isUnique`=:isUnique, `isLoginIdentifier`=:isLoginIdentifier, `jsonExtendedAttribs`=:jsonExtendedAttribs WHERE `fieldName`=:fieldName;",
                                             {{":fieldName", MAKE_VAR(STRING, fieldName)},
                                              {":fieldDescription", MAKE_VAR(STRING, details.description)},
                                              {":fieldType", MAKE_VAR(STRING, details.fieldType)},
                                              {":isOptionalField", MAKE_VAR(BOOL, details.isOptionalField)},
                                              {":isUnique", MAKE_VAR(BOOL, details.isUnique)},
                                              {":isLoginIdentifier", MAKE_VAR(BOOL, details.isLoginIdentifier)},
                                              {":jsonExtendedAttribs", MAKE_VAR(STRING, details.extendedAttributes.toStyledString())}}))
    {
        return UpdateAccountDetailFieldResult::DB_ERROR;
    }

    _parent->logSecurityEventOnAccountDetailFields(fieldName, SecurityEventAction::UPDATE, "Account detail field updated", performedBy, clientDetails);

    return UpdateAccountDetailFieldResult::SUCCESS;
}

IdentityManager::Accounts::RemoveAccountDetailFieldResult IdentityManager_DB::Accounts_DB::removeAccountDetailField(const ClientDetails &clientDetails, const std::string &performedBy,
                                                                                                                    const std::string &fieldName)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);

    // Step 1: Check if the field exists and if it's a login identifier.
    Abstract::BOOL isLoginIdentifier;
    bool fieldExists = _parent->m_sqlConnector->qSelectSingleRow("SELECT `isLoginIdentifier` FROM iam.accountDetailFields WHERE `fieldName` = :fieldName;",
                                                                 {{":fieldName", MAKE_VAR(STRING, fieldName)}}, {&isLoginIdentifier});

    if (!fieldExists)
    {
        return RemoveAccountDetailFieldResult::FIELD_NOT_FOUND;
    }

    // Step 2: If this field is a login identifier, check if it's the last one.
    if (isLoginIdentifier.getValue())
    {
        Abstract::INT32 loginIdentifierCount;
        if (_parent->m_sqlConnector->qSelectSingleRow("SELECT COUNT(*) FROM iam.accountDetailFields WHERE `isLoginIdentifier` = 1;", {}, {&loginIdentifierCount}))
        {
            if (loginIdentifierCount.getValue() <= 1)
            {
                // This is the last login identifier, cannot remove it.
                return RemoveAccountDetailFieldResult::LAST_LOGIN_IDENTIFIER;
            }
        }
    }

    // Step 3: Delete the field.
    if (!_parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountDetailFields WHERE `fieldName` = :fieldName;", {{":fieldName", MAKE_VAR(STRING, fieldName)}}))
    {
        return RemoveAccountDetailFieldResult::DB_ERROR;
    }

    _parent->logSecurityEventOnAccountDetailFields(fieldName, SecurityEventAction::DELETE, "Account detail field removed", performedBy, clientDetails);

    return RemoveAccountDetailFieldResult::SUCCESS;
}

std::map<std::string, AccountDetailField> IdentityManager_DB::Accounts_DB::listAccountDetailFields()
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);
    return _listAccountDetailFields();
}
std::optional<AccountDetailField> IdentityManager_DB::Accounts_DB::getAccountDetailField(const std::string &fieldName)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    AccountDetailField field;

    // Variables para capturar valores de la base de datos
    Abstract::STRING fieldDescription, fieldType;
    Abstract::BOOL isOptionalField, isUnique, isLoginIdentifier;
    Abstract::STRING jsonExtendedAttribsText;
    Abstract::INT32 orderPriority;

    if (_parent->m_sqlConnector->qSelectSingleRow(
            "SELECT `fieldDescription`,`fieldType`,`isOptionalField`, `isUnique`, `isLoginIdentifier`,`jsonExtendedAttribs`,`orderPriority` FROM `iam`.`accountDetailFields` WHERE `fieldName` = :fieldName;",
            {{":fieldName", MAKE_VAR(STRING, fieldName)}}, {&fieldDescription, &fieldType, &isOptionalField, &isUnique, &isLoginIdentifier, &jsonExtendedAttribsText, &orderPriority}))
    {
        Json::Value r;
        Json::Reader().parse(jsonExtendedAttribsText.getValue(), r);

        field.description = fieldDescription.getValue();
        field.fieldType = fieldType.getValue();
        field.isOptionalField = isOptionalField.getValue();
        field.isUnique = isUnique.getValue();
        field.isLoginIdentifier = isLoginIdentifier.getValue();
        field.extendedAttributes = r;
        field.orderPriority = orderPriority.getValue();

        return field;
    }

    // Return empty optional if not found
    return std::nullopt;
}

bool IdentityManager_DB::Accounts_DB::changeAccountDetails(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID,
                                                           const std::map<std::string, std::string> &fieldsValues, bool resetAllValues)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    Transaction tg(*_parent->m_sqlConnector);

    if (resetAllValues)
    {
        // Delete all values for the specified account
        if (!_parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountDetailValues WHERE `f_accountUUID` = :accountUUID;", {{":accountUUID", MAKE_VAR(STRING, accountUUID)}}))
        {
            return tg.finalize(false);
        }
    }
    else
    {
        // Delete only specified fields for the account
        for (const auto &field : fieldsValues)
        {
            if (!_parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountDetailValues WHERE `f_accountUUID` = :accountUUID AND `f_fieldName` = :fieldName;",
                                                     {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":fieldName", MAKE_VAR(STRING, field.first)}}))
            {
                return tg.finalize(false);
            }
        }
    }

    // Insert new values
    for (const auto &field : fieldsValues)
    {
        // Validate field value against regex from iam.accountDetailFields
        Abstract::STRING regex;
        if (_parent->m_sqlConnector->qSelectSingleRow("SELECT `fieldRegexpValidator` FROM iam.accountDetailFields WHERE `fieldName` = :fieldName;", {{":fieldName", MAKE_VAR(STRING, field.first)}},
                                                      {&regex}))
        {
            std::regex reg(regex.getValue());
            if (!std::regex_match(field.second, reg))
            {
                // The value does not match the regex
                return tg.finalize(false);
            }
        }

        // Inserting the validated value
        if (!_parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.accountDetailValues (`f_accountUUID`, `f_fieldName`, `value`) VALUES(:accountUUID, :fieldName, :value);",
                                                 {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":fieldName", MAKE_VAR(STRING, field.first)}, {":value", MAKE_VAR(STRING, field.second)}}))
        {
            return tg.finalize(false);
        }
    }

    // Commit the transaction
    _parent->logSecurityEventOnAccounts(accountUUID, SecurityEventAction::UPDATE, resetAllValues ? "All account details reset" : "Account details updated", performedBy, clientDetails);

    return tg.finalize();
}

bool IdentityManager_DB::Accounts_DB::removeAccountDetail(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, const std::string &fieldName)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);

    bool result = _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountDetailValues WHERE `f_accountUUID` = :accountUUID AND `f_fieldName` = :fieldName;",
                                                      {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":fieldName", MAKE_VAR(STRING, fieldName)}});
    if (result)
    {
        _parent->logSecurityEventOnAccounts(accountUUID, SecurityEventAction::DELETE, "Account detail removed", performedBy, clientDetails);
    }
    return result;
}

UpdateAccountDetailFieldValuesResult IdentityManager_DB::Accounts_DB::updateAccountDetailFieldValues(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID,
                                                                                                     const std::map<std::string, std::string> &inputFieldValues, bool isAdmin)
{
    std::unique_lock<std::shared_mutex> lock(_parent->m_mutex);
    Database::Transaction tg(*_parent->m_sqlConnector);

    UpdateAccountDetailFieldValuesResult result = _updateAccountDetailFieldValues(clientDetails,performedBy,accountUUID,inputFieldValues,isAdmin);
    if (result.status == UpdateAccountDetailFieldValuesResult::Status::SUCCESS)
    {
        bool finalized = tg.finalize(true);
        if (!finalized)
        {
            result.status = UpdateAccountDetailFieldValuesResult::Status::DB_ERROR;
        }
        return result;
    }
    else
    {
        tg.finalize(false);
        return result;
    }
}

std::map<std::string, AccountDetailField> IdentityManager_DB::Accounts_DB::_listAccountDetailFields()
{

    std::map<std::string, AccountDetailField> fieldMap;

    // Variables para capturar valores de la base de datos
    Abstract::STRING fieldName, fieldDescription, fieldType;
    Abstract::BOOL isOptionalField, isUnique, isLoginIdentifier;
    Abstract::STRING jsonExtendedAttribsText;
    Abstract::INT32 orderPriority;

    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect(
        "SELECT `fieldName`, `fieldDescription`, `fieldType`, `isOptionalField`, `isUnique`, `isLoginIdentifier`, `jsonExtendedAttribs`, `orderPriority` FROM `iam`.`accountDetailFields` ORDER BY `orderPriority` ASC;", {},
        {&fieldName, &fieldDescription, &fieldType, &isOptionalField, &isUnique, &isLoginIdentifier, &jsonExtendedAttribsText, &orderPriority});

    if (i && i->isSuccessful())
    {
        while (i->step())
        {
            Json::Value r;
            Json::Reader().parse(jsonExtendedAttribsText.getValue(), r);

            AccountDetailField field;
            field.description = fieldDescription.getValue();
            field.fieldType = fieldType.getValue();
            field.isOptionalField = isOptionalField.getValue();
            field.isUnique = isUnique.getValue();
            field.isLoginIdentifier = isLoginIdentifier.getValue();
            field.extendedAttributes = r;
            field.orderPriority = orderPriority.getValue();

            fieldMap[fieldName.getValue()] = field;
        }
    }

    return fieldMap;
}

UpdateAccountDetailFieldValuesResult IdentityManager_DB::Accounts_DB::_updateAccountDetailFieldValues(const ClientDetails &clientDetails, const std::string &performedBy, const std::string &accountUUID, const std::map<std::string, std::string> &inputFieldValues, bool isAdmin)
{
    UpdateAccountDetailFieldValuesResult result;
    std::map<std::string, AccountDetailField> dbFieldsScheme = _listAccountDetailFields();

    // TODO: log the field update operation.
    for (const auto &[fieldName, fieldValue] : inputFieldValues)
    {
        // Validate field exists.
        if (dbFieldsScheme.find(fieldName) == dbFieldsScheme.end())
        {
            result.status = UpdateAccountDetailFieldValuesResult::Status::INVALID_FIELD;
            return result;
        }

        if (!dbFieldsScheme[fieldName].canUserEdit() && !isAdmin)
        {
            result.status = UpdateAccountDetailFieldValuesResult::Status::PERMISSION_DENIED;
            return result;
        }

        std::string regexpValidator = dbFieldsScheme[fieldName].getRegexpValidatorText();
        if (!regexpValidator.empty())
        {
            try
            {
                boost::regex regExp(regexpValidator);
                if (!boost::regex_search(fieldValue, regExp))
                {
                    result.regexInvalidFields.insert(fieldName);
                }
            }
            catch (const boost::regex_error &)
            {
                // if not defined, continue.
            }
        }
    }

    if (!result.regexInvalidFields.empty())
    {
        result.status = UpdateAccountDetailFieldValuesResult::Status::REGEX_VALIDATION_FAILED;
        return result;
    }


    // Validate that login-identifier values do not collide with values from other accounts.
    for (const auto &[fieldName, fieldValue] : inputFieldValues)
    {
        if (dbFieldsScheme.find(fieldName) != dbFieldsScheme.end() && dbFieldsScheme[fieldName].isLoginIdentifier)
        {
            Abstract::INT32 conflictCount;
            if (_parent->m_sqlConnector->qSelectSingleRow(
                    R"(SELECT COUNT(*) FROM iam.accountDetailValues vadv
                       INNER JOIN iam.accountDetailFields vadf ON vadf.fieldName = vadv.f_fieldName
                       WHERE vadf.isLoginIdentifier = 1
                         AND vadv.value = :value
                         AND vadv.f_accountUUID != :accountUUID)",
                    {{":value", MAKE_VAR(STRING, fieldValue)}, {":accountUUID", MAKE_VAR(STRING, accountUUID)}}, {&conflictCount}))
            {
                if (conflictCount.getValue() > 0)
                {
                    result.duplicateFields.insert(fieldName);
                }
            }
        }
    }

    if (!result.duplicateFields.empty())
    {
        result.status = UpdateAccountDetailFieldValuesResult::Status::DUPLICATE_LOGIN_IDENTIFIER;
        return result;
    }

    // Validate that unique values do not collide with values from other accounts.
    for (const auto &[fieldName, fieldValue] : inputFieldValues)
    {
        if (dbFieldsScheme.find(fieldName) != dbFieldsScheme.end() && dbFieldsScheme[fieldName].isUnique)
        {
            Abstract::INT32 conflictCount;
            if (_parent->m_sqlConnector->qSelectSingleRow(
                    R"(SELECT COUNT(*) FROM iam.accountDetailValues vadv
                       INNER JOIN iam.accountDetailFields vadf ON vadf.fieldName = vadv.f_fieldName
                       WHERE vadf.isUnique = 1
                         AND vadf.fieldName = :fieldName
                         AND vadv.value = :value
                         AND vadv.f_accountUUID != :accountUUID)",
                    {{":fieldName", MAKE_VAR(STRING, fieldName)}, {":value", MAKE_VAR(STRING, fieldValue)}, {":accountUUID", MAKE_VAR(STRING, accountUUID)}}, {&conflictCount}))
            {
                if (conflictCount.getValue() > 0)
                {
                    result.uniqueInvalidFields.insert(fieldName);
                }
            }
        }
    }

    if (!result.uniqueInvalidFields.empty())
    {
        result.status = UpdateAccountDetailFieldValuesResult::Status::DUPLICATE_UNIQUE_FIELD;
        return result;
    }


    // Delete all the fields that are going to be replaced.
    if (isAdmin)
    {
        _parent->m_sqlConnector->qExecuteEx("DELETE FROM iam.accountDetailValues WHERE `f_accountUUID` = :accountUUID;", {{":accountUUID", MAKE_VAR(STRING, accountUUID)}});
    }
    else
    {
        std::set<std::string> editableFields;
        for (const auto &field : dbFieldsScheme)
        {
            if ((field.second.canUserEdit() && !isAdmin) || isAdmin)
            {
                editableFields.insert(field.first);
            }
        }

        for (const std::string &fieldName : editableFields)
        {
            std::string sql = "DELETE FROM iam.accountDetailValues WHERE `f_accountUUID` = :account AND `f_fieldName` = :field;";
            std::map<std::string, std::shared_ptr<Mantids30::Memory::Abstract::Var>> params;
            params[":account"] = MAKE_VAR(STRING, accountUUID);
            params[":field"] = MAKE_VAR(STRING, fieldName);
            if (!_parent->m_sqlConnector->qExecuteEx(sql, params))
            {
                // Maybe the field does not exist yet...
            }
        }
    }

    // Insert all the fields to the database.
    for (const auto &[fieldName, fieldValue] : inputFieldValues)
    {
        if (dbFieldsScheme.find(fieldName) != dbFieldsScheme.end())
        {
            if (!_parent->m_sqlConnector->qExecuteEx("INSERT INTO iam.accountDetailValues (`f_accountUUID`, `f_fieldName`, `value`) VALUES(:accountUUID, :fieldName, :value);",
                                                     {{":accountUUID", MAKE_VAR(STRING, accountUUID)}, {":fieldName", MAKE_VAR(STRING, fieldName)}, {":value", MAKE_VAR(STRING, fieldValue)}}))
            {
                _parent->m_sqlConnector->rollbackTransaction();
                result.status = UpdateAccountDetailFieldValuesResult::Status::DB_ERROR;
                return result;
            }
        }
    }

    _parent->logSecurityEventOnAccounts(accountUUID, SecurityEventAction::UPDATE, "Account detail field values updated", performedBy, clientDetails);
    return result;
}

std::map<std::string, AccountDetailFieldValue> IdentityManager_DB::Accounts_DB::getAccountDetailFieldValues(const std::string &accountUUID, const AccountDetailsToShow &detailsToShow)
{
    std::shared_lock<std::shared_mutex> lock(_parent->m_mutex);

    std::map<std::string, AccountDetailFieldValue> detailValues;

    Abstract::STRING fieldName, fieldDescription, fieldType, jsonExtendedAttribsText, value;

    std::string query = R"(
                            SELECT vadf.fieldName, vadf.fieldDescription, vadf.fieldType, vadf.jsonExtendedAttribs, vadv.value
                            FROM iam.accountDetailFields vadf
                            LEFT JOIN iam.accountDetailValues vadv ON vadf.fieldName = vadv.f_fieldName
                            AND vadv.f_accountUUID = :accountUUID
                        )";

    std::shared_ptr<Query> i = _parent->m_sqlConnector->qSelect(query, {{":accountUUID", MAKE_VAR(STRING, accountUUID)}}, {&fieldName, &fieldDescription, &fieldType, &jsonExtendedAttribsText, &value});

    if (i && i->isSuccessful())
    {
        while (i->step())
        {
            Json::Value extendedAttributes;
            Json::Reader().parse(jsonExtendedAttribsText.getValue(), extendedAttributes);

            bool visible = false;

            switch (detailsToShow)
            {
            case AccountDetailsToShow::SEARCH:
                visible = Helpers::JSON::ASBOOL(extendedAttributes["visibility"], "includeInSearch", false);
                break;
            case AccountDetailsToShow::COLUMNVIEW:
                visible = Helpers::JSON::ASBOOL(extendedAttributes["visibility"], "includeInColumnView", false);
                break;
            case AccountDetailsToShow::TOKEN:
                visible = Helpers::JSON::ASBOOL(extendedAttributes["visibility"], "includeInToken", false);
                break;
            case AccountDetailsToShow::APISYNC:
                visible = Helpers::JSON::ASBOOL(extendedAttributes["visibility"], "includeInAPISync", false);
                break;
            case AccountDetailsToShow::ALL:
            default:
                // no additional filter for ALL
                visible = true;
                break;
            }

            visible &= Helpers::JSON::ASBOOL(extendedAttributes["security"], "canUserView", false);

            if (visible)
            {
                AccountDetailFieldValue field;
                field.name = fieldName.getValue();
                field.description = fieldDescription.getValue();
                field.fieldType = fieldType.getValue();
                field.fieldRegexpValidator = Helpers::JSON::ASSTRING(extendedAttributes["behavior"], "regexpValidator", ""); // TODO: remover esta linea
                field.extendedAttribs = extendedAttributes;

                if (value.isNull())
                {
                    field.value = std::nullopt;
                }
                else
                {
                    field.value = value.getValue();
                }

                detailValues[fieldName.getValue()] = field;
            }
        }
    }

    return detailValues;
}
