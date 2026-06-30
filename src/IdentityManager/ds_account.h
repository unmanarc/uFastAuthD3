#pragma once

#include <json/value.h>
#include <Mantids30/Helpers/json.h>
#include <ctime>
#include <optional>
#include <set>
#include <string>

enum class AccountDetailsToShow : uint8_t
{
    ALL,
    SEARCH,
    COLUMNVIEW,
    APISYNC,
    TOKEN
};

struct AccountDetailFieldValue
{
    std::string name;
    std::string description;
    std::string fieldType;
    std::string fieldRegexpValidator;
    std::optional<std::string> value;
    Json::Value extendedAttribs;

    [[nodiscard]] Json::Value toJSON() const
    {
        Json::Value fieldJson;
        fieldJson["extendedAttribs"] = extendedAttribs;
        fieldJson["name"] = name;
        fieldJson["description"] = description;
        fieldJson["type"] = fieldType;
        fieldJson["regexpValidator"] = fieldRegexpValidator;

        if (value.has_value())
        {
            fieldJson["value"] = value.value();
        }
        else
        {
            fieldJson["value"] = Json::Value(Json::nullValue);
        }
        return fieldJson;
    }

    void fromJSON(const Json::Value &json)
    {
        name = Mantids30::Helpers::JSON::ASSTRING(json, "name", "");
        description = Mantids30::Helpers::JSON::ASSTRING(json, "description", "");
        fieldType = Mantids30::Helpers::JSON::ASSTRING(json, "type", "");
        fieldRegexpValidator = Mantids30::Helpers::JSON::ASSTRING(json, "regexpValidator", "");
        extendedAttribs = json["extendedAttribs"];
        if (json.isMember("value") && !json["value"].isNull())
        {
            value = Mantids30::Helpers::JSON::ASSTRING(json, "value", "");
        }
    }
};

struct AccountDetailField
{
    std::string description;
    std::string fieldType = "TEXTLINE";
    bool isOptionalField = true;
    bool isUnique = false;
    bool isLoginIdentifier = false;
    int orderPriority = 0;
    Json::Value extendedAttributes;

    [[nodiscard]] std::string getRegexpValidatorText() const { return Mantids30::Helpers::JSON::ASSTRING(extendedAttributes["behavior"], "regexpValidator", ""); }

    [[nodiscard]] bool canUserEdit() const { return Mantids30::Helpers::JSON::ASBOOL(extendedAttributes["security"], "canUserEdit", false); }

    [[nodiscard]] Json::Value toJSON() const
    {
        Json::Value r;
        r["orderPriority"] = orderPriority;
        r["description"] = description;
        r["fieldType"] = fieldType;
        r["isOptionalField"] = isOptionalField;
        r["isUnique"] = isUnique;
        r["isLoginIdentifier"] = isLoginIdentifier;
        r["extendedAttributes"] = extendedAttributes;
        return r;
    }

    void fromJSON(const Json::Value &r)
    {
        orderPriority = Mantids30::Helpers::JSON::ASINT(r, "orderPriority", 0);
        description = Mantids30::Helpers::JSON::ASSTRING(r, "description", "");
        fieldType = Mantids30::Helpers::JSON::ASSTRING(r, "fieldType", "TEXTLINE");
        isOptionalField = Mantids30::Helpers::JSON::ASBOOL(r, "isOptionalField", true);
        isUnique = Mantids30::Helpers::JSON::ASBOOL(r, "isUnique", false);
        isLoginIdentifier = Mantids30::Helpers::JSON::ASBOOL(r, "isLoginIdentifier", false);
        extendedAttributes = r["extendedAttributes"];
    }
};

struct UpdateAccountDetailFieldValuesResult
{
    enum class Status : uint8_t
    {
        SUCCESS = 0,                        // All fields updated successfully.
        DUPLICATE_LOGIN_IDENTIFIER = 1,     // One or more login-identifier values conflict with another account.
        DUPLICATE_UNIQUE_FIELD = 2,         // One or more login-identifier values conflict with another account.
        INVALID_FIELD = 3,                  // One or more field names do not exist.
        PERMISSION_DENIED = 4,              // User lacks permission to edit one or more fields.
        REGEX_VALIDATION_FAILED = 5,        // One or more values failed regex validation.
        DB_ERROR = 6                        // Database error occurred.
    };

    Status status = Status::SUCCESS;
    std::set<std::string> duplicateFields;      // Field names whose login-identifier values already exist in another account.
    std::set<std::string> uniqueInvalidFields;  // Field names whose unique values conflict.
    std::set<std::string> regexInvalidFields;   // Field names that failed regex validation.
};

struct CreateAccountResult
{
    bool success = false;                            // true if account creation succeeded.
    std::string accountUUID;                         // The created account UUID (empty if failed).
    UpdateAccountDetailFieldValuesResult detailResult; // Result of setting account detail field values.
};

struct AccountFlags
{
    AccountFlags(bool enabled, bool confirmed, bool admin, bool blocked)
    {
        this->enabled = enabled;
        this->confirmed = confirmed;
        this->admin = admin;
        this->blocked = blocked;
    }
    AccountFlags() = default;

    [[nodiscard]] Json::Value toJSON() const
    {
        Json::Value r;
        r["enabled"] = enabled;
        r["confirmed"] = confirmed;
        r["admin"] = admin;
        r["blocked"] = blocked;
        return r;
    }

    void fromJSON(const Json::Value &r)
    {
        enabled = Mantids30::Helpers::JSON::ASBOOL(r, "enabled", false);
        confirmed = Mantids30::Helpers::JSON::ASBOOL(r, "confirmed", false);
        admin = Mantids30::Helpers::JSON::ASBOOL(r, "admin", false);
        blocked = Mantids30::Helpers::JSON::ASBOOL(r, "blocked", false);
    }

    bool blocked = false;
    bool enabled = false;
    bool confirmed = false;
    bool admin = false;
};
struct AccountDetails
{
    AccountDetails() = default;

    std::map<std::string, AccountDetailFieldValue> fields;
    std::string accountUUID, creator;
    AccountFlags accountFlags;
    time_t expirationDate = 0, creationDate = 0;
    bool expired = true;

    [[nodiscard]] Json::Value toJSON() const
    {
        Json::Value r;

        r["fields"] = Json::nullValue;
        for (const auto &i : fields)
        {
            r["fields"][i.first] = i.second.toJSON();
        }

        r["accountUUID"] = accountUUID;
        r["creator"] = creator;
        r["accountFlags"] = accountFlags.toJSON();
        r["expirationDate"] = expirationDate;
        r["creationDate"] = creationDate;
        return r;
    }

    void fromJSON(const Json::Value &r)
    {
        // Deserialize 'fields' map
        const Json::Value &fieldsJson = r["fields"];
        for (Json::ValueConstIterator it = fieldsJson.begin(); it != fieldsJson.end(); ++it)
        {
            AccountDetailFieldValue field;
            field.fromJSON(*it);
            fields[it.key().asString()] = field;
        }

        accountUUID = Mantids30::Helpers::JSON::ASSTRING(r, "accountUUID", "");
        creator = Mantids30::Helpers::JSON::ASSTRING(r, "creator", "");
        accountFlags.fromJSON(r["accountFlags"]);
        expirationDate = Mantids30::Helpers::JSON::ASINT64(r, "expirationDate", 0);
        expired = std::time(nullptr) > expirationDate;
    }
};
