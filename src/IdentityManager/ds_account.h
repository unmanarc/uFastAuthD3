#pragma once

#include "Mantids30/DataFormat_JSON/json_detail.h"
#include <Mantids30/DataFormat_JSON/json.h>
#include <Mantids30/Helpers/json.h>
#include <boost/json/value.hpp>
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
    boost::json::value extendedAttribs;
    int orderPriority = 0;

    [[nodiscard]] boost::json::object toJSON() const
    {
        boost::json::value fieldValue = value.has_value() ? boost::json::value(value.value()) : boost::json::value{};
        return boost::json::object{
            {"extendedAttribs",   extendedAttribs},
            {"name",              name},
            {"description",       description},
            {"type",              fieldType},
            {"regexpValidator",   fieldRegexpValidator},
            {"orderPriority",     orderPriority},
            {"value",             fieldValue},
        };
    }

    void fromJSON(const boost::json::value &json)
    {
        name = Mantids30::Helpers::JSON::ASSTRING(json, "name", "");
        description = Mantids30::Helpers::JSON::ASSTRING(json, "description", "");
        fieldType = Mantids30::Helpers::JSON::ASSTRING(json, "type", "");
        fieldRegexpValidator = Mantids30::Helpers::JSON::ASSTRING(json, "regexpValidator", "");
        extendedAttribs = Mantids30::Helpers::JSON::MEMBER_OR_NULL(json, "extendedAttribs");
        orderPriority = Mantids30::Helpers::JSON::ASINT(json, "orderPriority", 0);

        boost::json::value _value = Mantids30::Helpers::JSON::MEMBER_OR_NULL(json, "value");
        if (!_value.is_null())
        {
            value = Mantids30::Helpers::JSON::ASSTRING_D(json, "value");
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
    boost::json::value extendedAttributes;

    [[nodiscard]] std::string_view getRegexpValidatorText() const { return Mantids30::Helpers::JSON::ASSTRING( Mantids30::Helpers::JSON::MEMBER_OR_NULL(extendedAttributes,"behavior"), "regexpValidator", ""); }

    [[nodiscard]] bool canUserEdit() const { return Mantids30::Helpers::JSON::ASBOOL(Mantids30::Helpers::JSON::MEMBER_OR_NULL(extendedAttributes,"security"), "canUserEdit", false); }

    [[nodiscard]] boost::json::object toJSON() const
    {
        return boost::json::object{
            {"orderPriority",      orderPriority},
            {"description",        description},
            {"fieldType",          fieldType},
            {"isOptionalField",    isOptionalField},
            {"isUnique",           isUnique},
            {"isLoginIdentifier",  isLoginIdentifier},
            {"extendedAttributes", extendedAttributes},
        };
    }

    void fromJSON(const boost::json::value &r)
    {
        orderPriority = Mantids30::Helpers::JSON::ASINT(r, "orderPriority", 0);
        description = Mantids30::Helpers::JSON::ASSTRING(r, "description", "");
        fieldType = Mantids30::Helpers::JSON::ASSTRING(r, "fieldType", "TEXTLINE");
        isOptionalField = Mantids30::Helpers::JSON::ASBOOL(r, "isOptionalField", true);
        isUnique = Mantids30::Helpers::JSON::ASBOOL(r, "isUnique", false);
        isLoginIdentifier = Mantids30::Helpers::JSON::ASBOOL(r, "isLoginIdentifier", false);
        extendedAttributes = Mantids30::Helpers::JSON::MEMBER_OR_NULL(r, "extendedAttributes");
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

    [[nodiscard]] boost::json::object toJSON() const
    {
        return boost::json::object{
            {"enabled",   enabled},
            {"confirmed", confirmed},
            {"admin",     admin},
            {"blocked",   blocked},
        };
    }

    void fromJSON(const boost::json::value &r)
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

    [[nodiscard]] boost::json::object toJSON() const
    {
        boost::json::object fieldsObj;
        for (const auto &i : fields)
        {
            fieldsObj[i.first] = i.second.toJSON();
        }
        return boost::json::object{
            {"fields",         fieldsObj},
            {"accountUUID",    accountUUID},
            {"creator",        creator},
            {"accountFlags",   accountFlags.toJSON()},
            {"expirationDate", expirationDate},
            {"creationDate",   creationDate},
        };
    }

    void fromJSON(const boost::json::value &r)
    {
        // Deserialize 'fields' map
        const boost::json::value &fieldsJson = Mantids30::Helpers::JSON::MEMBER_OR_NULL(r, "fields");
        if (fieldsJson.is_object())
        {
            for (const auto &kv : fieldsJson.as_object())
            {
                AccountDetailFieldValue field;
                field.fromJSON(kv.value());
                fields[std::string(kv.key())] = field;
            }
        }

        accountUUID = std::string(Mantids30::Helpers::JSON::ASSTRING(r, "accountUUID", ""));
        creator = std::string(Mantids30::Helpers::JSON::ASSTRING(r, "creator", ""));
        accountFlags.fromJSON(Mantids30::Helpers::JSON::MEMBER_OR_NULL(r, "accountFlags"));
        expirationDate = Mantids30::Helpers::JSON::ASINT64(r, "expirationDate", 0);
        expired = std::time(nullptr) > expirationDate;
    }
};
