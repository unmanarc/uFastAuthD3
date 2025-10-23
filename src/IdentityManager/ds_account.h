#pragma once

#include <Mantids30/Helpers/json.h>
#include <ctime>
#include <optional>
#include <string>

enum AccountDetailsToShow
{
    ACCOUNT_DETAILS_ALL,
    ACCOUNT_DETAILS_SEARCH,
    ACCOUNT_DETAILS_COLUMNVIEW,
    ACCOUNT_DETAILS_APISYNC,
    ACCOUNT_DETAILS_TOKEN
};


struct AccountDetailFieldValue
{
    std::string name;
    std::string description;
    std::string fieldType;
    std::string fieldRegexpValidator;
    std::optional<std::string> value;

    Json::Value toJSON() const
    {
        Json::Value fieldJson;
        fieldJson["name"] = name;
        fieldJson["description"] = description;
        fieldJson["type"] = fieldType;
        fieldJson["regexpValidator"] = fieldRegexpValidator;

        if (value.has_value())
            fieldJson["value"] = value.value();
        else
            fieldJson["value"] = Json::Value(Json::nullValue);
        return fieldJson;
    }

    void fromJSON(const Json::Value &json)
    {
        name = JSON_ASSTRING(json, "name", "");
        description = JSON_ASSTRING(json, "description", "");
        fieldType = JSON_ASSTRING(json, "type", "");
        fieldRegexpValidator = JSON_ASSTRING(json, "regexpValidator", "");
        if (json.isMember("value") && !json["value"].isNull())
            value = JSON_ASSTRING(json, "value", "");
    }
};


struct AccountDetailField
{
    std::string description;
    std::string fieldType = "TEXTLINE";
    bool isOptionalField = true;
    bool isUnique = false;
    json extendedAttributes;

    std::string getRegexpValidatorText()
    {
        return JSON_ASSTRING(extendedAttributes["behavior"],"regexpValidator","");
    }

    Json::Value toJSON() const
    {
        Json::Value r;
        r["description"] = description;
        r["fieldType"] = fieldType;
        r["isOptionalField"] = isOptionalField;
        r["isUnique"] = isUnique;
        r["extendedAttributes"] = extendedAttributes;
        return r;
    }

    void fromJSON(const Json::Value &r)
    {
        description = JSON_ASSTRING(r, "description", "");
        fieldType = JSON_ASSTRING(r, "fieldType", "TEXTLINE");
        isOptionalField = JSON_ASBOOL(r, "isOptionalField", true);
        isUnique = JSON_ASBOOL(r, "isUnique", false);
        extendedAttributes = r["extendedAttributes"];
    }
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
    AccountFlags() {}

    Json::Value toJSON() const
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
        enabled = JSON_ASBOOL(r, "enabled", false);
        confirmed = JSON_ASBOOL(r, "confirmed", false);
        admin = JSON_ASBOOL(r, "admin", false);
        blocked = JSON_ASBOOL(r, "blocked", false);
    }

    bool blocked = false;
    bool enabled = false;
    bool confirmed = false;
    bool admin = false;
};
struct AccountDetails
{
    AccountDetails() {}

    std::map<std::string, AccountDetailFieldValue> fields;
    //std::map<std::string, std::string> fieldValues;
    std::string accountName, creator;
    AccountFlags accountFlags;
    time_t expirationDate, creationDate;
    bool expired;

    Json::Value toJSON() const
    {
        Json::Value r;

        r["fields"] = json::null;
        for (auto &i : fields)
        {
            r["fields"][i.first] = i.second.toJSON();
        }

        r["accountName"] = accountName;
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

        accountName = JSON_ASSTRING(r, "accountName", "");
        creator = JSON_ASSTRING(r, "creator", "");
        accountFlags.fromJSON(r["accountFlags"]);
        expirationDate = JSON_ASUINT64(r, "expirationDate", 0);
        expired = std::time(nullptr) > expirationDate;
    }
};
