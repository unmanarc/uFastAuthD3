#include "credentialdata.h"

using namespace Mantids30;

CredentialData::CredentialData(const std::string &password, const uint32_t &slotId)
{
    this->m_password = password;
    this->m_slotId = slotId;
}

bool CredentialData::parse(const std::string &sAuth)
{
    Json::Value x;

    if (sAuth.empty())
    {
        return true;
    }

    Helpers::JSON::JSONReader2 reader;

    if (!reader.parse(sAuth, x))
    {
        return false;
    }
    if (!x.isObject())
    {
        return false;
    }

    return setJSON(x);
}

bool CredentialData::setJSON(const Json::Value &jsonObject)
{
    if (jsonObject["pass"].isNull() || jsonObject["slotId"].isNull())
    {
        return false;
    }

    this->m_password = Helpers::JSON::ASSTRING(jsonObject, "pass", "");
    this->m_slotId = Helpers::JSON::ASUINT(jsonObject, "slotId", 0);

    return true;
}

Json::Value CredentialData::toJSON() const
{
    Json::Value x;
    x["pass"] = this->m_password;
    x["slotId"] = this->m_slotId;
    return x;
}
