#include "credentialdata.h"
#include "Mantids30/DataFormat_JSON/json_accessors.h"
#include "Mantids30/DataFormat_JSON/json_convert.h"
#include <boost/json/value.hpp>

using namespace Mantids30;

CredentialData::CredentialData(const std::string &password, const uint32_t &slotId)
{
    this->m_password = password;
    this->m_slotId = slotId;
}

bool CredentialData::parse(std::string_view sAuth)
{

    boost::json::value x;

    if (sAuth.empty())
    {
        return true;
    }

    Helpers::JSON::Reader reader;

    if (!reader.parse(sAuth, x))
    {
        return false;
    }

    if (!x.is_object())
    {
        return false;
    }

    return setJSON(x);
}

bool CredentialData::setJSON(const boost::json::value &jsonObject)
{
    if (!Helpers::JSON::HAS_MEMBER(jsonObject,"pass") || Helpers::JSON::HAS_MEMBER(jsonObject,"slotId"))
    {
        return false;
    }

    this->m_password = Helpers::JSON::ASSTRING(jsonObject, "pass", "");
    this->m_slotId = Helpers::JSON::ASUINT(jsonObject, "slotId", 0);

    return true;
}

boost::json::object CredentialData::toJSON() const
{
    return boost::json::object{
        {"pass",   this->m_password},
        {"slotId", this->m_slotId},
    };
}
