#include "GpCryptoAddressGroup.hpp"
#include "GpCryptoWalletUtils.hpp"

namespace GPlatform {

GpCryptoAddressGroup::GpCryptoAddressGroup
(
    const GpUUID&               aUID,
    GpCryptoKeyFactory::SP      aKeyFactory,
    GpCryptoAddressFactory::SP  aAddrFactory
) noexcept:
iUID(aUID),
iKeyFactory(std::move(aKeyFactory)),
iAddrFactory(std::move(aAddrFactory))
{
}

GpCryptoAddressGroup::~GpCryptoAddressGroup (void) noexcept
{
}

GpCryptoAddress::SP GpCryptoAddressGroup::GenerateNext (void)
{
    GpCryptoAddress::SP addr = GpCryptoWalletUtils::SNewAddrFromFactory(iAddrFactory.V(), iKeyFactory.V());
    iAddrsList.emplace(addr->UID(), addr);
    return addr;
}

bool    GpCryptoAddressGroup::Delete (const GpUUID& aAddrUID)
{
    auto iter = iAddrsList.find(aAddrUID);

    if (iter == iAddrsList.end())
    {
        return false;
    }

    iAddrsList.erase(iter);

    return true;
}

std::optional<GpCryptoAddress::SP>  GpCryptoAddressGroup::Find (const GpUUID& aAddrUID)
{
    auto iter = iAddrsList.find(aAddrUID);

    if (iter == iAddrsList.end())
    {
        return std::nullopt;
    }

    return iter->second;
}

GpCryptoAddress::C::Vec::SP GpCryptoAddressGroup::FindAllByName (std::string_view aAddrName)
{
    GpCryptoAddress::C::Vec::SP res;

    for (auto& addr: iAddrsList)
    {
        if (addr.second.VC().Name() == aAddrName)
        {
            res.emplace_back(addr.second);
        }
    }

    return res;
}

}//namespace GPlatform
