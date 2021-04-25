#include "AddressGroup.hpp"
#include "WalletUtils.hpp"

namespace GPlatform {

AddressGroup::AddressGroup (AddressGroup&& aAddressGroup) noexcept:
iFactory(std::move(aAddressGroup.iFactory)),
iAddrsList(std::move(aAddressGroup.iAddrsList))
{
}

AddressGroup::AddressGroup (GpCryptoKeyFactory::SP aFactory):
iFactory(std::move(aFactory))
{
}

AddressGroup::~AddressGroup (void) noexcept
{
    Clear();
}

AddressGroup&   AddressGroup::operator= (AddressGroup&& aAddressGroup)
{
    iFactory    = std::move(aAddressGroup.iFactory);
    iAddrsList  = std::move(aAddressGroup.iAddrsList);

    return *this;
}

void    AddressGroup::Clear (void) noexcept
{
    iFactory.Clear();
    iAddrsList.clear();
}

void    AddressGroup::Set (AddressGroup&& aGroup) noexcept
{
    Clear();

    iFactory    = std::move(aGroup.iFactory);
    iAddrsList  = std::move(aGroup.iAddrsList);

    aGroup.Clear();
}

Address::SP AddressGroup::GenNext (void)
{
    Address::SP addr = WalletUtils::SNewAddrFromFactory(iFactory.V());
    iAddrsList.emplace(addr.VCn().Name(), addr);
    return addr;
}

void    AddressGroup::Delete (std::string_view aName)
{
    auto iter = iAddrsList.find(aName);

    if (iter == iAddrsList.end())
    {
        THROW_GPE("Addres '"_sv + aName + "' not found"_sv);
    }

    iAddrsList.erase(iter);
}

Address::SP AddressGroup::Find (std::string_view aName)
{
    auto iter = iAddrsList.find(aName);

    if (iter == iAddrsList.end())
    {
        THROW_GPE("Addres '"_sv + aName + "' not found"_sv);
    }

    return iter->second;
}

bool    AddressGroup::IsContainAddr (std::string_view aName) const
{
    return iAddrsList.count(aName) > 0;
}

}//namespace GPlatform
