#include "Wallet.hpp"
#include "WalletUtils.hpp"

namespace GPlatform {
/*
Wallet::Wallet (void):
iRndAddrGroup(MakeSP<GpCryptoKeyFactory_Ed25519_Rnd>())
{
}

Wallet::~Wallet (void) noexcept
{
}

void    Wallet::Clear (void) noexcept
{
    iRndAddrGroup.Clear();
    iHDAddrGroups.clear();
    iHDAddrGroupLastId = 0_cnt;
}

void    Wallet::Set (Wallet&& aWallet) noexcept
{
    Clear();

    iRndAddrGroup       = std::move(aWallet.iRndAddrGroup);
    iHDAddrGroups       = std::move(aWallet.iHDAddrGroups);
    iHDAddrGroupLastId  = aWallet.iHDAddrGroupLastId;

    aWallet.Clear();
}

Address::SP Wallet::GenRndAddr (void)
{
    return iRndAddrGroup.GenNext();
}

Address::SP Wallet::GenNextHDAddr (const count_t aHDGroupId)
{
    return iHDAddrGroups.at(aHDGroupId)->GenNext();
}

void    Wallet::DeleteAddr (std::string_view aName)
{
    if (iRndAddrGroup.IsContainAddr(aName))
    {
        iRndAddrGroup.Delete(aName);
        return;
    }

    for (auto& iter: iHDAddrGroups)
    {
        auto& g = iter.second.V();
        if (g.IsContainAddr(aName))
        {
            g.Delete(aName);
            return;
        }
    }

    THROW_GPE("Addres '"_sv + aName + "' not found"_sv);
}

Address::SP Wallet::FindAddr (std::string_view aName)
{
    if (iRndAddrGroup.IsContainAddr(aName))
    {
        return iRndAddrGroup.Find(aName);
    }

    for (auto& iter: iHDAddrGroups)
    {
        auto& g = iter.second.V();

        if (g.IsContainAddr(aName))
        {
            return g.Find(aName);
        }
    }

    THROW_GPE("Addres '"_sv + aName + "' not found"_sv);
}

count_t Wallet::AddHDGroup (GpRawPtrCharR aMnemonic, GpRawPtrCharR aPassword)
{
    GpCryptoKeyFactory::SP hdKeyFactory = WalletUtils::SNewHDKeyFactoryMnemonic(aMnemonic, aPassword);

    iHDAddrGroupLastId++;

    iHDAddrGroups.insert({iHDAddrGroupLastId, MakeSP<AddressGroup>(hdKeyFactory)});

    return iHDAddrGroupLastId;
}

void    Wallet::DeleteHDGroup (const count_t aHDGroupId)
{
    iHDAddrGroups.erase(aHDGroupId);
}
*/
}//namespace GPlatform
