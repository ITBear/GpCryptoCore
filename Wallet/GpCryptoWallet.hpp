#pragma once

#include "GpCryptoAddressGroup.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoWallet
{
public:
    CLASS_REMOVE_CTRS(GpCryptoWallet)
    CLASS_DECLARE_DEFAULTS(GpCryptoWallet)

    using HDAddrGroupsT = GpCryptoAddressGroup::C::MapUuid::SP;

public:
                                            GpCryptoWallet      (GpCryptoAddressFactory::SP aAddrFactory) noexcept;
                                            ~GpCryptoWallet     (void) noexcept;

    GpCryptoAddress::SP                     GenerateNextRndAddr (void);
    GpCryptoAddress::SP                     GenerateNextHDAddr  (const GpUUID& aGroupUID);

    std::optional<GpCryptoAddress::SP>      FindAddr            (const GpUUID& aAddrUID);
    GpCryptoAddress::C::Vec::SP             FindAddrAllByName   (std::string_view aAddrName);
    [[nodiscard]] bool                      DeleteAddr          (const GpUUID& aAddrUID);

    GpCryptoAddressGroup::SP                AddHDGroup          (GpRawPtrCharR  aMnemonic,
                                                                 GpRawPtrCharR  aPassword);
    std::optional<GpCryptoAddressGroup::SP> FindHDGroup         (const GpUUID& aGroupUID);
    [[nodiscard]] bool                      DeleteHDGroup       (const GpUUID& aGroupUID);

private:
    GpCryptoAddressGroup&                   _RndAddrGroup       (void);

private:
    GpCryptoAddressFactory::SP              iAddrFactory;
    GpCryptoAddressGroup::SP                iRndAddrGroup;
    HDAddrGroupsT                           iHDAddrGroups;
};

}//namespace GPlatform
