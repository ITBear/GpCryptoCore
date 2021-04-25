#pragma once

#include "AddressGroup.hpp"

namespace GPlatform {
/*
class GPCRYPTOCORE_API Wallet
{
public:
    CLASS_REMOVE_CTRS_EXCEPT_DEFAULT(Wallet)
    CLASS_DECLARE_DEFAULTS(Wallet)

    using HDAddrGroupsT = AddressGroup::C::MapCountT::SP;

public:
                                Wallet              (void);
                                ~Wallet             (void) noexcept;

    void                        Clear               (void) noexcept;
    void                        Set                 (Wallet&& aWallet) noexcept;

    Address::SP                 GenRndAddr          (void);
    Address::SP                 GenNextHDAddr       (const count_t aHDGroupId);
    void                        DeleteAddr          (std::string_view aName);
    Address::SP                 FindAddr            (std::string_view aName);
    count_t                     AddHDGroup          (GpRawPtrCharR aMnemonic, GpRawPtrCharR aPassword);
    void                        DeleteHDGroup       (const count_t aHDGroupId);

    const AddressGroup&         RndAddrGroup        (void) const noexcept {return iRndAddrGroup;}
    const HDAddrGroupsT&        HDAddrGroups        (void) const noexcept {return iHDAddrGroups;}
    count_t                     HDAddrGroupLastId   (void) const noexcept {return iHDAddrGroupLastId;}

private:
    AddressGroup                iRndAddrGroup;
    HDAddrGroupsT               iHDAddrGroups;
    count_t                     iHDAddrGroupLastId = 0_cnt;
};
*/
}//namespace GPlatform
