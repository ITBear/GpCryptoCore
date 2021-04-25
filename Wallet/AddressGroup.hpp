#pragma once

#include "Address.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API AddressGroup
{
public:
    CLASS_REMOVE_CTRS_EXCEPT_MOVE(AddressGroup)
    CLASS_DECLARE_DEFAULTS(AddressGroup)

    using AddrListT = GpMap<std::string, Address::SP, std::less<>>;

public:
                                AddressGroup    (AddressGroup&& aAddressGroup) noexcept;
                                AddressGroup    (GpCryptoKeyFactory::SP aFactory);
                                ~AddressGroup   (void) noexcept;

    AddressGroup&               operator=       (AddressGroup&& aAddressGroup);

    void                        Clear           (void) noexcept;
    void                        Set             (AddressGroup&& aGroup) noexcept;

    Address::SP                 GenNext         (void);
    void                        Delete          (std::string_view aName);
    Address::SP                 Find            (std::string_view aName);
    bool                        IsContainAddr   (std::string_view aName) const;
    const AddrListT&            AddrsList       (void) const noexcept {return iAddrsList;}
    const GpCryptoKeyFactory&   Factory         (void) const {return iFactory.VC();}

private:
    GpCryptoKeyFactory::SP      iFactory;
    AddrListT                   iAddrsList;
};

}//namespace GPlatform
