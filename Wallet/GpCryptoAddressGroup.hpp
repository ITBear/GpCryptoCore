#pragma once

#include "GpCryptoAddressFactory.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoAddressGroup
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoAddressGroup)
    CLASS_DECLARE_DEFAULTS(GpCryptoAddressGroup)

    using AddrListT = GpMap<GpUUID, GpCryptoAddress::SP, std::less<>>;

public:
                                        GpCryptoAddressGroup    (const GpUUID&              aUID,
                                                                 GpCryptoKeyFactory::SP     aKeyFactory,
                                                                 GpCryptoAddressFactory::SP aAddrFactory) noexcept;
                                        ~GpCryptoAddressGroup   (void) noexcept;

    const GpUUID&                       UID                     (void) const noexcept {return iUID;}

    GpCryptoAddress::SP                 GenerateNext        (void);
    [[nodiscard]] bool                  Delete              (const GpUUID& aAddrUID);
    std::optional<GpCryptoAddress::SP>  Find                (const GpUUID& aAddrUID);
    GpCryptoAddress::C::Vec::SP         FindAllByName       (std::string_view aAddrName);
    const AddrListT&                    AddrsList           (void) const noexcept {return iAddrsList;}

private:
    const GpUUID                        iUID;
    GpCryptoKeyFactory::SP              iKeyFactory;
    GpCryptoAddressFactory::SP          iAddrFactory;
    AddrListT                           iAddrsList;
};

}//namespace GPlatform
