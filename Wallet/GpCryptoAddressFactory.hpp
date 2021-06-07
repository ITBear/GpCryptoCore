#pragma once

#include "GpCryptoAddress.hpp"

namespace GPlatform {

class GpCryptoAddressFactory
{
public:
    CLASS_REMOVE_CTRS_EXCEPT_DEFAULT(GpCryptoAddressFactory)
    CLASS_DECLARE_DEFAULTS(GpCryptoAddressFactory)

protected:
                                    GpCryptoAddressFactory  (void) noexcept {}

public:
    virtual                         ~GpCryptoAddressFactory (void) noexcept {}

    virtual GpCryptoAddress::SP     Generate                (GpCryptoKeyFactory& aKeyFactory) = 0;
};

}//namespace GPlatform
