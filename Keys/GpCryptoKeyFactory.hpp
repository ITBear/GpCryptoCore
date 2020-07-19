#pragma once

#include "GpCryptoKeyPair.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoKeyFactory
{
public:
    CLASS_REMOVE_CTRS_EXCEPT_DEFAULT(GpCryptoKeyFactory)
    CLASS_DECLARE_DEFAULTS(GpCryptoKeyFactory)

protected:
                                    GpCryptoKeyFactory  (void) noexcept = default;
    virtual                         ~GpCryptoKeyFactory (void) noexcept = default;

public:
    virtual GpCryptoKeyPair::SP     Generate            (void) = 0;
};

}//namespace GPlatform
