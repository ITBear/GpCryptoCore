#pragma once

#include "GpCryptoKeyPair.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoKeyFactory
{
public:
    CLASS_REMOVE_CTRS_EXCEPT_DEFAULT(GpCryptoKeyFactory)
    CLASS_DECLARE_DEFAULTS(GpCryptoKeyFactory)

protected:
                                    GpCryptoKeyFactory  (void) noexcept {}

public:
    virtual                         ~GpCryptoKeyFactory (void) noexcept {}

    virtual GpCryptoKeyPair::SP     Generate            (void) = 0;
    virtual void                    Serialize           (GpByteWriter& aWriter) const = 0;
    virtual void                    Deserialize         (GpByteReader& aReader) = 0;
};

}//namespace GPlatform
