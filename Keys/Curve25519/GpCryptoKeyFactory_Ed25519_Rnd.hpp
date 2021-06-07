#pragma once

#include "../GpCryptoKeyFactory.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoKeyFactory_Ed25519_Rnd final: public GpCryptoKeyFactory
{
public:
    CLASS_REMOVE_CTRS_EXCEPT_DEFAULT(GpCryptoKeyFactory_Ed25519_Rnd)
    CLASS_DECLARE_DEFAULTS(GpCryptoKeyFactory_Ed25519_Rnd)

public:
                                    GpCryptoKeyFactory_Ed25519_Rnd  (void) noexcept;
    virtual                         ~GpCryptoKeyFactory_Ed25519_Rnd (void) noexcept override final;

    virtual GpCryptoKeyPair::CSP    Generate                        (void) override final;
    //virtual void                  Serialize                       (GpByteWriter& aWriter) const override final;
    //virtual void                  Deserialize                     (GpByteReader& aReader) override final;
};

}//GPlatform
