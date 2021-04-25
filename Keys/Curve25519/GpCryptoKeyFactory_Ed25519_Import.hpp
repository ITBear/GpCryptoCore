#pragma once

#include "../GpCryptoKeyFactory.hpp"

namespace GPlatform {

/*class GPCRYPTOCORE_API GpCryptoKeyFactory_Ed25519_Import final: public GpCryptoKeyFactory
{
public:
    CLASS_REMOVE_CTRS(GpCryptoKeyFactory_Ed25519_Import)
    CLASS_DECLARE_DEFAULTS(GpCryptoKeyFactory_Ed25519_Import)

public:
                                    GpCryptoKeyFactory_Ed25519_Import   (const GpSecureStorage& aSeed);
                                    GpCryptoKeyFactory_Ed25519_Import   (GpSecureStorage&& aSeed);
                                    GpCryptoKeyFactory_Ed25519_Import   (GpRawPtrByteR aSeed);
    virtual                         ~GpCryptoKeyFactory_Ed25519_Import  (void) noexcept override final;

    virtual GpCryptoKeyPair::SP     Generate                            (void) override final;
    virtual void                    Serialize                           (GpByteWriter& aWriter) const override final;
    virtual void                    Deserialize                         (GpByteReader& aReader) override final;

private:
    GpSecureStorage                 iSeed;
};*/

}//GPlatform
