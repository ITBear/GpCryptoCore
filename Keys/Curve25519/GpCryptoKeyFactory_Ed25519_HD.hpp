#pragma once

#include "../GpCryptoKeyFactory.hpp"
#include "../HD/GpCryptoHDKeyStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoKeyFactory_Ed25519_HD final: public GpCryptoKeyFactory
{
public:
    CLASS_REMOVE_CTRS(GpCryptoKeyFactory_Ed25519_HD)
    CLASS_DECLARE_DEFAULTS(GpCryptoKeyFactory_Ed25519_HD)

public:
                                    GpCryptoKeyFactory_Ed25519_HD   (const GpCryptoHDKeyStorage&    aParentHDKeyStorage);
                                    GpCryptoKeyFactory_Ed25519_HD   (GpCryptoHDKeyStorage&&         aParentHDKeyStorage);
    virtual                         ~GpCryptoKeyFactory_Ed25519_HD  (void) noexcept override final;

    virtual GpCryptoKeyPair::SP     Generate                        (void) override final;

    virtual void                    Serialize                       (GpByteWriter& aWriter) const override final;
    virtual void                    Deserialize                     (GpByteReader& aReader) override final;

private:
    GpCryptoHDKeyStorage            iParentHDKeyStorage;
    count_t                         iChildNumber        = 0_cnt;
};

}//GPlatform
