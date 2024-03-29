#pragma once

#include "../GpCryptoKeyFactory.hpp"
#include "../HD/GpCryptoHDKeyStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoKeyFactory_Ed25519_HD final: public GpCryptoKeyFactory
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoKeyFactory_Ed25519_HD)
    CLASS_DECLARE_DEFAULTS(GpCryptoKeyFactory_Ed25519_HD)

public:
                                    GpCryptoKeyFactory_Ed25519_HD   (GpCryptoHDKeyStorage::CSP aParentHDKeyStorage) noexcept;
    virtual                         ~GpCryptoKeyFactory_Ed25519_HD  (void) noexcept override final;

    virtual GpCryptoKeyPair::CSP    Generate                        (void) override final;

    //virtual void                  Serialize                       (GpByteWriter& aWriter) const override final;
    //virtual void                  Deserialize                     (GpByteReader& aReader) override final;

private:
    GpCryptoHDKeyStorage::CSP       iParentHDKeyStorage;
    count_t                         iChildNumber        = 0_cnt;
};

}//GPlatform
