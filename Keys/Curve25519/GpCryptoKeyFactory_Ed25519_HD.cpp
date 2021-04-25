#include "GpCryptoKeyFactory_Ed25519_HD.hpp"
#include "GpCryptoKeyPair_Ed25519.hpp"
#include "../HD/GpCryptoHDKeys.hpp"
#include "GpCryptoKeyFactory_Ed25519_Import.hpp"

GP_WARNING_PUSH()
GP_WARNING_DISABLE(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {
/*
GpCryptoKeyFactory_Ed25519_HD::GpCryptoKeyFactory_Ed25519_HD (const GpCryptoHDKeyStorage& aParentHDKeyStorage):
iParentHDKeyStorage(aParentHDKeyStorage)
{
}

GpCryptoKeyFactory_Ed25519_HD::GpCryptoKeyFactory_Ed25519_HD (GpCryptoHDKeyStorage&& aParentHDKeyStorage):
iParentHDKeyStorage(std::move(aParentHDKeyStorage))
{
}

GpCryptoKeyFactory_Ed25519_HD::~GpCryptoKeyFactory_Ed25519_HD (void) noexcept
{
}

GpCryptoKeyPair::SP GpCryptoKeyFactory_Ed25519_HD::Generate (void)
{
    THROW_GPE_COND
    (
        iParentHDKeyStorage.SchemeType() == GpCryptoHDSchemeType::SLIP10_ED25519,
        "HD scheme type must be SLIP10_ED25519"_sv
    );

    GpCryptoHDKeyStorage keyStorageHD = GpCryptoHDKeyGen::SChildKeyPair(iParentHDKeyStorage, iChildNumber);
    iChildNumber++;

    GpCryptoKeyFactory_Ed25519_Import factory(keyStorageHD.KeyData());

    return factory.Generate();
}

void    GpCryptoKeyFactory_Ed25519_HD::Serialize (GpByteWriter& aWriter) const
{
    //iParentHDKeyStorage
    {
        //SchemeType
        aWriter.BytesWithLen(GpCryptoHDSchemeType::SToString(iParentHDKeyStorage.SchemeType()));

        //ChainCode
        aWriter.BytesWithLen(iParentHDKeyStorage.ChainCode().ViewR().R());

        //KeyData
        aWriter.BytesWithLen(iParentHDKeyStorage.KeyData().ViewR().R());
    }

    //iChildNumber
    aWriter.CompactUInt32(iChildNumber.As<s_int_32>());
}

void    GpCryptoKeyFactory_Ed25519_HD::Deserialize (GpByteReader& aReader)
{
    //iParentHDKeyStorage
    {
        //SchemeType
        THROW_GPE_COND
        (
            aReader.BytesWithLen() == GpCryptoHDSchemeType::SToString(iParentHDKeyStorage.SchemeType()),
            "Wrong SchemeType"_sv
        );

        //ChainCode
        iParentHDKeyStorage.ChainCode().ViewRW().RW().CopyFrom(aReader.BytesWithLen());

        //KeyData
        iParentHDKeyStorage.KeyData().ViewRW().RW().CopyFrom(aReader.BytesWithLen());
    }

    //iChildNumber
    iChildNumber = count_t::SMake(aReader.CompactSInt32());
}
*/
}//GPlatform
