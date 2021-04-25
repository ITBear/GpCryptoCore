#include "GpCryptoHDKeyGen.hpp"
#include "../Curve25519/GpCryptoHDKeyGen_Ed25519.hpp"

namespace GPlatform {

GpCryptoHDKeyStorage::SP    GpCryptoHDKeyGen::SMasterKeyPairFromSeed
(
    GpRawPtrByteR       aSeed,
    const SchemeTypeTE  aSchemeType
)
{
    switch (aSchemeType)
    {
        case SchemeTypeTE::SLIP10_ED25519:
        {
            return GpCryptoHDKeyGen_Ed25519::SMasterKeyPairFromSeed(aSeed);
        } break;
        default:
        {
            THROW_GPE("Unknown HD scheme type "_sv + SchemeTypeT::SToString(aSchemeType));
        }
    }
}

GpCryptoHDKeyStorage::SP    GpCryptoHDKeyGen::SChildKeyPair
(
    const GpCryptoHDKeyStorage& aParentHDKeyStorage,
    const count_t               aChildId
)
{
    switch (aParentHDKeyStorage.SchemeType())
    {
        case SchemeTypeTE::SLIP10_ED25519:
        {
            return GpCryptoHDKeyGen_Ed25519::SChildKeyPair(aParentHDKeyStorage, aChildId);
        } break;
        default:
        {
            THROW_GPE("Unknown HD scheme type "_sv + SchemeTypeT::SToString(aParentHDKeyStorage.SchemeType()));
        }
    }
}

}//GPlatform
