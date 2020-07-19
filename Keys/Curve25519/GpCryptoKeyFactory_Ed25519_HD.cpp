#include "GpCryptoKeyFactory_Ed25519_HD.hpp"
#include "GpCryptoKeyPair_Ed25519.hpp"
#include "../HD/GpCryptoHDKeys.hpp"
#include "GpCryptoKeyFactory_Ed25519_Import.hpp"

#include <libsodium/sodium.h>

namespace GPlatform {

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
    THROW_GPE_COND_CHECK_M(iParentHDKeyStorage.SchemeType() == GpCryptoHDSchemeType::SLIP10_ED25519,
                           "HD scheme type must be SLIP10_ED25519"_sv);

    GpCryptoHDKeyStorage keyStorageHD = GpCryptoHDKeyGen::SChildKeyPair(iParentHDKeyStorage, iChildNumber);
    iChildNumber++;

    GpCryptoKeyFactory_Ed25519_Import factory(keyStorageHD.KeyData());

    return factory.Generate();
}

}//GPlatform
