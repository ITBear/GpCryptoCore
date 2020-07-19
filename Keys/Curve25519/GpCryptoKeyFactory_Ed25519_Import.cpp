#include "GpCryptoKeyFactory_Ed25519_Import.hpp"
#include "GpCryptoKeyPair_Ed25519.hpp"

#include <libsodium/sodium.h>

namespace GPlatform {

GpCryptoKeyFactory_Ed25519_Import::GpCryptoKeyFactory_Ed25519_Import (const GpSecureStorage& aSeed):
iSeed(aSeed)
{
}

GpCryptoKeyFactory_Ed25519_Import::GpCryptoKeyFactory_Ed25519_Import (GpSecureStorage&& aSeed):
iSeed(std::move(aSeed))
{
}

GpCryptoKeyFactory_Ed25519_Import::GpCryptoKeyFactory_Ed25519_Import (GpRawPtrByteR aSeed):
iSeed(aSeed)
{
}

GpCryptoKeyFactory_Ed25519_Import::~GpCryptoKeyFactory_Ed25519_Import (void) noexcept
{
}

GpCryptoKeyPair::SP GpCryptoKeyFactory_Ed25519_Import::Generate (void)
{
    THROW_GPE_COND_CHECK_M(iSeed.Size() == size_byte_t::SMake(crypto_sign_ed25519_SEEDBYTES),
                           "Wrong seed size"_sv);

    GpSecureStorage privateBytes;
    GpBytesArray    publicBytes;

    privateBytes.Allocate(size_byte_t::SMake(crypto_sign_ed25519_SECRETKEYBYTES));
    publicBytes.resize(size_t(crypto_sign_ed25519_PUBLICKEYBYTES));

    GpRawPtrByteRW publicBytesPtr = GpRawPtrByteRW(publicBytes);

    if (crypto_sign_ed25519_seed_keypair(publicBytesPtr.PtrAs<unsigned char*>(),
                                         privateBytes.ViewRW().RW().PtrAs<unsigned char*>(),
                                         iSeed.ViewR().R().PtrAs<const unsigned char*>()) != 0)
    {
        THROW_GPE("crypto_sign_ed25519_keypair return error"_sv);
    }

    return GpCryptoKeyPair_Ed25519::SP::SNew(std::move(privateBytes), std::move(publicBytes));
}

}//GPlatform
