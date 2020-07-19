#include "GpCryptoKeyFactory_Ed25519_Rnd.hpp"
#include "GpCryptoKeyPair_Ed25519.hpp"

#include <libsodium/sodium.h>

namespace GPlatform {

GpCryptoKeyFactory_Ed25519_Rnd::GpCryptoKeyFactory_Ed25519_Rnd (void) noexcept
{
}

GpCryptoKeyFactory_Ed25519_Rnd::~GpCryptoKeyFactory_Ed25519_Rnd (void) noexcept
{
}

GpCryptoKeyPair::SP GpCryptoKeyFactory_Ed25519_Rnd::Generate (void)
{
    GpSecureStorage privateBytes;
    GpBytesArray    publicBytes;

    {
        privateBytes.Allocate(size_byte_t::SMake(crypto_sign_ed25519_SECRETKEYBYTES));
        publicBytes.resize(size_t(crypto_sign_PUBLICKEYBYTES));

        GpSecureStorageViewRW   privateBytesView    = privateBytes.ViewRW();
        GpRawPtrByteRW          privateBytesPtr     = privateBytesView.RW();
        GpRawPtrByteRW          publicBytesPtr      = GpRawPtrByteRW(publicBytes);

        if (crypto_sign_ed25519_keypair(publicBytesPtr.PtrAs<unsigned char*>(),
                                        privateBytesPtr.PtrAs<unsigned char*>()) != 0)
        {
            THROW_GPE("crypto_sign_ed25519_keypair return error"_sv);
        }
    }

    return GpCryptoKeyPair_Ed25519::SP::SNew(std::move(privateBytes), std::move(publicBytes));
}

}//GPlatform
