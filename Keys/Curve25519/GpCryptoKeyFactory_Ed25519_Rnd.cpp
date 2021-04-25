#include "GpCryptoKeyFactory_Ed25519_Rnd.hpp"
#include "GpCryptoKeyPair_Ed25519.hpp"

GP_WARNING_PUSH()
GP_WARNING_DISABLE(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {
/*
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
        privateBytes.Resize(size_byte_t::SMake(crypto_sign_ed25519_SECRETKEYBYTES));
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

    return MakeSP<GpCryptoKeyPair_Ed25519>(std::move(privateBytes), std::move(publicBytes));
}

void    GpCryptoKeyFactory_Ed25519_Rnd::Serialize (GpByteWriter& aWriter) const
{
    aWriter.BytesWithLen("GpCryptoKeyFactory_Ed25519_Rnd"_sv);
}

void    GpCryptoKeyFactory_Ed25519_Rnd::Deserialize (GpByteReader& aReader)
{
    THROW_GPE_COND
    (
        aReader.BytesWithLen() == "GpCryptoKeyFactory_Ed25519_Rnd"_sv,
        "Wrong data"_sv
    );
}
*/
}//GPlatform
