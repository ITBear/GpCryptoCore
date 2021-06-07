#include "GpCryptoKeyFactory_Ed25519_Import.hpp"
#include "GpCryptoKeyPair_Ed25519.hpp"

GP_WARNING_PUSH()
GP_WARNING_DISABLE(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

GpCryptoKeyFactory_Ed25519_Import::GpCryptoKeyFactory_Ed25519_Import (GpSecureStorage::CSP aSeed) noexcept:
iSeed(std::move(aSeed))
{
}

GpCryptoKeyFactory_Ed25519_Import::~GpCryptoKeyFactory_Ed25519_Import (void) noexcept
{
}

GpCryptoKeyPair::CSP    GpCryptoKeyFactory_Ed25519_Import::Generate (void)
{
    THROW_GPE_COND
    (
        iSeed.VC().Size() == size_byte_t::SMake(crypto_sign_ed25519_SEEDBYTES),
        "Wrong seed size"_sv
    );

    GpSecureStorage::SP privateBytes = MakeSP<GpSecureStorage>();
    GpBytesArray        publicBytes;

    privateBytes->Resize(size_byte_t::SMake(crypto_sign_ed25519_SECRETKEYBYTES));
    publicBytes.resize(size_t(crypto_sign_ed25519_PUBLICKEYBYTES));

    GpRawPtrByteRW publicBytesPtr = GpRawPtrByteRW(publicBytes);

    if (crypto_sign_ed25519_seed_keypair(publicBytesPtr.PtrAs<unsigned char*>(),
                                         privateBytes->ViewRW().RW().PtrAs<unsigned char*>(),
                                         iSeed.VC().ViewR().R().PtrAs<const unsigned char*>()) != 0)
    {
        THROW_GPE("crypto_sign_ed25519_keypair return error"_sv);
    }

    return MakeCSP<GpCryptoKeyPair_Ed25519>(privateBytes, std::move(publicBytes));
}

/*void  GpCryptoKeyFactory_Ed25519_Import::Serialize (GpByteWriter& aWriter) const
{
    aWriter.BytesWithLen("GpCryptoKeyFactory_Ed25519_Import"_sv);
}

void    GpCryptoKeyFactory_Ed25519_Import::Deserialize (GpByteReader& aReader)
{
    THROW_GPE_COND
    (
        aReader.BytesWithLen() == "GpCryptoKeyFactory_Ed25519_Import"_sv,
        "Wrong data"_sv
    );
}*/

}//GPlatform
