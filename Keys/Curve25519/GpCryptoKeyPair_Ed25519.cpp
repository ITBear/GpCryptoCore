#include "GpCryptoKeyPair_Ed25519.hpp"

GP_WARNING_PUSH()
GP_WARNING_DISABLE(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

const std::string_view  GpCryptoKeyPair_Ed25519::sPrivateKeyPrefix  = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20"_sv;
const std::string_view  GpCryptoKeyPair_Ed25519::sPublicKeyPrefix   = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"_sv;

GpCryptoKeyPair_Ed25519::GpCryptoKeyPair_Ed25519
(
    GpSecureStorage::SP aPrivateKey,
    GpBytesArray&&      aPublicKey
) noexcept:
GpCryptoKeyPair
(
    GpCryptoKeyType::ED_25519,
    std::move(aPrivateKey),
    std::move(aPublicKey)
)
{
}

GpCryptoKeyPair_Ed25519::~GpCryptoKeyPair_Ed25519 (void) noexcept
{
}

GpBytesArray    GpCryptoKeyPair_Ed25519::Sign (GpRawPtrByteR aData) const
{
    return SSign(aData, PrivateKey());
}

bool    GpCryptoKeyPair_Ed25519::VerifySign (GpRawPtrByteR  aData,
                                             GpRawPtrByteR  aSign) const
{
    return SVerifySign(aData, aSign, PublicKey());
}

GpBytesArray    GpCryptoKeyPair_Ed25519::SSign
(
    GpRawPtrByteR           aData,
    const GpSecureStorage&  aPrivateKey
)
{
    THROW_GPE_COND
    (
        aData.SizeLeft() > 0_byte,
        "Data is empty"_sv
    );

    GpSecureStorageViewR    privateKeyViewR = aPrivateKey.ViewR();
    GpRawPtrByteR           privateKey      = privateKeyViewR.R();

    THROW_GPE_COND
    (
        privateKey.SizeLeft() == size_byte_t::SMake(crypto_sign_ed25519_BYTES),
        "Wrong private key size"_sv
    );

    GpBytesArray sign;
    sign.resize(size_t(crypto_sign_ed25519_BYTES));

    THROW_GPE_COND
    (
        crypto_sign_ed25519_detached
        (
            reinterpret_cast<unsigned char*>(sign.data()),
            nullptr,
            aData.PtrAs<const unsigned char*>(),
            aData.SizeLeft().As<size_t>(),
            privateKey.PtrAs<const unsigned char*>()
        ) == 0,
        "crypto_sign_ed25519_detached return error"_sv
    );

    return sign;
}

bool    GpCryptoKeyPair_Ed25519::SVerifySign
(
    GpRawPtrByteR   aData,
    GpRawPtrByteR   aSign,
    GpRawPtrByteR   aPublicKey
)
{
    THROW_GPE_COND
    (
        aSign.CountLeft() >= count_t::SMake(crypto_sign_ed25519_BYTES),
        "aSign size too small"_sv
    );

    THROW_GPE_COND
    (
        aPublicKey.CountLeft() >= count_t::SMake(crypto_sign_ed25519_PUBLICKEYBYTES),
        "aPublicKey size too small"_sv
    );

    if (crypto_sign_ed25519_verify_detached(aSign.PtrAs<const unsigned char*>(),
                                            aData.PtrAs<const unsigned char*>(),
                                            aData.SizeLeft().As<size_t>(),
                                            aPublicKey.PtrAs<const unsigned char*>()) == 0)
    {
        return true;
    } else
    {
        return false;
    }
}

GpRawPtrByteR   GpCryptoKeyPair_Ed25519::PrivateKeyPrefix (void) const noexcept
{
    return sPrivateKeyPrefix;
}

GpRawPtrByteR   GpCryptoKeyPair_Ed25519::PublicKeyPrefix (void) const noexcept
{
    return sPublicKeyPrefix;
}

}//namespace GPlatform
