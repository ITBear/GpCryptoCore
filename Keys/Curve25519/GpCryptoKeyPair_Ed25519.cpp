#include "GpCryptoKeyPair_Ed25519.hpp"

GP_WARNING_PUSH()
GP_WARNING_DISABLE(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

const std::string_view  GpCryptoKeyPair_Ed25519::sPrivateBytesPrefix    = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20"_sv;
const std::string_view  GpCryptoKeyPair_Ed25519::sPublicBytesPrefix     = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"_sv;

GpCryptoKeyPair_Ed25519::GpCryptoKeyPair_Ed25519 (void) noexcept:
GpCryptoKeyPair(GpCryptoKeyType::ED_25519)
{
}

GpCryptoKeyPair_Ed25519::GpCryptoKeyPair_Ed25519 (const GpCryptoKeyPair_Ed25519& aKeyPair):
GpCryptoKeyPair(aKeyPair)
{
}

GpCryptoKeyPair_Ed25519::GpCryptoKeyPair_Ed25519 (GpCryptoKeyPair_Ed25519&& aKeyPair):
GpCryptoKeyPair(std::move(aKeyPair))
{
}

GpCryptoKeyPair_Ed25519::GpCryptoKeyPair_Ed25519 (GpSecureStorage&& aPrivateBytes,
                                                  GpBytesArray&&    aPublicBytes):
GpCryptoKeyPair(GpCryptoKeyType::ED_25519,
                std::move(aPrivateBytes),
                std::move(aPublicBytes))
{
}

GpCryptoKeyPair_Ed25519::~GpCryptoKeyPair_Ed25519 (void) noexcept
{
}

GpCryptoKeyPair_Ed25519&    GpCryptoKeyPair_Ed25519::operator= (const GpCryptoKeyPair_Ed25519& aKeyPair)
{
    SetKeys(aKeyPair.iPrivateBytes.ViewR().R(),
            aKeyPair.iPublicBytes);

    return *this;
}

GpCryptoKeyPair_Ed25519&    GpCryptoKeyPair_Ed25519::operator= (GpCryptoKeyPair_Ed25519&& aKeyPair)
{
    SetKeys(std::move(aKeyPair.iPrivateBytes),
            std::move(aKeyPair.iPublicBytes));

    return *this;
}

GpCryptoKeyPair_Ed25519::ResSignT   GpCryptoKeyPair_Ed25519::Sign (GpRawPtrByteR aData) const
{
    static_assert(std::tuple_size<ResSignT>::value == crypto_sign_ed25519_BYTES);

    ResSignT res;

    if (crypto_sign_ed25519_detached(reinterpret_cast<unsigned char*>(res.data()),
                                     nullptr,
                                     aData.PtrAs<const unsigned char*>(),
                                     aData.SizeLeft().As<size_t>(),
                                     iPrivateBytes.ViewR().R().PtrAs<const unsigned char*>()) != 0)
    {
        THROW_GPE("crypto_sign_ed25519_detached return error"_sv);
    }

    return res;
}

bool    GpCryptoKeyPair_Ed25519::VerifySign (GpRawPtrByteR  aData,
                                             GpRawPtrByteR  aSign) const
{
    return SVerifySign(aData, aSign, PublicBytes());
}

bool    GpCryptoKeyPair_Ed25519::SVerifySign (GpRawPtrByteR aData,
                                              GpRawPtrByteR aSign,
                                              GpRawPtrByteR aPublicKey)
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

GpRawPtrByteR   GpCryptoKeyPair_Ed25519::PrivateBytesPrefix (void) const noexcept
{
    return sPrivateBytesPrefix;
}

GpRawPtrByteR   GpCryptoKeyPair_Ed25519::PublicBytesPrefix (void) const noexcept
{
    return sPublicBytesPrefix;
}

}//namespace GPlatform
