#pragma once

#include "../GpCryptoKeyPair.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoKeyPair_Ed25519 final : public GpCryptoKeyPair
{
public:
    CLASS_DECLARE_DEFAULTS(GpCryptoKeyPair_Ed25519)

    using ResSignT = GpArray<std::byte, 64>;

public:
                                GpCryptoKeyPair_Ed25519     (void) noexcept;
                                GpCryptoKeyPair_Ed25519     (const GpCryptoKeyPair_Ed25519& aKeyPair);
                                GpCryptoKeyPair_Ed25519     (GpCryptoKeyPair_Ed25519&& aKeyPair);
                                GpCryptoKeyPair_Ed25519     (GpSecureStorage&&  aPrivateBytes,
                                                             GpBytesArray&&     aPublicBytes);
    virtual                     ~GpCryptoKeyPair_Ed25519    (void) noexcept override final;

    GpCryptoKeyPair_Ed25519&    operator=                   (const GpCryptoKeyPair_Ed25519& aKeyPair);
    GpCryptoKeyPair_Ed25519&    operator=                   (GpCryptoKeyPair_Ed25519&& aKeyPair);

    ResSignT                    Sign                        (GpRawPtrByteR  aData) const;
    bool                        VerifySign                  (GpRawPtrByteR  aData,
                                                             GpRawPtrByteR  aSign) const;
    static bool                 SVerifySign                 (GpRawPtrByteR  aData,
                                                             GpRawPtrByteR  aSign,
                                                             GpRawPtrByteR  aPublicKey);

    virtual GpRawPtrByteR       PrivateBytesPrefix          (void) const noexcept override final;
    virtual GpRawPtrByteR       PublicBytesPrefix           (void) const noexcept override final;

    static GpRawPtrByteR        SPrivateBytesPrefix         (void) noexcept {return sPrivateBytesPrefix;}
    static GpRawPtrByteR        SPublicBytesPrefix          (void) noexcept {return sPublicBytesPrefix;}

private:
    static const std::string_view   sPrivateBytesPrefix;
    static const std::string_view   sPublicBytesPrefix;
};

}//namespace GPlatform
