#pragma once

#include "../GpCryptoKeyPair.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoKeyPair_Ed25519 final : public GpCryptoKeyPair
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoKeyPair_Ed25519);
    CLASS_DECLARE_DEFAULTS(GpCryptoKeyPair_Ed25519)

public:
                                GpCryptoKeyPair_Ed25519     (GpSecureStorage::CSP   aPrivateKey,
                                                             GpBytesArray&&         aPublicKey) noexcept;
    virtual                     ~GpCryptoKeyPair_Ed25519    (void) noexcept override final;

    virtual GpBytesArray        Sign                        (GpRawPtrByteR  aData) const override final;
    virtual bool                VerifySign                  (GpRawPtrByteR  aData,
                                                             GpRawPtrByteR  aSign) const override final;

    static GpBytesArray         SSign                       (GpRawPtrByteR          aData,
                                                             const GpSecureStorage& aPrivateKey);

    static bool                 SVerifySign                 (GpRawPtrByteR  aData,
                                                             GpRawPtrByteR  aSign,
                                                             GpRawPtrByteR  aPublicKey);

    virtual GpRawPtrByteR       PrivateKeyPrefix            (void) const noexcept override final;
    virtual GpRawPtrByteR       PublicKeyPrefix             (void) const noexcept override final;

    static GpRawPtrByteR        SPrivateKeyPrefix           (void) noexcept {return sPrivateKeyPrefix;}
    static GpRawPtrByteR        SPublicKeyPrefix            (void) noexcept {return sPublicKeyPrefix;}

private:
    static const std::string_view   sPrivateKeyPrefix;
    static const std::string_view   sPublicKeyPrefix;
};

}//namespace GPlatform
