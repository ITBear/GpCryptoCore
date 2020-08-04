#pragma once

#include "../GpCryptoKeyPair.hpp"

namespace GPlatform {

/*class GPCRYPTOCORE_API GpCryptoKeyPair_X25519 final : public GpCryptoKeyPair
{
public:
    CLASS_DECLARE_DEFAULTS(GpCryptoKeyPair_X25519)

    using ResSignT = GpArray<std::byte, 64>;

public:
                                GpCryptoKeyPair_X25519      (void) noexcept;
                                GpCryptoKeyPair_X25519      (const GpCryptoKeyPair_X25519& aKeyPair);
                                GpCryptoKeyPair_X25519      (GpCryptoKeyPair_X25519&& aKeyPair);
                                GpCryptoKeyPair_X25519      (GpSecureStorage&&  aPrivateBytes,
                                                             GpBytesArray&&     aPublicBytes);
    virtual                     ~GpCryptoKeyPair_X25519     (void) noexcept override final;

    virtual GpRawPtrByteR       PrivateBytesPrefix          (void) const noexcept override final;
    virtual GpRawPtrByteR       PublicBytesPrefix           (void) const noexcept override final;

    //static GpRawPtrByteR      SPrivateBytesPrefix         (void) noexcept {return sPrivateBytesPrefix;}
    //static GpRawPtrByteR      SPublicBytesPrefix          (void) noexcept {return sPublicBytesPrefix;}

private:
    //static const std::string_view sPrivateBytesPrefix;
    //static const std::string_view sPublicBytesPrefix;
};*/

}//namespace GPlatform
