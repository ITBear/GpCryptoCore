#pragma once

#include "GpCryptoKeyType.hpp"
#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoKeyPair
{
public:
    CLASS_DECLARE_DEFAULTS(GpCryptoKeyPair)

    using TypeT     = GpCryptoKeyType;
    using TypeTE    = TypeT::EnumT;

protected:
                                GpCryptoKeyPair             (const TypeTE aType) noexcept;
                                GpCryptoKeyPair             (const TypeTE       aType,
                                                             GpSecureStorage&&  aPrivateBytes,
                                                             GpBytesArray&&     aPublicBytes);
                                GpCryptoKeyPair             (const GpCryptoKeyPair& aKeyPair);
                                GpCryptoKeyPair             (GpCryptoKeyPair&& aKeyPair);

public:
    virtual                     ~GpCryptoKeyPair            (void) noexcept;

    void                        Clear                       (void) noexcept;

    TypeTE                      Type                        (void) const noexcept {return iType;}

    //const GpSecureStorage&        PrivateBytes                (void) const noexcept {return iPrivateBytes;}
    const GpRawPtrByteR         PublicBytes                 (void) const noexcept {return GpRawPtrByteR(iPublicBytes);}

    GpSecureStorage             ToPrivateBytesWithPrefix    (void) const;
    GpSecureStorage             ToPrivateStrHexWithPrefix   (void) const;

    GpBytesArray                ToPublicBytesWithPrefix     (void) const;
    GpBytesArray                ToPublicStrHexWithPrefix    (void) const;

    virtual GpRawPtrByteR       PrivateBytesPrefix          (void) const noexcept = 0;
    virtual GpRawPtrByteR       PublicBytesPrefix           (void) const noexcept = 0;

protected:
    const TypeTE                iType;
    GpSecureStorage             iPrivateBytes;
    GpBytesArray                iPublicBytes;
};

}//namespace GPlatform
