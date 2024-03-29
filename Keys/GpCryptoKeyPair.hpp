#pragma once

#include "GpCryptoKeyType.hpp"
#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoKeyPair
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoKeyPair);
    CLASS_DECLARE_DEFAULTS(GpCryptoKeyPair)

    using TypeT     = GpCryptoKeyType;
    using TypeTE    = TypeT::EnumT;

protected:
                                GpCryptoKeyPair     (const TypeTE           aType,
                                                     GpSecureStorage::CSP   aPrivateKey,
                                                     GpBytesArray&&         aPublicKey) noexcept;

public:
    virtual                     ~GpCryptoKeyPair    (void) noexcept;

    void                        Clear               (void) noexcept;

    TypeTE                      Type                (void) const noexcept {return iType;}

    const GpSecureStorage::CSP  PrivateKey          (void) const {return iPrivateKey;}
    const GpRawPtrByteR         PublicKey           (void) const noexcept {return GpRawPtrByteR(iPublicKey);}

    virtual GpRawPtrByteR       PrivateKeyPrefix    (void) const noexcept = 0;
    virtual GpRawPtrByteR       PublicKeyPrefix     (void) const noexcept = 0;

    virtual GpBytesArray        Sign                (GpRawPtrByteR  aData) const = 0;
    virtual bool                VerifySign          (GpRawPtrByteR  aData,
                                                     GpRawPtrByteR  aSign) const = 0;
protected:
    const TypeTE                iType;
    GpSecureStorage::CSP        iPrivateKey;
    GpBytesArray                iPublicKey;
};

}//namespace GPlatform
