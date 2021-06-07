#pragma once

#include "../Keys/GpCryptoKeys.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoAddress
{
public:
    CLASS_REMOVE_CTRS(GpCryptoAddress);
    CLASS_DECLARE_DEFAULTS(GpCryptoAddress)

public:
                            GpCryptoAddress     (const GpUUID&          aUID,
                                                 GpCryptoKeyPair::CSP   aKeyPair) noexcept;

    virtual                 ~GpCryptoAddress    (void) noexcept;

    const GpUUID&           UID                 (void) const noexcept {return iUID;}
    const GpCryptoKeyPair&  KeyPair             (void) const noexcept {return iKeyPair.VC();}
    std::string_view        Name                (void) const noexcept {return iName;}
    void                    SetName             (std::string_view aName)  {iName = aName;}
    std::string_view        AddrStr             (void) const noexcept {return iAddrStr;}

    GpBytesArray            SignData            (GpRawPtrByteR aData) const;
    bool                    VerifySign          (GpRawPtrByteR  aData,
                                                 GpRawPtrByteR  aSign) const;

    void                    RecalcAddrStr       (void);

protected:
    virtual std::string     OnRecalcAddrStr     (void) const = 0;

private:
    const GpUUID            iUID;
    GpCryptoKeyPair::CSP    iKeyPair;
    std::string             iName;
    std::string             iAddrStr;
};

}//namespace GPlatform
