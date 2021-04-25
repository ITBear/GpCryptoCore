#pragma once

#include "../Keys/GpCryptoKeys.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API Address
{
public:
    CLASS_REMOVE_CTRS(Address);
    CLASS_DECLARE_DEFAULTS(Address)

protected:
                            Address         (std::string&&          aName,
                                             GpCryptoKeyPair::CSP   aKeyPair) noexcept;

public:
    virtual                 ~Address        (void) noexcept;

    const GpCryptoKeyPair&  KeyPair         (void) const noexcept {return iKeyPair.VC();}
    std::string_view        Name            (void) const noexcept {return iName;}

    GpBytesArray            SignData        (GpRawPtrByteR aData) const;
    bool                    VerifySign      (GpRawPtrByteR  aData,
                                             GpRawPtrByteR  aSign) const;

private:
    std::string             iName;
    GpCryptoKeyPair::CSP    iKeyPair;
};

}//namespace GPlatform
