#pragma once

#include "../GpCryptoKeyPair.hpp"
#include "GpCryptoHDSchemeType.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHDKeyStorage
{
public:
    CLASS_REMOVE_CTRS(GpCryptoHDKeyStorage);
    CLASS_DECLARE_DEFAULTS(GpCryptoHDKeyStorage)

    using SchemeTypeT   = GpCryptoHDSchemeType;
    using SchemeTypeTE  = SchemeTypeT::EnumT;

public:
                                GpCryptoHDKeyStorage    (const SchemeTypeTE     aSchemeType,
                                                         GpSecureStorage::CSP   aChainCode,
                                                         GpSecureStorage::CSP   aKeyData) noexcept;
                                ~GpCryptoHDKeyStorage   (void) noexcept;

    SchemeTypeTE                SchemeType              (void) const noexcept {return iSchemeType;}
    const GpSecureStorage&      ChainCode               (void) const noexcept {return iChainCode.VC();}
    const GpSecureStorage&      KeyData                 (void) const noexcept {return iKeyData.VC();}

private:
    const SchemeTypeTE          iSchemeType;
    GpSecureStorage::CSP        iChainCode;
    GpSecureStorage::CSP        iKeyData;
};

}//GPlatform
