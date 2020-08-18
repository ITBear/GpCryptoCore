#pragma once

#include "../GpCryptoKeyPair.hpp"
#include "GpCryptoHDSchemeType.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHDKeyStorage
{
public:
    CLASS_DECLARE_DEFAULTS(GpCryptoHDKeyStorage)

    using SchemeTypeT   = GpCryptoHDSchemeType;
    using SchemeTypeTE  = SchemeTypeT::EnumT;

public:
                                GpCryptoHDKeyStorage    (void) noexcept;
                                GpCryptoHDKeyStorage    (const SchemeTypeTE     aSchemeType,
                                                         const GpSecureStorage& aChainCode,
                                                         const GpSecureStorage& aKeyData);
                                GpCryptoHDKeyStorage    (const SchemeTypeTE aSchemeType,
                                                         GpSecureStorage&&  aChainCode,
                                                         GpSecureStorage&&  aKeyData);
                                GpCryptoHDKeyStorage    (const GpCryptoHDKeyStorage& aKeyStorage);
                                GpCryptoHDKeyStorage    (GpCryptoHDKeyStorage&& aKeyStorage);
                                ~GpCryptoHDKeyStorage   (void) noexcept;

    GpCryptoHDKeyStorage&       operator=               (const GpCryptoHDKeyStorage& aKeyStorage);
    GpCryptoHDKeyStorage&       operator=               (GpCryptoHDKeyStorage&& aKeyStorage);

    void                        Set                     (const GpCryptoHDKeyStorage& aKeyStorage);
    void                        Set                     (GpCryptoHDKeyStorage&& aKeyStorage);

    SchemeTypeTE                SchemeType              (void) const noexcept {return iSchemeType;}
    const GpSecureStorage&      ChainCode               (void) const noexcept {return iChainCode;}
    GpSecureStorage&            ChainCode               (void) noexcept {return iChainCode;}
    const GpSecureStorage&      KeyData                 (void) const noexcept {return iKeyData;}
    GpSecureStorage&            KeyData                 (void) noexcept {return iKeyData;}

private:
    SchemeTypeTE                iSchemeType;
    GpSecureStorage             iChainCode;
    GpSecureStorage             iKeyData;
};

}//GPlatform
