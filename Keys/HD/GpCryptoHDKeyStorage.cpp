#include "GpCryptoHDKeyStorage.hpp"

namespace GPlatform {

GpCryptoHDKeyStorage::GpCryptoHDKeyStorage
(
    const SchemeTypeTE      aSchemeType,
    GpSecureStorage::CSP    aChainCode,
    GpSecureStorage::CSP    aKeyData
) noexcept:
iSchemeType(aSchemeType),
iChainCode(std::move(aChainCode)),
iKeyData(std::move(aKeyData))
{
}

GpCryptoHDKeyStorage::~GpCryptoHDKeyStorage (void) noexcept
{
}

}//GPlatform
