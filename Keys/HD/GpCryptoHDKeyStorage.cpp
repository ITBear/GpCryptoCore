#include "GpCryptoHDKeyStorage.hpp"

namespace GPlatform {

GpCryptoHDKeyStorage::GpCryptoHDKeyStorage (void) noexcept
{
}

GpCryptoHDKeyStorage::GpCryptoHDKeyStorage (const SchemeTypeTE      aSchemeType,
                                            const GpSecureStorage&  aChainCode,
                                            const GpSecureStorage&  aKeyData):
iSchemeType(aSchemeType),
iChainCode(aChainCode),
iKeyData(aKeyData)
{
}

GpCryptoHDKeyStorage::GpCryptoHDKeyStorage (const SchemeTypeTE  aSchemeType,
                                            GpSecureStorage&&   aChainCode,
                                            GpSecureStorage&&   aKeyData):
iSchemeType(std::move(aSchemeType)),
iChainCode(std::move(aChainCode)),
iKeyData(std::move(aKeyData))
{
}

GpCryptoHDKeyStorage::GpCryptoHDKeyStorage (const GpCryptoHDKeyStorage& aKeyStorage)
{
    Set(aKeyStorage);
}

GpCryptoHDKeyStorage::GpCryptoHDKeyStorage (GpCryptoHDKeyStorage&& aKeyStorage)
{
    Set(std::move(aKeyStorage));
}

GpCryptoHDKeyStorage::~GpCryptoHDKeyStorage (void) noexcept
{
}

GpCryptoHDKeyStorage&   GpCryptoHDKeyStorage::operator= (const GpCryptoHDKeyStorage& aKeyStorage)
{
    Set(aKeyStorage);
    return *this;
}

GpCryptoHDKeyStorage&   GpCryptoHDKeyStorage::operator= (GpCryptoHDKeyStorage&& aKeyStorage)
{
    Set(std::move(aKeyStorage));
    return *this;
}

void    GpCryptoHDKeyStorage::Set (const GpCryptoHDKeyStorage& aKeyStorage)
{
    iSchemeType     = aKeyStorage.iSchemeType;
    iChainCode      = aKeyStorage.iChainCode;
    iKeyData        = aKeyStorage.iKeyData;
}

void    GpCryptoHDKeyStorage::Set (GpCryptoHDKeyStorage&& aKeyStorage)
{
    iSchemeType     = std::move(aKeyStorage.iSchemeType);
    iChainCode      = std::move(aKeyStorage.iChainCode);
    iKeyData        = std::move(aKeyStorage.iKeyData);
}

}//GPlatform
