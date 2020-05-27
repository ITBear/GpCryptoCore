#include "GpCryptoHDKeyStorage.hpp"

namespace GPlatform {

GpCryptoHDKeyStorage::GpCryptoHDKeyStorage (KeyTypeTE aKeyType) noexcept:
iKeyType(aKeyType)
{
}

GpCryptoHDKeyStorage::GpCryptoHDKeyStorage (GpCryptoHDKeyStorage&& aKeyStorage) noexcept:
iKeyType(std::move(aKeyStorage.iKeyType)),
iNetworkType(std::move(aKeyStorage.iNetworkType)),
iSchemeType(std::move(aKeyStorage.iSchemeType)),
iDepth(std::move(aKeyStorage.iDepth)),
iFingerprint(std::move(aKeyStorage.iFingerprint)),
iChildNumber(std::move(aKeyStorage.iChildNumber)),
iChainCode(std::move(aKeyStorage.iChainCode)),
iKeyData(std::move(aKeyStorage.iKeyData))
{
}

GpCryptoHDKeyStorage&	GpCryptoHDKeyStorage::operator= (GpCryptoHDKeyStorage&& aKeyStorage) noexcept
{
	iKeyType		= std::move(aKeyStorage.iKeyType);
	iNetworkType	= std::move(aKeyStorage.iNetworkType);
	iSchemeType		= std::move(aKeyStorage.iSchemeType);
	iDepth			= std::move(aKeyStorage.iDepth);
	iFingerprint	= std::move(aKeyStorage.iFingerprint);
	iChildNumber	= std::move(aKeyStorage.iChildNumber);
	iChainCode		= std::move(aKeyStorage.iChainCode);
	iKeyData		= std::move(aKeyStorage.iKeyData);

	return *this;
}

GpCryptoHDKeyStorage::~GpCryptoHDKeyStorage	(void) noexcept
{
}

void	GpCryptoHDKeyStorage::ConstructRoot (const NetworkTypeTE	aNetworkType,
											 const SchemeTypeTE		aScheme,
											 const GpSecureStorage&	aChainCode,
											 const GpSecureStorage&	aKeyData)
{
	iNetworkType	= aNetworkType;
	iSchemeType		= aScheme;
	iDepth			= 0_cnt;
	std::memset(iFingerprint.data(), 0, iFingerprint.size());
	iChildNumber	= 0_cnt;
	iChainCode.Set(aChainCode.ViewR().AsStringView());
	iKeyData.Set(aKeyData.ViewR().AsStringView());
}

void	GpCryptoHDKeyStorage::ConstructChild (const NetworkTypeTE			aNetworkType,
											  const SchemeTypeTE			aScheme,
											  const count_t					aDepth,
											  const GpArray<std::byte, 4>	aFingerprint,
											  const count_t					aChildNumber,
											  const GpSecureStorage&		aChainCode,
											  const GpSecureStorage&		aKeyData)
{
	iNetworkType	= aNetworkType;
	iSchemeType		= aScheme;
	iDepth			= aDepth;
	iFingerprint	= aFingerprint;
	iChildNumber	= aChildNumber;
	iChainCode.Set(aChainCode.ViewR().AsStringView());
	iKeyData.Set(aKeyData.ViewR().AsStringView());
}

}//GPlatform
