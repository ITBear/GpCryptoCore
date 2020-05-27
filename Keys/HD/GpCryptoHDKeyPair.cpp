#include "GpCryptoHDKeyPair.hpp"

namespace GPlatform {

GpCryptoHDKeyPair::GpCryptoHDKeyPair (void) noexcept
{
}

GpCryptoHDKeyPair::GpCryptoHDKeyPair (GpCryptoHDKeyPair&& aKeyPair) noexcept:
iPrivate(std::move(aKeyPair.iPrivate)),
iPublic(std::move(aKeyPair.iPublic)),
iUID(std::move(aKeyPair.iUID)),
iPath(std::move(aKeyPair.iPath))
{
}

GpCryptoHDKeyPair::~GpCryptoHDKeyPair (void) noexcept
{
}

GpCryptoHDKeyPair&	GpCryptoHDKeyPair::operator= (GpCryptoHDKeyPair&& aKeyPair) noexcept
{
	iPrivate	= std::move(aKeyPair.iPrivate);
	iPublic		= std::move(aKeyPair.iPublic);
	iUID		= std::move(aKeyPair.iUID);
	iPath		= std::move(aKeyPair.iPath);
}

void	GpCryptoHDKeyPair::ConstructRoot (const NetworkTypeTE		aNetworkType,
										  const SchemeTypeTE		aScheme,
										  const GpSecureStorage&	aChainCode,
										  const GpSecureStorage&	aPrivateKeyData,
										  std::string_view			aPublicKeyData,
										  const count_t				aUID,
										  std::string_view			aPath)
{
	iPrivate.ConstructRoot(aNetworkType,
						   aScheme,
						   aChainCode,
						   aPrivateKeyData);

	GpSecureStorage publicData;
	publicData.Set(aPublicKeyData);

	iPublic.ConstructRoot(aNetworkType,
						  aScheme,
						  aChainCode,
						  publicData);

	iUID	= aUID;
	iPath	= aPath;
}

void	GpCryptoHDKeyPair::ConstructChild (const NetworkTypeTE			aNetworkType,
										   const SchemeTypeTE			aScheme,
										   const count_t				aDepth,
										   const GpArray<std::byte, 4>	aFingerprint,
										   const count_t				aChildNumber,
										   const GpSecureStorage&		aChainCode,
										   const GpSecureStorage&		aPrivateKeyData,
										   std::string_view				aPublicKeyData,
										   const count_t				aUID,
										   std::string_view				aPath)
{
	iPrivate.ConstructChild(aNetworkType,
							aScheme,
							aDepth,
							aFingerprint,
							aChildNumber,
							aChainCode,
							aPrivateKeyData);

	GpSecureStorage publicData;
	publicData.Set(aPublicKeyData);

	iPublic.ConstructChild(aNetworkType,
						   aScheme,
						   aDepth,
						   aFingerprint,
						   aChildNumber,
						   aChainCode,
						   publicData);

	iUID	= aUID;
	iPath	= aPath;
}

}//GPlatform
