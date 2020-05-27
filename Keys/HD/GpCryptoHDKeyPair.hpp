#pragma once

#include "GpCryptoHDKeyPrivate.hpp"
#include "GpCryptoHDKeyPublic.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHDKeyPair
{
public:
	CLASS_REMOVE_CTRS_EXCEPT_DEFAULT_MOVE(GpCryptoHDKeyPair);
	CLASS_DECLARE_DEFAULTS(GpCryptoHDKeyPair);

	using KeyTypeT		= GpCryptoHDKeyType;
	using KeyTypeTE		= KeyTypeT::EnumT;

	using NetworkTypeT	= GpCryptoHDNetworkType;
	using NetworkTypeTE	= NetworkTypeT::EnumT;

	using SchemeTypeT	= GpCryptoHDSchemeType;
	using SchemeTypeTE	= SchemeTypeT::EnumT;

public:
									GpCryptoHDKeyPair	(void) noexcept;
									GpCryptoHDKeyPair	(GpCryptoHDKeyPair&& aKeyPair) noexcept;
									~GpCryptoHDKeyPair	(void) noexcept;

	GpCryptoHDKeyPair&				operator=			(GpCryptoHDKeyPair&& aKeyPair) noexcept;

	void							ConstructRoot		(const NetworkTypeTE	aNetworkType,
														 const SchemeTypeTE		aScheme,
														 const GpSecureStorage&	aChainCode,
														 const GpSecureStorage&	aPrivateKeyData,
														 std::string_view		aPublicKeyData,
														 const count_t			aUID,
														 std::string_view		aPath);

	void							ConstructChild		(const NetworkTypeTE			aNetworkType,
														 const SchemeTypeTE				aScheme,
														 const count_t					aDepth,
														 const GpArray<std::byte, 4>	aFingerprint,
														 const count_t					aChildNumber,
														 const GpSecureStorage&			aChainCode,
														 const GpSecureStorage&			aPrivateKeyData,
														 std::string_view				aPublicKeyData,
														 const count_t					aUID,
														 std::string_view				aPath);


	const GpCryptoHDKeyPrivate&		Private				(void) const noexcept {return iPrivate;}
	const GpCryptoHDKeyPublic&		Public				(void) const noexcept {return iPublic;}
	count_t							UID					(void) const noexcept {return iUID;}
	std::string_view				Path				(void) const noexcept {return iPath;}

private:
	GpCryptoHDKeyPrivate			iPrivate;
	GpCryptoHDKeyPublic				iPublic;
	count_t							iUID;
	std::string						iPath;
};

}//GPlatform
