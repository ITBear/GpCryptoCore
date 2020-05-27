#pragma once

#include "../GpCryptoKeyPair.hpp"
#include "GpCryptoHDKeyType.hpp"
#include "GpCryptoHDNetworkType.hpp"
#include "GpCryptoHDSchemeType.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHDKeyStorage
{
public:
	CLASS_REMOVE_CTRS_EXCEPT_MOVE(GpCryptoHDKeyStorage);
	CLASS_DECLARE_DEFAULTS(GpCryptoHDKeyStorage);

	using KeyTypeT		= GpCryptoHDKeyType;
	using KeyTypeTE		= KeyTypeT::EnumT;

	using NetworkTypeT	= GpCryptoHDNetworkType;
	using NetworkTypeTE	= NetworkTypeT::EnumT;

	using SchemeTypeT	= GpCryptoHDSchemeType;
	using SchemeTypeTE	= SchemeTypeT::EnumT;

protected:
								GpCryptoHDKeyStorage	(KeyTypeTE aKeyType) noexcept;
								GpCryptoHDKeyStorage	(GpCryptoHDKeyStorage&& aKeyStorage) noexcept;

	GpCryptoHDKeyStorage&		operator=				(GpCryptoHDKeyStorage&& aKeyStorage) noexcept;

public:
	virtual						~GpCryptoHDKeyStorage	(void) noexcept;

	void						ConstructRoot			(const NetworkTypeTE	aNetworkType,
														 const SchemeTypeTE		aScheme,
														 const GpSecureStorage&	aChainCode,
														 const GpSecureStorage&	aKeyData);

	void						ConstructChild			(const NetworkTypeTE			aNetworkType,
														 const SchemeTypeTE				aScheme,
														 const count_t					aDepth,
														 const GpArray<std::byte, 4>	aFingerprint,
														 const count_t					aChildNumber,
														 const GpSecureStorage&			aChainCode,
														 const GpSecureStorage&			aKeyData);

	KeyTypeTE					KeyType					(void) const noexcept {return iKeyType;}
	NetworkTypeTE				NetworkType				(void) const noexcept {return iNetworkType;}
	SchemeTypeTE				SchemeType				(void) const noexcept {return iSchemeType;}
	count_t						Depth					(void) const noexcept {return iDepth;}
	GpArray<std::byte, 4>		Fingerprint				(void) const noexcept {return iFingerprint;}
	count_t						ChildNumber				(void) const noexcept {return iChildNumber;}
	const GpSecureStorage&		ChainCode				(void) const noexcept {return iChainCode;}
	const GpSecureStorage&		KeyData					(void) const noexcept {return iKeyData;}

private:
	KeyTypeTE					iKeyType;
	NetworkTypeTE				iNetworkType;
	SchemeTypeTE				iSchemeType;
	count_t						iDepth;
	GpArray<std::byte, 4>		iFingerprint;
	count_t						iChildNumber;
	GpSecureStorage				iChainCode;
	GpSecureStorage				iKeyData;
};

}//GPlatform
