#pragma once

#include "GpCryptoHDKeyPair.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHDKeyGen
{
public:
	CLASS_REMOVE_CTRS(GpCryptoHDKeyGen);

	using KeyTypeT		= GpCryptoHDKeyType;
	using KeyTypeTE		= KeyTypeT::EnumT;

	using NetworkTypeT	= GpCryptoHDNetworkType;
	using NetworkTypeTE	= NetworkTypeT::EnumT;

	using SchemeTypeT	= GpCryptoHDSchemeType;
	using SchemeTypeTE	= SchemeTypeT::EnumT;

public:
	static GpCryptoHDKeyPair		SMasterKeyPairFromSeed (const GpSecureStorage&	aSeed,
															const NetworkTypeTE		aNetworkType,
															const SchemeTypeTE		aSchemeType,
															const count_t			aUID);

	static GpCryptoHDKeyPair		SChildKeyPair			(const GpCryptoHDKeyPair&	aParentHDKeyPair,
															 const count_t				aChildNumber,
															 const bool					aIsHardened,
															 std::string_view			aPath);
};

}//GPlatform
