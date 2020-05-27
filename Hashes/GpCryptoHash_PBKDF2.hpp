#pragma once

#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHash_PBKDF2
{
	CLASS_REMOVE_CTRS(GpCryptoHash_PBKDF2);

public:
	static GpSecureStorage		S_HmacSHA512	(const GpSecureStorage&	aPassword,
												 const GpSecureStorage&	aSalt,
												 const count_t			aIterations,
												 const size_bit_t		aBitLengthDerivedKey);
	static GpSecureStorage		S_HmacSHA256	(const GpSecureStorage&	aPassword,
												 const GpSecureStorage&	aSalt,
												 const count_t			aIterations,
												 const size_bit_t		aBitLengthDerivedKey);
};

}//GPlatform
