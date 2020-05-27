#pragma once

#include "GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoRandom
{
	CLASS_REMOVE_CTRS(GpCryptoRandom);

public:
	static GpSecureStorage		SEntropy	(const count_t aSize);
};

}//namespace GPlatform
