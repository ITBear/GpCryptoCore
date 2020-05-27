#pragma once

#include "../GpCryptoCore_global.hpp"

namespace GPlatform {

void ripemd160 (const std::byte*	aData,
				const count_t		aLength,
				std::byte*			aOut/*size must be 20 bytes*/);

}//GPlatform
