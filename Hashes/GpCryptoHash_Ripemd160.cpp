#include "GpCryptoHash_Ripemd160.hpp"

#include "../ExtSources/ripemd160.hpp"

namespace GPlatform {

GpBytesArray	GpCryptoHash_Ripemd160::S_H (const std::byte*	aData,
											 const count_t		aDataSize)
{
	THROW_GPE_COND_CHECK_M((aData != nullptr) && (aDataSize > 0_cnt), "Wrong data"_sv);

	GpBytesArray hash;
	hash.resize(20);

	ripemd160(aData, aDataSize, hash.data());

	return hash;
}

}//namespace GPlatform
