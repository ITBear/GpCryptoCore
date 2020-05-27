#include "GpCryptoHash_Blake2b.hpp"
#include <libsodium/sodium.h>

namespace GPlatform {

void	GpCryptoHash_Blake2b::S_256 (const std::byte*	aData,
									 const count_t		aDataSize,
									 const std::byte*	aKey,
									 const count_t		aKeySize,
									 Res256T::pointer	aDataOut)
{
	THROW_GPE_COND_CHECK_M((aData != nullptr) && (aDataSize > 0_cnt), "Wrong data"_sv);

	THROW_GPE_COND_CHECK_M(((aKey != nullptr) && (aKeySize > 0_cnt)) ||
						   ((aKey == nullptr) && (aKeySize == 0_cnt)), "Wrong key"_sv);

	THROW_GPE_COND_CHECK_M(aDataOut != nullptr, "Wrong data out"_sv);

	crypto_generichash(reinterpret_cast<unsigned char*>(aDataOut),
					   std::tuple_size<Res256T>::value,
					   reinterpret_cast<const unsigned char*>(aData),
					   aDataSize.ValueAs<size_t>(),
					   reinterpret_cast<const unsigned char*>(aKey),
					   aKeySize.ValueAs<size_t>());
}

}//namespace GPlatform
