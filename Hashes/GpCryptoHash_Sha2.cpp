#include "GpCryptoHash_Sha2.hpp"
#include <libsodium/sodium.h>

namespace GPlatform {

GpBytesArray	GpCryptoHash_Sha2::S_256 (const std::byte*	aData,
										  const count_t	aDataSize)
{
	THROW_GPE_COND_CHECK_M((aData != nullptr) && (aDataSize > 0_cnt), "Wrong data"_sv);

	GpBytesArray hash;
	hash.resize(size_t(crypto_hash_sha256_BYTES));

	crypto_hash_sha256(reinterpret_cast<unsigned char*>(hash.data()),
					   reinterpret_cast<const unsigned char*>(aData),
					   aDataSize.ValueAs<size_t>());

	return hash;
}

GpBytesArray	GpCryptoHash_Sha2::S_512 (const std::byte*	aData,
										  const count_t	aDataSize)
{
	THROW_GPE_COND_CHECK_M((aData != nullptr) && (aDataSize > 0_cnt), "Wrong data"_sv);

	GpBytesArray hash;
	hash.resize(size_t(crypto_hash_sha512_BYTES));

	crypto_hash_sha512(reinterpret_cast<unsigned char*>(hash.data()),
					   reinterpret_cast<const unsigned char*>(aData),
					   aDataSize.ValueAs<size_t>());

	return hash;
}

}//namespace GPlatform
