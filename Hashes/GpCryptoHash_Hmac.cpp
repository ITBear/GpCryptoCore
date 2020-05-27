#include "GpCryptoHash_Hmac.hpp"

#include <libsodium/sodium.h>

namespace GPlatform {

void	GpCryptoHash_Hmac::S_256 (const std::byte*	aData,
								  const count_t		aDataSize,
								  const std::byte*	aKey,
								  const count_t		aKeySize,
								  Res256T::pointer	aDataOut)
{
	THROW_GPE_COND_CHECK_M((aData != nullptr) && (aDataSize > 0_cnt), "Wrong data"_sv);
	THROW_GPE_COND_CHECK_M((aKey != nullptr) && (aKeySize > 0_cnt), "Wrong key"_sv);
	THROW_GPE_COND_CHECK_M(aDataOut != nullptr, "Wrong data out"_sv);

	crypto_auth_hmacsha256_state hctx;

	crypto_auth_hmacsha256_init(&hctx,
								reinterpret_cast<const unsigned char*>(aKey),
								aKeySize.ValueAs<size_t>());
	crypto_auth_hmacsha256_update(&hctx,
								  reinterpret_cast<const unsigned char*>(aData),
								  aDataSize.ValueAs<size_t>());
	crypto_auth_hmacsha256_final(&hctx,
								 reinterpret_cast<unsigned char*>(aDataOut));

	sodium_memzero(&hctx, sizeof(hctx));
}

void	GpCryptoHash_Hmac::S_512 (const std::byte*	aData,
								  const count_t		aDataSize,
								  const std::byte*	aKey,
								  const count_t		aKeySize,
								  Res512T::pointer	aDataOut)
{
	THROW_GPE_COND_CHECK_M((aData != nullptr) && (aDataSize > 0_cnt), "Wrong data"_sv);
	THROW_GPE_COND_CHECK_M((aKey != nullptr) && (aKeySize > 0_cnt), "Wrong key"_sv);
	THROW_GPE_COND_CHECK_M(aDataOut != nullptr, "Wrong data out"_sv);

	crypto_auth_hmacsha512_state hctx;

	crypto_auth_hmacsha512_init(&hctx,
								reinterpret_cast<const unsigned char*>(aKey),
								aKeySize.ValueAs<size_t>());
	crypto_auth_hmacsha512_update(&hctx,
								  reinterpret_cast<const unsigned char*>(aData),
								  aDataSize.ValueAs<size_t>());
	crypto_auth_hmacsha512_final(&hctx,
								 reinterpret_cast<unsigned char*>(aDataOut));

	sodium_memzero(&hctx, sizeof(hctx));
}

}//namespace GPlatform
