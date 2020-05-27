#include "GpCryptoHash_PBKDF2.hpp"
#include "GpCryptoHash_Sha2.hpp"
#include <libsodium/sodium.h>

namespace GPlatform {

GpSecureStorage	GpCryptoHash_PBKDF2::S_HmacSHA512 (const GpSecureStorage&	aPassword,
												   const GpSecureStorage&	aSalt,
												   const count_t			aIterations,
												   const size_bit_t			aBitLengthDerivedKey)
{
	THROW_GPE_COND_CHECK_M(!aPassword.IsEmpty(), "Wrong password"_sv);
	THROW_GPE_COND_CHECK_M(!aSalt.IsEmpty(), "Wrong salt"_sv);
	THROW_GPE_COND_CHECK_M(   (aBitLengthDerivedKey > 0_bit)
						   && (aBitLengthDerivedKey % 8_bit == 0_bit)
						   && (aBitLengthDerivedKey <= 0x1fffffffe0_bit), "Wrong aBitLengthDerivedKey"_sv);

	GpSecureStorageViewR	passwordView	= aPassword.ViewR();
	GpSecureStorageViewR	saltView		= aSalt.ViewR();

	const size_t	iterations			= aIterations.ValueAs<size_t>();
	const size_t	derivedKeySize		= size_byte_t(aBitLengthDerivedKey).ValueAs<size_t>();
	size_t			derivedKeyLeftBytes	= derivedKeySize;

	GpSecureStorage derivedKey;
	derivedKey.Allocate(count_t::SMake(derivedKeySize));
	GpSecureStorageViewRW derivedKeyView = derivedKey.ViewRW();
	std::byte* derivedKeyData = derivedKeyView.Data();

	GpSecureStorage buf_U_T;
	constexpr size_t sizeU	= size_t(crypto_auth_hmacsha512_BYTES);
	constexpr size_t sizeT	= size_t(crypto_auth_hmacsha512_BYTES);
	buf_U_T.Allocate(count_t::SMake(sizeU + sizeT));
	GpSecureStorageViewRW buf_U_T_KeyView = buf_U_T.ViewRW();

	std::byte* dataU	= buf_U_T_KeyView.Data() + 0;
	std::byte* dataT	= buf_U_T_KeyView.Data() + sizeU;

	crypto_auth_hmacsha512_state PShctx, hctx;

	crypto_auth_hmacsha512_init(&PShctx, reinterpret_cast<const unsigned char*>(passwordView.Data()), passwordView.Size().ValueAs<size_t>());
	crypto_auth_hmacsha512_update(&PShctx, reinterpret_cast<const unsigned char*>(saltView.Data()), saltView.Size().ValueAs<size_t>());

	size_t partsCount = derivedKeySize / sizeT;
	if ((derivedKeySize % sizeT) > 0)
	{
		partsCount++;
	}

	for (size_t partId = 0; partId < partsCount; partId++)
	{
		u_int_32 ivecVal = NumOps::SConvert<u_int_32>(partId + 1);
		ivecVal = BitOps::H2N(ivecVal);

		std::memcpy(&hctx, &PShctx, sizeof(crypto_auth_hmacsha512_state));
		crypto_auth_hmacsha512_update(&hctx, reinterpret_cast<const unsigned char*>(&ivecVal), sizeof(ivecVal));
		crypto_auth_hmacsha512_final(&hctx, reinterpret_cast<unsigned char*>(dataU));

		std::memcpy(dataT, dataU, sizeT);

		for (size_t j = 2; j <= iterations; j++)
		{
			crypto_auth_hmacsha512_init(&hctx, reinterpret_cast<const unsigned char*>(passwordView.Data()), passwordView.Size().ValueAs<size_t>());
			crypto_auth_hmacsha512_update(&hctx, reinterpret_cast<const unsigned char*>(dataU), sizeU);
			crypto_auth_hmacsha512_final(&hctx, reinterpret_cast<unsigned char*>(dataU));

			for (size_t k = 0; k < sizeT; k++)
			{
				dataT[k] ^= dataU[k];
			}
		}

		const size_t clen = std::min(derivedKeyLeftBytes, sizeT);
		std::memcpy(derivedKeyData, dataT, clen);
		derivedKeyLeftBytes -= clen;
		derivedKeyData		+= clen;
	}

	sodium_memzero(&PShctx, sizeof(PShctx));
	sodium_memzero(&hctx, sizeof(hctx));

	return derivedKey;
}

GpSecureStorage	GpCryptoHash_PBKDF2::S_HmacSHA256 (const GpSecureStorage&	aPassword,
												   const GpSecureStorage&	aSalt,
												   const count_t			aIterations,
												   const size_bit_t			aBitLengthDerivedKey)
{
	THROW_GPE_COND_CHECK_M(!aPassword.IsEmpty(), "Wrong password"_sv);
	THROW_GPE_COND_CHECK_M(!aSalt.IsEmpty(), "Wrong salt"_sv);
	THROW_GPE_COND_CHECK_M(   (aBitLengthDerivedKey > 0_bit)
						   && (aBitLengthDerivedKey % 8_bit == 0_bit)
						   && (aBitLengthDerivedKey <= 0x1fffffffe0_bit), "Wrong aBitLengthDerivedKey"_sv);

	GpSecureStorageViewR	passwordView	= aPassword.ViewR();
	GpSecureStorageViewR	saltView		= aSalt.ViewR();

	const size_t	iterations			= aIterations.ValueAs<size_t>();
	const size_t	derivedKeySize		= size_byte_t(aBitLengthDerivedKey).ValueAs<size_t>();
	size_t			derivedKeyLeftBytes	= derivedKeySize;

	GpSecureStorage derivedKey;
	derivedKey.Allocate(count_t::SMake(derivedKeySize));
	GpSecureStorageViewRW derivedKeyView = derivedKey.ViewRW();
	std::byte* derivedKeyData = derivedKeyView.Data();

	GpSecureStorage buf_U_T;
	constexpr size_t sizeU	= size_t(crypto_auth_hmacsha256_BYTES);
	constexpr size_t sizeT	= size_t(crypto_auth_hmacsha256_BYTES);
	buf_U_T.Allocate(count_t::SMake(sizeU + sizeT));
	GpSecureStorageViewRW buf_U_T_KeyView = buf_U_T.ViewRW();

	std::byte* dataU	= buf_U_T_KeyView.Data() + 0;
	std::byte* dataT	= buf_U_T_KeyView.Data() + sizeU;

	crypto_auth_hmacsha256_state PShctx, hctx;

	crypto_auth_hmacsha256_init(&PShctx, reinterpret_cast<const unsigned char*>(passwordView.Data()), passwordView.Size().ValueAs<size_t>());
	crypto_auth_hmacsha256_update(&PShctx, reinterpret_cast<const unsigned char*>(saltView.Data()), saltView.Size().ValueAs<size_t>());

	size_t partsCount = derivedKeySize / sizeT;
	if ((derivedKeySize % sizeT) > 0)
	{
		partsCount++;
	}

	for (size_t partId = 0; partId < partsCount; partId++)
	{
		u_int_32 ivecVal = NumOps::SConvert<u_int_32>(partId + 1);
		ivecVal = BitOps::H2N(ivecVal);

		std::memcpy(&hctx, &PShctx, sizeof(crypto_auth_hmacsha256_state));
		crypto_auth_hmacsha256_update(&hctx, reinterpret_cast<const unsigned char*>(&ivecVal), sizeof(ivecVal));
		crypto_auth_hmacsha256_final(&hctx, reinterpret_cast<unsigned char*>(dataU));

		std::memcpy(dataT, dataU, sizeT);

		for (size_t j = 2; j <= iterations; j++)
		{
			crypto_auth_hmacsha256_init(&hctx, reinterpret_cast<const unsigned char*>(passwordView.Data()), passwordView.Size().ValueAs<size_t>());
			crypto_auth_hmacsha256_update(&hctx, reinterpret_cast<const unsigned char*>(dataU), sizeU);
			crypto_auth_hmacsha256_final(&hctx, reinterpret_cast<unsigned char*>(dataU));

			for (size_t k = 0; k < sizeT; k++)
			{
				dataT[k] ^= dataU[k];
			}
		}

		const size_t clen = std::min(derivedKeyLeftBytes, sizeT);
		std::memcpy(derivedKeyData, dataT, clen);
		derivedKeyLeftBytes -= clen;
		derivedKeyData		+= clen;
	}

	sodium_memzero(&PShctx, sizeof(PShctx));
	sodium_memzero(&hctx, sizeof(hctx));

	return derivedKey;
}

}//namespace GPlatform
