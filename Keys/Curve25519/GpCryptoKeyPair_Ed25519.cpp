#include "GpCryptoKeyPair_Ed25519.hpp"
#include <libsodium/sodium.h>

namespace GPlatform {

GpCryptoKeyPair_Ed25519::GpCryptoKeyPair_Ed25519 (void) noexcept:
GpCryptoKeyPair(GpCryptoKeyType::ED_25519)
{
}

GpCryptoKeyPair_Ed25519::~GpCryptoKeyPair_Ed25519 (void) noexcept
{
}

GpBytesArray	GpCryptoKeyPair_Ed25519::Sign (const GpBytesArray& aMessage) const
{
	GpBytesArray sign;
	sign.resize(size_t(crypto_sign_BYTES));

	GpSecureStorageViewR privateBytesView = iPrivateBytes.ViewR();

	if (crypto_sign_detached(reinterpret_cast<unsigned char*>(sign.data()),
							 nullptr,
							 reinterpret_cast<const unsigned char*>(aMessage.data()),
							 aMessage.size(),
							 reinterpret_cast<const unsigned char*>(privateBytesView.Data())) != 0)
	{
		THROW_GPE("crypto_sign_detached return error"_sv);
	}

	return sign;
}

void	GpCryptoKeyPair_Ed25519::GenerateNew (void)
{
	Clear();

	iPrivateBytes.Allocate(count_t::SMake(crypto_sign_SECRETKEYBYTES));
	iPublicBytes.resize(size_t(crypto_sign_PUBLICKEYBYTES));

	GpSecureStorageViewRW privateBytesView = iPrivateBytes.ViewRW();

	if (crypto_sign_keypair(reinterpret_cast<unsigned char*>(iPublicBytes.data()),
							reinterpret_cast<unsigned char*>(privateBytesView.Data())) != 0)
	{
		Clear();
		THROW_GPE("crypto_sign_keypair return error"_sv);
	}
}

void	GpCryptoKeyPair_Ed25519::GenerateNewSV (std::string_view aSeed)
{
	Clear();

	THROW_GPE_COND_CHECK_M(aSeed.size() == size_t(crypto_sign_SEEDBYTES), "Seed length must be 32 bytes"_sv);

	iPrivateBytes.Allocate(count_t::SMake(crypto_sign_SECRETKEYBYTES));
	iPublicBytes.resize(size_t(crypto_sign_PUBLICKEYBYTES));

	GpSecureStorageViewRW privateBytesView = iPrivateBytes.ViewRW();

	if (crypto_sign_seed_keypair(reinterpret_cast<unsigned char*>(iPublicBytes.data()),
								 reinterpret_cast<unsigned char*>(privateBytesView.Data()),
								 reinterpret_cast<const unsigned char*>(aSeed.data())) != 0)
	{
		Clear();
		THROW_GPE("crypto_sign_seed_keypair return error"_sv);
	}
}

void	GpCryptoKeyPair_Ed25519::ImportPrivateBytesSV (std::string_view aPrivateBytes)
{
	GenerateNewSV(aPrivateBytes);//PrivateBytes == seed (see crypto_sign_seed_keypair)
}

void	GpCryptoKeyPair_Ed25519::ImportPrivateStrHexSV (std::string_view aPrivateStrHex)
{
	Clear();

	GpSecureStorage privateBytes;

	{
		//Check length
		THROW_GPE_COND_CHECK_M(aPrivateStrHex.size() == 96, "Private key (of Ed25519) string length must be 96"_sv);

		//Check prefix
		THROW_GPE_COND_CHECK_M(aPrivateStrHex.substr(0, 32) == PrivateStrHexPrefix(),
							   "Private key (of Ed25519) string prefix must be '302e020100300506032b657004220420'"_sv);

		privateBytes.Allocate(count_t::SMake(crypto_sign_SEEDBYTES));
		GpSecureStorageViewRW privateBytesView = privateBytes.ViewRW();

		const count_t readCount = GpStringOps::SToBytes(aPrivateStrHex.substr(32, 64),
														privateBytesView.Data(),
														count_t::SMake(crypto_sign_SEEDBYTES));

		if (readCount != 32_cnt)
		{
			THROW_GPE("Wrong hex length"_sv);
		}
	}

	ImportPrivateBytesSS(privateBytes);
}

std::string_view	GpCryptoKeyPair_Ed25519::PrivateBytesPrefix (void) const noexcept
{
	//https://github.com/str4d/ed25519-java/blob/master/src/net/i2p/crypto/eddsa/EdDSAPrivateKey.java
	static std::string_view s("\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20"_sv);
	return s;
}

std::string_view	GpCryptoKeyPair_Ed25519::PublicBytesPrefix (void) const noexcept
{
	//https://github.com/str4d/ed25519-java/blob/master/src/net/i2p/crypto/eddsa/EdDSAPublicKey.java
	static std::string_view s("\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"_sv);
	return s;
}

std::string_view	GpCryptoKeyPair_Ed25519::PrivateStrHexPrefix (void) const noexcept
{
	static std::string_view s("302e020100300506032b657004220420"_sv);
	return s;
}

std::string_view	GpCryptoKeyPair_Ed25519::PublicStrHexPrefix (void) const noexcept
{
	static std::string_view s("302a300506032b6570032100"_sv);
	return s;
}

}//namespace GPlatform
