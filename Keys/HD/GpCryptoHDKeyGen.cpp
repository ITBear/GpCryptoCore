#include "GpCryptoHDKeyGen.hpp"
#include "../../Hashes/GpCryptoHash_Hmac.hpp"
#include "../../Hashes/GpCryptoHash_Ripemd160.hpp"
#include "../Curve25519/GpCryptoKey_Curve25519.hpp"

namespace GPlatform {

GpCryptoHDKeyPair	GpCryptoHDKeyGen::SMasterKeyPairFromSeed (const GpSecureStorage&	aSeed,
															  const NetworkTypeTE		aNetworkType,
															  const SchemeTypeTE		aSchemeType,
															  const count_t				aUID)
{
	GpSecureStorage			valI		= GpCryptoHash_Hmac::S_512_Ss(aSeed, "ed25519 seed"_sv);
	GpSecureStorageViewR	valIView	= valI.ViewR();
	std::string_view		valIL		= valIView.AsStringView(0_cnt, 32_cnt);
	std::string_view		valIR		= valIView.AsStringView(32_cnt, 32_cnt);

	GpSecureStorage	chainCode;
	GpSecureStorage	privateData;

	chainCode.Set(valIR);
	privateData.Set(valIL);

	GpCryptoKeyPair_Ed25519 keyPair_Ed25519;
	keyPair_Ed25519.ImportPrivateBytesSV(valIL);
	const GpBytesArray& publicBytes = keyPair_Ed25519.PublicBytes();
	GpBytesArray		publicData;
	publicData.resize(33);
	GpByteOStreamFixedSize publicBytesOStream(publicData.data(),
											  count_t::SMake(publicData.size()));
	publicBytesOStream.UInt8(0);
	publicBytesOStream.Bytes(publicBytes);

	GpCryptoHDKeyPair p;

	p.ConstructRoot(aNetworkType,
					aSchemeType,
					chainCode,
					privateData,
					std::string_view(reinterpret_cast<const char*>(publicData.data()), publicData.size()),
					aUID,
					"m"_sv);

	return p;
}

GpCryptoHDKeyPair	GpCryptoHDKeyGen::SChildKeyPair (const GpCryptoHDKeyPair&	aParentHDKeyPair,
													 const count_t				aChildNumber,
													 const bool					aIsHardened,
													 std::string_view			aPath)
{
	count_t childNumber = aChildNumber;

	if (aIsHardened)
	{
		childNumber += 0x80000000_cnt;
	} else
	{
		THROW_GPE_COND_CHECK_M(aParentHDKeyPair.Public().SchemeType() == GpCryptoHDSchemeType::SLIP10_ED25519,
							   "SLIP10_ED25519 only supports hardened keys"_sv);
	}

	GpSecureStorage sourceData;

	if (aIsHardened)
	{
		sourceData.Resize(1_cnt + 32_cnt + 4_cnt);
		GpSecureStorageViewRW	sourceDataView = sourceData.ViewRW();
		GpByteOStreamFixedSize	sourceDataOStream(sourceDataView.Data(), sourceDataView.Size());

		sourceDataOStream.UInt8(0);
		sourceDataOStream.Bytes(aParentHDKeyPair.Private().KeyData().ViewR().AsStringView());
		sourceDataOStream.UInt32(childNumber.ValueAs<u_int_32>());
	} else
	{
		sourceData.Resize(32_cnt + 4_cnt);
		GpSecureStorageViewRW	sourceDataView = sourceData.ViewRW();
		GpByteOStreamFixedSize	sourceDataOStream(sourceDataView.Data(), sourceDataView.Size());

		sourceDataOStream.Bytes(aParentHDKeyPair.Public().KeyData().ViewR().AsStringView());
		sourceDataOStream.UInt32(childNumber.ValueAs<u_int_32>());
	}

	GpSecureStorage			valI		= GpCryptoHash_Hmac::S_512_Ss(sourceData, aParentHDKeyPair.Private().ChainCode());
	GpSecureStorageViewR	valIView	= valI.ViewR();
	std::string_view		valIL		= valIView.AsStringView(0_cnt, 32_cnt);
	std::string_view		valIR		= valIView.AsStringView(32_cnt, 32_cnt);

	GpSecureStorage	chainCode;
	GpSecureStorage	privateData;

	chainCode.Set(valIR);
	privateData.Set(valIL);

	GpCryptoKeyPair_Ed25519 keyPair_Ed25519;
	keyPair_Ed25519.ImportPrivateBytesSV(valIL);
	const GpBytesArray& publicBytes = keyPair_Ed25519.PublicBytes();
	GpBytesArray		publicData;
	publicData.resize(33);
	GpByteOStreamFixedSize publicBytesOStream(publicData.data(),
											  count_t::SMake(publicData.size()));
	publicBytesOStream.UInt8(0);
	publicBytesOStream.Bytes(publicBytes);

	GpBytesArray h160 = GpCryptoHash_Ripemd160::S_H(aParentHDKeyPair.Public().KeyData().ViewR().AsStringView());
	GpArray<std::byte, 4> fingerprint = { h160[0], h160[1], h160[2], h160[3] };

	GpCryptoHDKeyPair p;

	p.ConstructChild(aParentHDKeyPair.Private().NetworkType(),
					 aParentHDKeyPair.Private().SchemeType(),
					 aParentHDKeyPair.Private().Depth() + 1_cnt,
					 fingerprint,
					 childNumber,
					 chainCode,
					 privateData,
					 std::string_view(reinterpret_cast<const char*>(publicData.data()), publicData.size()),
					 aParentHDKeyPair.UID(),
					 aParentHDKeyPair.Path() + aPath);

	return p;
}

}//GPlatform
