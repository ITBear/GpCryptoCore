#include "GpCryptoKeyPair.hpp"

namespace GPlatform {

GpCryptoKeyPair::GpCryptoKeyPair (const TypeTE aType) noexcept:
iType(aType)
{
}

GpCryptoKeyPair::GpCryptoKeyPair (GpCryptoKeyPair&& aKeyPair) noexcept:
iType(std::move(aKeyPair.iType)),
iPrivateBytes(std::move(aKeyPair.iPrivateBytes)),
iPublicBytes(std::move(aKeyPair.iPublicBytes))
{
}

GpCryptoKeyPair::~GpCryptoKeyPair (void) noexcept
{
	Clear();
}

void	GpCryptoKeyPair::Clear (void) noexcept
{
	iPrivateBytes.Clear();
	iPublicBytes.clear();
}

void	GpCryptoKeyPair::GenerateNewSS (const GpSecureStorage& aSeed)
{
	GpSecureStorageViewR view = aSeed.ViewR();
	GenerateNewSV(view.AsStringView());
}

void	GpCryptoKeyPair::ImportPrivateBytesSS (const GpSecureStorage& aPrivateBytes)
{
	GpSecureStorageViewR view = aPrivateBytes.ViewR();
	ImportPrivateBytesSV(view.AsStringView());
}

void	GpCryptoKeyPair::ImportPrivateStrHexSS (const GpSecureStorage& aPrivateStrHex)
{
	GpSecureStorageViewR view = aPrivateStrHex.ViewR();
	ImportPrivateStrHexSV(view.AsStringView());
}

GpBytesArray	GpCryptoKeyPair::ToPublicBytesWithPrefix (void) const
{
	GpBytesArray res;

	if (iPublicBytes.size() == 0)
	{
		return res;
	}

	std::string_view prefix = PublicBytesPrefix();
	res.resize(prefix.size() + iPublicBytes.size());
	std::memcpy(res.data(), prefix.data(), prefix.size());
	std::memcpy(res.data() + prefix.size(), iPublicBytes.data(), iPublicBytes.size());

	return res;
}

GpSecureStorage	GpCryptoKeyPair::ToPrivateStrHexWithPrefix (void) const
{
	if (iPrivateBytes.Size() == 0_cnt)
	{
		return GpSecureStorage();
	}

	std::string_view prefix = PrivateStrHexPrefix();
	GpSecureStorage res;
	res.Allocate(count_t::SMake(prefix.length() + 64));
	GpSecureStorageViewRW	resView		= res.ViewRW();
	GpSecureStorageViewR	privateView	= iPrivateBytes.ViewR();

	std::memcpy(resView.Data(), prefix.data(), prefix.length());

	GpStringOps::SFromBytes(privateView.Data(),
							32_cnt,
							reinterpret_cast<char*>(resView.Data()) + prefix.length(),
							64_cnt);

	return res;
}

std::string	GpCryptoKeyPair::ToPublicStrHexWithPrefix (void) const
{
	if (iPublicBytes.size() == 0)
	{
		return std::string();
	}

	return PublicStrHexPrefix() + GpStringOps::SFromBytes(iPublicBytes);
}

}//namespace GPlatform
