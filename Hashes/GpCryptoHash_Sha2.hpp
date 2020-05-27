#pragma once

#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHash_Sha2
{
	CLASS_REMOVE_CTRS(GpCryptoHash_Sha2);

public:
	static GpBytesArray			S_256	(const std::byte*	aData,
										 const count_t		aDataSize);
	static inline GpBytesArray	S_256	(std::string_view aData);
	static inline GpBytesArray	S_256	(const GpBytesArray& aData);
	static inline GpBytesArray	S_256	(const GpSecureStorage& aData);

	static GpBytesArray			S_512	(const std::byte*	aData,
										 const count_t		aDataSize);
	static inline GpBytesArray	S_512	(std::string_view aData);
	static inline GpBytesArray	S_512	(const GpBytesArray& aData);
	static inline GpBytesArray	S_512	(const GpSecureStorage& aData);
};

GpBytesArray	GpCryptoHash_Sha2::S_256 (std::string_view aData)
{
	return S_256(reinterpret_cast<const std::byte*>(aData.data()), count_t::SMake(aData.size()));
}

GpBytesArray	GpCryptoHash_Sha2::S_256 (const GpBytesArray& aData)
{
	return S_256(aData.data(), count_t::SMake(aData.size()));
}

GpBytesArray	GpCryptoHash_Sha2::S_256 (const GpSecureStorage& aData)
{
	GpSecureStorageViewR view = aData.ViewR();
	return S_256(view.Data(), view.Size());
}

GpBytesArray	GpCryptoHash_Sha2::S_512 (std::string_view aData)
{
	return S_512(reinterpret_cast<const std::byte*>(aData.data()), count_t::SMake(aData.size()));
}

GpBytesArray	GpCryptoHash_Sha2::S_512 (const GpBytesArray& aData)
{
	return S_512(aData.data(), count_t::SMake(aData.size()));
}

GpBytesArray	GpCryptoHash_Sha2::S_512 (const GpSecureStorage& aData)
{
	GpSecureStorageViewR view = aData.ViewR();
	return S_512(view.Data(), view.Size());
}

}//GPlatform
