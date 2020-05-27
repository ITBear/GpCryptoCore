#pragma once

#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHash_Ripemd160
{
	CLASS_REMOVE_CTRS(GpCryptoHash_Ripemd160);

public:
	static GpBytesArray			S_H	(const std::byte*	aData,
									 const count_t		aDataSize);

	static inline GpBytesArray	S_H	(std::string_view aData);
	static inline GpBytesArray	S_H	(const GpBytesArray& aData);
	static inline GpBytesArray	S_H	(const GpSecureStorage& aData);
};

GpBytesArray	GpCryptoHash_Ripemd160::S_H (std::string_view aData)
{
	return S_H(reinterpret_cast<const std::byte*>(aData.data()), count_t::SMake(aData.size()));
}

GpBytesArray	GpCryptoHash_Ripemd160::S_H (const GpBytesArray& aData)
{
	return S_H(aData.data(), count_t::SMake(aData.size()));
}

GpBytesArray	GpCryptoHash_Ripemd160::S_H (const GpSecureStorage& aData)
{
	GpSecureStorageViewR view = aData.ViewR();
	return S_H(view.Data(), view.Size());
}
}//GPlatform
