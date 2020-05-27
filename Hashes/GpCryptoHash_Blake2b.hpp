#pragma once

#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHash_Blake2b
{
public:
	CLASS_REMOVE_CTRS(GpCryptoHash_Blake2b);

	using Res256T = GpArray<std::byte, 32>;


public:
	static void					S_256	(const std::byte*	aData,
										 const count_t		aDataSize,
										 const std::byte*	aKey,
										 const count_t		aKeySize,
										 Res256T::pointer	aDataOut);

	static inline void			S_256	(const std::byte*	aData,
										 const count_t		aSize,
										 Res256T::pointer	aDataOut);
	static inline void			S_256	(std::string_view	aData,
										 Res256T::pointer	aDataOut);
	static inline void			S_256	(std::string_view	aData,
										 std::string_view	aKey,
										 Res256T::pointer	aDataOut);
	static inline void			S_256	(const GpBytesArray&	aData,
										 Res256T::pointer		aDataOut);
	static inline void			S_256	(const GpBytesArray&	aData,
										 const GpBytesArray&	aKey,
										 Res256T::pointer		aDataOut);
	static inline void			S_256	(const GpSecureStorage& aData,
										 const GpSecureStorage& aKey,
										 Res256T::pointer		aDataOut);

	static inline GpBytesArray	S_256_Ba(const std::byte*	aData,
										 const count_t		aDataSize,
										 const std::byte*	aKey,
										 const count_t		aKeySize);

	static inline GpBytesArray	S_256_Ba(const std::byte*	aData,
										 const count_t		aSize);
	static inline GpBytesArray	S_256_Ba(std::string_view aData);
	static inline GpBytesArray	S_256_Ba(std::string_view aData,
										 std::string_view aKey);
	static inline GpBytesArray	S_256_Ba(const GpBytesArray& aData);
	static inline GpBytesArray	S_256_Ba(const GpBytesArray& aData,
										 const GpBytesArray& aKey);
	static inline GpBytesArray	S_256_Ba(const GpSecureStorage& aData,
										 const GpSecureStorage& aKey);
};

void	GpCryptoHash_Blake2b::S_256 (const std::byte*	aData,
									 const count_t		aSize,
									 Res256T::pointer	aDataOut)
{
	S_256(aData, aSize, nullptr, 0_cnt, aDataOut);
}

void	GpCryptoHash_Blake2b::S_256 (std::string_view	aData,
									 Res256T::pointer	aDataOut)
{
	S_256(reinterpret_cast<const std::byte*>(aData.data()),
		  count_t::SMake(aData.size()),
		  aDataOut);
}

void	GpCryptoHash_Blake2b::S_256 (std::string_view	aData,
									 std::string_view	aKey,
									 Res256T::pointer	aDataOut)
{
	S_256(reinterpret_cast<const std::byte*>(aData.data()),
		  count_t::SMake(aData.size()),
		  reinterpret_cast<const std::byte*>(aKey.data()),
		  count_t::SMake(aKey.size()),
		  aDataOut);
}

void	GpCryptoHash_Blake2b::S_256 (const GpBytesArray&	aData,
									 Res256T::pointer		aDataOut)
{
	S_256(aData.data(),
		  count_t::SMake(aData.size()),
		  aDataOut);
}

void	GpCryptoHash_Blake2b::S_256 (const GpBytesArray&	aData,
									 const GpBytesArray&	aKey,
									 Res256T::pointer		aDataOut)
{
	S_256(aData.data(),
		  count_t::SMake(aData.size()),
		  aKey.data(),
		  count_t::SMake(aKey.size()),
		  aDataOut);
}

void	GpCryptoHash_Blake2b::S_256	(const GpSecureStorage& aData,
									 const GpSecureStorage& aKey,
									 Res256T::pointer		aDataOut)
{
	GpSecureStorageViewR viewData	= aData.ViewR();
	GpSecureStorageViewR viewKey	= aKey.ViewR();

	S_256(viewData.Data(), viewData.Size(),
		  viewKey.Data(), viewKey.Size(),
		  aDataOut);
}

GpBytesArray	GpCryptoHash_Blake2b::S_256_Ba	(const std::byte*	aData,
												 const count_t		aDataSize,
												 const std::byte*	aKey,
												 const count_t		aKeySize)
{
	GpBytesArray res;
	res.resize(std::tuple_size<Res256T>::value);

	S_256(aData, aDataSize, aKey, aKeySize, res.data());

	return res;
}

GpBytesArray	GpCryptoHash_Blake2b::S_256_Ba (const std::byte*	aData,
												const count_t		aSize)
{
	return S_256_Ba(aData, aSize, nullptr, 0_cnt);
}

GpBytesArray	GpCryptoHash_Blake2b::S_256_Ba (std::string_view aData)
{
	return S_256_Ba(reinterpret_cast<const std::byte*>(aData.data()), count_t::SMake(aData.size()));
}

GpBytesArray	GpCryptoHash_Blake2b::S_256_Ba (std::string_view aData,
												std::string_view aKey)
{
	return S_256_Ba(reinterpret_cast<const std::byte*>(aData.data()), count_t::SMake(aData.size()),
					reinterpret_cast<const std::byte*>(aKey.data()), count_t::SMake(aKey.size()));
}

GpBytesArray	GpCryptoHash_Blake2b::S_256_Ba (const GpBytesArray& aData)
{
	return S_256_Ba(aData.data(), count_t::SMake(aData.size()));
}

GpBytesArray	GpCryptoHash_Blake2b::S_256_Ba (const GpBytesArray& aData,
												const GpBytesArray& aKey)
{
	return S_256_Ba(aData.data(), count_t::SMake(aData.size()),
					aKey.data(), count_t::SMake(aKey.size()));
}

GpBytesArray	GpCryptoHash_Blake2b::S_256_Ba	(const GpSecureStorage& aData,
												 const GpSecureStorage& aKey)
{
	GpSecureStorageViewR viewData	= aData.ViewR();
	GpSecureStorageViewR viewKey	= aKey.ViewR();

	return S_256_Ba(viewData.Data(), viewData.Size(),
					viewKey.Data(), viewKey.Size());
}

}//GPlatform
