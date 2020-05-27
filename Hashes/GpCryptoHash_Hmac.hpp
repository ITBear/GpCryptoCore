#pragma once

#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHash_Hmac
{
	CLASS_REMOVE_CTRS(GpCryptoHash_Hmac);

	using Res256T = GpArray<std::byte, 32>;
	using Res512T = GpArray<std::byte, 64>;

public:
	static void						S_256		(const std::byte*	aData,
												 const count_t		aDataSize,
												 const std::byte*	aKey,
												 const count_t		aKeySize,
												 Res256T::pointer	aDataOut);
	static inline void				S_256		(std::string_view	aData,
												 std::string_view	aKey,
												 Res256T::pointer	aDataOut);
	static inline void				S_256		(const GpBytesArray&	aData,
												 const GpBytesArray&	aKey,
												 Res256T::pointer		aDataOut);
	static inline void				S_256		(const GpSecureStorage& aData,
												 const GpSecureStorage& aKey,
												 Res256T::pointer		aDataOut);
	static inline void				S_256		(const GpSecureStorage& aData,
												 std::string_view		aKey,
												 Res256T::pointer		aDataOut);

	static inline GpBytesArray		S_256_Ba	(const std::byte*	aData,
												 const count_t		aDataSize,
												 const std::byte*	aKey,
												 const count_t		aKeySize);
	static inline GpBytesArray		S_256_Ba	(std::string_view aData,
												 std::string_view aKey);
	static inline GpBytesArray		S_256_Ba	(const GpBytesArray& aData,
												 const GpBytesArray& aKey);
	static inline GpBytesArray		S_256_Ba	(const GpSecureStorage& aData,
												 const GpSecureStorage& aKey);
	static inline GpBytesArray		S_256_Ba	(const GpSecureStorage& aData,
												 std::string_view		aKey);
	static inline GpSecureStorage	S_256_Ss	(const GpSecureStorage& aData,
												 const GpSecureStorage& aKey);
	static inline GpSecureStorage	S_256_Ss	(const GpSecureStorage& aData,
												 std::string_view		aKey);

	static void						S_512		(const std::byte*	aData,
												 const count_t		aDataSize,
												 const std::byte*	aKey,
												 const count_t		aKeySize,
												 Res512T::pointer	aDataOut);
	static inline void				S_512		(std::string_view	aData,
												 std::string_view	aKey,
												 Res512T::pointer	aDataOut);
	static inline void				S_512		(const GpBytesArray&	aData,
												 const GpBytesArray&	aKey,
												 Res512T::pointer		aDataOut);
	static inline void				S_512		(const GpSecureStorage& aData,
												 const GpSecureStorage& aKey,
												 Res512T::pointer		aDataOut);
	static inline void				S_512		(const GpSecureStorage& aData,
												 std::string_view		aKey,
												 Res512T::pointer		aDataOut);

	static inline GpBytesArray		S_512_Ba	(const std::byte*	aData,
												 const count_t		aDataSize,
												 const std::byte*	aKey,
												 const count_t		aKeySize);
	static inline GpBytesArray		S_512_Ba	(std::string_view aData,
												 std::string_view aKey);
	static inline GpBytesArray		S_512_Ba	(const GpBytesArray& aData,
												 const GpBytesArray& aKey);
	static inline GpBytesArray		S_512_Ba	(const GpSecureStorage& aData,
												 const GpSecureStorage& aKey);
	static inline GpBytesArray		S_512_Ba	(const GpSecureStorage& aData,
												 std::string_view		aKey);
	static inline GpSecureStorage	S_512_Ss	(const GpSecureStorage& aData,
												 const GpSecureStorage& aKey);
	static inline GpSecureStorage	S_512_Ss	(const GpSecureStorage& aData,
												 std::string_view		aKey);
};

void	GpCryptoHash_Hmac::S_256 (std::string_view	aData,
								  std::string_view	aKey,
								  Res256T::pointer	aDataOut)
{
	S_256(reinterpret_cast<const std::byte*>(aData.data()),
		  count_t::SMake(aData.size()),
		  reinterpret_cast<const std::byte*>(aKey.data()),
		  count_t::SMake(aKey.size()),
		  aDataOut);
}

void	GpCryptoHash_Hmac::S_256 (const GpBytesArray&	aData,
								  const GpBytesArray&	aKey,
								  Res256T::pointer		aDataOut)
{
	S_256(aData.data(),
		  count_t::SMake(aData.size()),
		  aKey.data(),
		  count_t::SMake(aKey.size()),
		  aDataOut);
}

void	GpCryptoHash_Hmac::S_256 (const GpSecureStorage&	aData,
								  const GpSecureStorage&	aKey,
								  Res256T::pointer			aDataOut)
{
	GpSecureStorageViewR viewData	= aData.ViewR();
	GpSecureStorageViewR viewKey	= aKey.ViewR();

	S_256(viewData.Data(),
		  viewData.Size(),
		  viewKey.Data(),
		  viewKey.Size(),
		  aDataOut);
}

void	GpCryptoHash_Hmac::S_256 (const GpSecureStorage&	aData,
								  std::string_view			aKey,
								  Res256T::pointer			aDataOut)
{
	GpSecureStorageViewR viewData = aData.ViewR();

	S_256(viewData.Data(),
		  viewData.Size(),
		  reinterpret_cast<const std::byte*>(aKey.data()),
		  count_t::SMake(aKey.size()),
		  aDataOut);
}

GpBytesArray	GpCryptoHash_Hmac::S_256_Ba (const std::byte*	aData,
											 const count_t		aDataSize,
											 const std::byte*	aKey,
											 const count_t		aKeySize)
{
	GpBytesArray res;
	res.resize(std::tuple_size<Res256T>::value);

	S_256(aData, aDataSize, aKey, aKeySize, res.data());

	return res;
}

GpBytesArray	GpCryptoHash_Hmac::S_256_Ba (std::string_view aData,
											 std::string_view aKey)
{
	return S_256_Ba(reinterpret_cast<const std::byte*>(aData.data()),
					count_t::SMake(aData.size()),
					reinterpret_cast<const std::byte*>(aKey.data()),
					count_t::SMake(aKey.size()));
}

GpBytesArray	GpCryptoHash_Hmac::S_256_Ba (const GpBytesArray& aData,
											 const GpBytesArray& aKey)
{
	return S_256_Ba(aData.data(),
					count_t::SMake(aData.size()),
					aKey.data(),
					count_t::SMake(aKey.size()));
}

GpBytesArray	GpCryptoHash_Hmac::S_256_Ba (const GpSecureStorage& aData,
											 const GpSecureStorage& aKey)
{
	GpSecureStorageViewR viewData	= aData.ViewR();
	GpSecureStorageViewR viewKey	= aKey.ViewR();

	return S_256_Ba(viewData.Data(),
					viewData.Size(),
					viewKey.Data(),
					viewKey.Size());
}

GpBytesArray	GpCryptoHash_Hmac::S_256_Ba (const GpSecureStorage&	aData,
											 std::string_view		aKey)
{
	GpSecureStorageViewR viewData = aData.ViewR();

	return S_256_Ba(viewData.Data(), viewData.Size(),
					reinterpret_cast<const std::byte*>(aKey.data()),
					count_t::SMake(aKey.size()));
}

GpSecureStorage	GpCryptoHash_Hmac::S_256_Ss (const GpSecureStorage& aData,
											 const GpSecureStorage& aKey)
{
	GpSecureStorage res;

	{
		GpSecureStorageViewR viewData	= aData.ViewR();
		GpSecureStorageViewR viewKey	= aKey.ViewR();


		res.Resize(count_t::SMake(std::tuple_size<Res256T>::value));
		GpSecureStorageViewRW resView = res.ViewRW();

		S_256(viewData.Data(),
			  viewData.Size(),
			  viewKey.Data(),
			  viewKey.Size(),
			  resView.Data());
	}

	return res;
}

GpSecureStorage	GpCryptoHash_Hmac::S_256_Ss	(const GpSecureStorage& aData,
											 std::string_view		aKey)
{
	GpSecureStorage res;

	{
		GpSecureStorageViewR viewData = aData.ViewR();

		res.Resize(count_t::SMake(std::tuple_size<Res256T>::value));
		GpSecureStorageViewRW resView = res.ViewRW();

		S_256(viewData.Data(), viewData.Size(),
			  reinterpret_cast<const std::byte*>(aKey.data()),
			  count_t::SMake(aKey.size()),
			  resView.Data());
	}

	return res;
}

void	GpCryptoHash_Hmac::S_512 (std::string_view	aData,
								  std::string_view	aKey,
								  Res512T::pointer	aDataOut)
{
	S_512(reinterpret_cast<const std::byte*>(aData.data()),
		  count_t::SMake(aData.size()),
		  reinterpret_cast<const std::byte*>(aKey.data()),
		  count_t::SMake(aKey.size()),
		  aDataOut);
}

void	GpCryptoHash_Hmac::S_512 (const GpBytesArray&	aData,
								  const GpBytesArray&	aKey,
								  Res512T::pointer		aDataOut)
{
	S_512(aData.data(),
		  count_t::SMake(aData.size()),
		  aKey.data(),
		  count_t::SMake(aKey.size()),
		  aDataOut);
}

void	GpCryptoHash_Hmac::S_512 (const GpSecureStorage&	aData,
								  const GpSecureStorage&	aKey,
								  Res512T::pointer			aDataOut)
{
	GpSecureStorageViewR viewData	= aData.ViewR();
	GpSecureStorageViewR viewKey	= aKey.ViewR();

	S_512(viewData.Data(),
		  viewData.Size(),
		  viewKey.Data(),
		  viewKey.Size(),
		  aDataOut);
}

void	GpCryptoHash_Hmac::S_512 (const GpSecureStorage&	aData,
								  std::string_view			aKey,
								  Res512T::pointer			aDataOut)
{
	GpSecureStorageViewR viewData = aData.ViewR();

	S_512(viewData.Data(),
		  viewData.Size(),
		  reinterpret_cast<const std::byte*>(aKey.data()),
		  count_t::SMake(aKey.size()),
		  aDataOut);
}

GpBytesArray	GpCryptoHash_Hmac::S_512_Ba (const std::byte*	aData,
											 const count_t		aDataSize,
											 const std::byte*	aKey,
											 const count_t		aKeySize)
{
	GpBytesArray res;
	res.resize(std::tuple_size<Res512T>::value);

	S_512(aData, aDataSize, aKey, aKeySize, res.data());

	return res;
}

GpBytesArray	GpCryptoHash_Hmac::S_512_Ba (std::string_view aData,
											 std::string_view aKey)
{
	return S_512_Ba(reinterpret_cast<const std::byte*>(aData.data()),
					count_t::SMake(aData.size()),
					reinterpret_cast<const std::byte*>(aKey.data()),
					count_t::SMake(aKey.size()));
}

GpBytesArray	GpCryptoHash_Hmac::S_512_Ba (const GpBytesArray& aData,
											 const GpBytesArray& aKey)
{
	return S_512_Ba(aData.data(),
					count_t::SMake(aData.size()),
					aKey.data(),
					count_t::SMake(aKey.size()));
}

GpBytesArray	GpCryptoHash_Hmac::S_512_Ba (const GpSecureStorage& aData,
											 const GpSecureStorage& aKey)
{
	GpSecureStorageViewR viewData	= aData.ViewR();
	GpSecureStorageViewR viewKey	= aKey.ViewR();

	return S_512_Ba(viewData.Data(),
					viewData.Size(),
					viewKey.Data(),
					viewKey.Size());
}

GpBytesArray	GpCryptoHash_Hmac::S_512_Ba (const GpSecureStorage&	aData,
											 std::string_view		aKey)
{
	GpSecureStorageViewR viewData = aData.ViewR();

	return S_512_Ba(viewData.Data(), viewData.Size(),
					reinterpret_cast<const std::byte*>(aKey.data()),
					count_t::SMake(aKey.size()));
}

GpSecureStorage	GpCryptoHash_Hmac::S_512_Ss (const GpSecureStorage& aData,
											 const GpSecureStorage& aKey)
{
	GpSecureStorage res;

	{
		GpSecureStorageViewR viewData	= aData.ViewR();
		GpSecureStorageViewR viewKey	= aKey.ViewR();


		res.Resize(count_t::SMake(std::tuple_size<Res512T>::value));
		GpSecureStorageViewRW resView = res.ViewRW();

		S_512(viewData.Data(),
			  viewData.Size(),
			  viewKey.Data(),
			  viewKey.Size(),
			  resView.Data());
	}

	return res;
}

GpSecureStorage	GpCryptoHash_Hmac::S_512_Ss	(const GpSecureStorage& aData,
											 std::string_view		aKey)
{
	GpSecureStorage res;

	{
		GpSecureStorageViewR viewData = aData.ViewR();

		res.Resize(count_t::SMake(std::tuple_size<Res512T>::value));
		GpSecureStorageViewRW resView = res.ViewRW();

		S_512(viewData.Data(), viewData.Size(),
			  reinterpret_cast<const std::byte*>(aKey.data()),
			  count_t::SMake(aKey.size()),
			  resView.Data());
	}

	return res;
}

}//GPlatform
