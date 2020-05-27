#include "GpSecureStorage.hpp"
#include <libsodium/sodium.h>

namespace GPlatform {

GpSecureStorage::GpSecureStorage (void) noexcept
{
}

GpSecureStorage::GpSecureStorage (GpSecureStorage&& aStorage) noexcept:
iData(aStorage.iData),
iSize(aStorage.iSize)
{
	aStorage.iData	= nullptr;
	aStorage.iSize	= 0_cnt;
}

GpSecureStorage::~GpSecureStorage (void) noexcept
{
	Clear();
}

GpSecureStorage&	GpSecureStorage::operator= (GpSecureStorage&& aStorage) noexcept
{
	if (&aStorage == this)
	{
		return *this;
	}

	Clear();

	iData	= aStorage.iData;
	iSize	= aStorage.iSize;

	aStorage.iData	= nullptr;
	aStorage.iSize	= 0_cnt;

	return *this;
}

void	GpSecureStorage::Clear (void) noexcept
{
	if (iData != nullptr)
	{
		UnlockRW();

		sodium_memzero(iData, iSize.ValueAs<size_t>());

#if !defined(OS_BROWSER)
        sodium_free(iData);
#else
		std::free(iData);
#endif

		iData = nullptr;
		iSize = 0_cnt;
	}
}

void	GpSecureStorage::Allocate (count_t aSize)
{
	Clear();

	THROW_GPE_COND_CHECK_M((aSize > 0_cnt) && (aSize < 4096_cnt), "aSize is out of range"_sv);

#if !defined(OS_BROWSER)
	iData = reinterpret_cast<std::byte*>(sodium_malloc(aSize.ValueAs<size_t>()));
#else
	iData = reinterpret_cast<std::byte*>(std::malloc(aSize.ValueAs<size_t>()));
#endif

	if (iData == nullptr)
	{
		THROW_GPE("sodium_malloc return error"_sv);
	}

	iSize = aSize;

#if !defined(OS_BROWSER)
	if (sodium_mlock(iData, iSize.ValueAs<size_t>()) != 0)
	{
		Clear();
		THROW_GPE("sodium_mlock return error"_sv);
	}
#endif//#if !defined(OS_BROWSER)

	LockRW();
}

void	GpSecureStorage::Resize (count_t aSize)
{
	if (IsEmpty())
	{
		Allocate(aSize);
		return;
	}

	GpSecureStorage s;

	{
		s.Allocate(aSize);
		GpSecureStorageViewRW	sView		= s.ViewRW();
		GpSecureStorageViewR	thisView	= ViewR();

		std::memcpy(sView.Data(), thisView.Data(), std::min(aSize.Value(), iSize.Value()));
	}

	Set(std::move(s));
}

void	GpSecureStorage::Set (GpMemoryStorage&& aStorage)
{
	if (this == &aStorage)
	{
		return;
	}

	GpSecureStorage* ss = dynamic_cast<GpSecureStorage*>(&aStorage);

	THROW_GPE_COND_CHECK_M(ss != nullptr, "Wrong type of aStorage"_sv);

	Clear();

	iData = ss->iData;
	iSize = ss->iSize;

	ss->iData = nullptr;
	ss->iSize = 0_cnt;
}

void	GpSecureStorage::Set (std::string_view aData)
{
	Resize(count_t::SMake(aData.size()));

	GpSecureStorageViewRW view = ViewRW();
	std::memcpy(view.Data(), aData.data(), aData.size());
}

GpMemoryStorage::SP	GpSecureStorage::New (void) const
{
	return GpSecureStorage::SP::SNew();
}

void	GpSecureStorage::LockRW (void) const
{
	if (iData != nullptr)
	{
#if !defined(OS_BROWSER)
		if (sodium_mprotect_noaccess(iData) != 0)
		{
			THROW_GPE("sodium_mprotect_noaccess return error"_sv);
		}
#endif//#if !defined(OS_BROWSER)
	}
}

void	GpSecureStorage::UnlockRW (void)
{
	if (iData != nullptr)
	{
#if !defined(OS_BROWSER)
		if (sodium_mprotect_readwrite(iData) != 0)
		{
			THROW_GPE("sodium_mprotect_readwrite return error"_sv);
		}
#endif//#if !defined(OS_BROWSER)
	}
}

void	GpSecureStorage::UnlockR (void) const
{
	if (iData != nullptr)
	{
#if !defined(OS_BROWSER)
		if (sodium_mprotect_readonly(iData) != 0)
		{
			THROW_GPE("sodium_mprotect_readonly return error"_sv);
		}
#endif//#if !defined(OS_BROWSER)
	}
}

}//namespace GPlatform
