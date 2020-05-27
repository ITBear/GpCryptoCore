#include "GpSecureStorageViewRW.hpp"
#include "GpSecureStorage.hpp"

namespace GPlatform {

GpSecureStorageViewRW::GpSecureStorageViewRW (GpSecureStorage& aStorage):
iStorage(&aStorage)
{
	iStorage->UnlockRW();
}

GpSecureStorageViewRW::GpSecureStorageViewRW (GpSecureStorageViewRW&& aView) noexcept:
iStorage(aView.iStorage)
{
	aView.iStorage = nullptr;
}

GpSecureStorageViewRW::~GpSecureStorageViewRW	(void) noexcept
{
	if (iStorage != nullptr)
	{
		try
		{
			iStorage->LockRW();
		} catch (const GpException& e)
		{
			GpExceptionsSink::SSink(e);
		}
	}
}

const std::byte*	GpSecureStorageViewRW::Data (void) const noexcept
{
	if (iStorage != nullptr)
	{
		return iStorage->iData;
	} else
	{
		return nullptr;
	}
}

std::byte*	GpSecureStorageViewRW::Data (void) noexcept
{
	if (iStorage != nullptr)
	{
		return iStorage->iData;
	} else
	{
		return nullptr;
	}
}

count_t	GpSecureStorageViewRW::Size (void) const noexcept
{
	if (iStorage != nullptr)
	{
		return iStorage->iSize;
	} else
	{
		return 0_cnt;
	}
}

std::string_view	GpSecureStorageViewRW::AsStringView (void) const noexcept
{
	if (iStorage != nullptr)
	{
		return std::string_view(reinterpret_cast<const char*>(iStorage->iData),
								iStorage->iSize.ValueAs<size_t>());
	} else
	{
		return std::string_view();
	}
}

std::string_view	GpSecureStorageViewRW::AsStringView (const count_t aOffset, const count_t aSize) const
{
	THROW_GPE_COND_CHECK_M(iStorage != nullptr, "Storage is empty"_sv);

	const count_t size = iStorage->Size();

	THROW_GPE_COND_CHECK_M(   (aOffset < size)
						   && ((aOffset + aSize) <= size), "Out of range"_sv);

	return std::string_view(reinterpret_cast<const char*>(iStorage->iData) + aOffset.ValueAs<size_t>(),
							aSize.ValueAs<size_t>());
}

bool	GpSecureStorageViewRW::IsEmpty (void) const noexcept
{
	return (iStorage == nullptr) || (iStorage->iSize == 0_cnt);
}

}//namespace GPlatform
