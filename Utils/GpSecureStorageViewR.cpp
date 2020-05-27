#include "GpSecureStorageViewR.hpp"
#include "GpSecureStorage.hpp"

namespace GPlatform {

GpSecureStorageViewR::GpSecureStorageViewR (const GpSecureStorage& aStorage):
iStorage(&aStorage)
{
	iStorage->UnlockR();
}

GpSecureStorageViewR::GpSecureStorageViewR	(GpSecureStorageViewR&& aView) noexcept:
iStorage(aView.iStorage)
{
	aView.iStorage = nullptr;
}

GpSecureStorageViewR::~GpSecureStorageViewR	(void) noexcept
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

const std::byte*	GpSecureStorageViewR::Data (void) const noexcept
{
	if (iStorage != nullptr)
	{
		return iStorage->iData;
	} else
	{
		return nullptr;
	}
}

count_t	GpSecureStorageViewR::Size (void) const noexcept
{
	if (iStorage != nullptr)
	{
		return iStorage->iSize;
	} else
	{
		return 0_cnt;
	}
}

std::string_view	GpSecureStorageViewR::AsStringView (void) const noexcept
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

std::string_view	GpSecureStorageViewR::AsStringView (count_t aOffset, count_t aSize) const
{
	THROW_GPE_COND_CHECK_M(iStorage != nullptr, "Storage is empty"_sv);

	const count_t size = iStorage->Size();

	THROW_GPE_COND_CHECK_M(   (aOffset < size)
						   && ((aOffset + aSize) <= size), "Out of range"_sv);

	return std::string_view(reinterpret_cast<const char*>(iStorage->iData) + aOffset.ValueAs<size_t>(),
							aSize.ValueAs<size_t>());
}

bool	GpSecureStorageViewR::IsEmpty (void) const noexcept
{
	return (iStorage == nullptr) || (iStorage->iSize == 0_cnt);
}

}//namespace GPlatform
