#include "GpSecureStorageViewR.hpp"
#include "GpSecureStorage.hpp"

namespace GPlatform {

GpSecureStorageViewR::GpSecureStorageViewR (const GpSecureStorage& aStorage):
iStorage(aStorage)
{
    const GpSecureStorage& storage = iStorage.value();

    storage.SetViewing(true);
    storage.UnlockR();
}

GpSecureStorageViewR::GpSecureStorageViewR (GpSecureStorageViewR&& aView) noexcept:
iStorage(std::move(aView.iStorage))
{
}

GpSecureStorageViewR::~GpSecureStorageViewR (void) noexcept
{
    if (iStorage.has_value() == false)
    {
        return;
    }

    const GpSecureStorage& storage = iStorage.value();

    storage.LockRW();
    storage.SetViewing(false);
}

GpRawPtrByteR   GpSecureStorageViewR::R (void) const
{
    THROW_GPE_COND_CHECK_M(iStorage.has_value(), "Storage is null");

    const GpSecureStorage& storage = iStorage.value();
    return storage.DataR();
}

size_byte_t GpSecureStorageViewR::Size (void) const noexcept
{
    if (iStorage.has_value() == false)
    {
        return 0_byte;
    }

    const GpSecureStorage& storage = iStorage.value();
    return storage.Size();
}

bool    GpSecureStorageViewR::IsEmpty (void) const noexcept
{
    return Size() == 0_byte;
}

}//namespace GPlatform
