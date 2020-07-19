#include "GpSecureStorageViewRW.hpp"
#include "GpSecureStorage.hpp"

namespace GPlatform {

GpSecureStorageViewRW::GpSecureStorageViewRW (GpSecureStorage& aStorage):
iStorage(aStorage)
{
    GpSecureStorage& storage = iStorage.value();

    storage.SetViewing(true);
    storage.UnlockRW();
}

GpSecureStorageViewRW::GpSecureStorageViewRW (GpSecureStorageViewRW&& aView) noexcept:
iStorage(std::move(aView.iStorage))
{
}

GpSecureStorageViewRW::~GpSecureStorageViewRW   (void) noexcept
{
    if (iStorage.has_value() == false)
    {
        return;
    }

    GpSecureStorage& storage = iStorage.value();

    storage.LockRW();
    storage.SetViewing(false);
}

GpRawPtrByteR   GpSecureStorageViewRW::R (void) const
{
    THROW_GPE_COND_CHECK_M(iStorage.has_value(), "Storage is null");

    const GpSecureStorage& storage = iStorage.value();
    return storage.DataR();
}

GpRawPtrByteRW  GpSecureStorageViewRW::RW (void)
{
    THROW_GPE_COND_CHECK_M(iStorage.has_value(), "Storage is null");

    GpSecureStorage& storage = iStorage.value();
    return storage.DataRW();
}

size_byte_t GpSecureStorageViewRW::Size (void) const noexcept
{
    if (iStorage.has_value() == false)
    {
        return 0_byte;
    }

    GpSecureStorage& storage = iStorage.value();
    return storage.Size();
}

bool    GpSecureStorageViewRW::IsEmpty (void) const noexcept
{
    return Size() == 0_byte;
}

}//namespace GPlatform
