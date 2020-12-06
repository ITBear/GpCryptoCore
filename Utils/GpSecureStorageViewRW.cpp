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
    Release();
}

GpSecureStorageViewRW&  GpSecureStorageViewRW::operator= (GpSecureStorageViewRW&& aView)
{
    if (this == &aView)
    {
        return *this;
    }

    Release();
    iStorage = std::move(aView.iStorage);
    aView.iStorage.reset();

    return *this;
}

GpRawPtrByteR   GpSecureStorageViewRW::R (void) const
{
    THROW_GPE_COND_CHECK_M(iStorage.has_value(), "Storage is null"_sv);

    const GpSecureStorage& storage = iStorage.value();
    return storage.DataR();
}

GpRawPtrByteRW  GpSecureStorageViewRW::RW (void)
{
    THROW_GPE_COND_CHECK_M(iStorage.has_value(), "Storage is null"_sv);

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

void    GpSecureStorageViewRW::Release (void)
{
    if (iStorage.has_value() == false)
    {
        return;
    }

    const GpSecureStorage& storage = iStorage.value();

    storage.LockRW();
    storage.SetViewing(false);
    iStorage.reset();
}

}//namespace GPlatform
