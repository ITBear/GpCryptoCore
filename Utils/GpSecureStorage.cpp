#include "GpSecureStorage.hpp"
#include <libsodium/sodium.h>

namespace GPlatform {

GpSecureStorage::GpSecureStorage (void) noexcept
{
}

GpSecureStorage::GpSecureStorage (const GpSecureStorage& aStorage)
{
    CopyFrom(aStorage);
}

GpSecureStorage::GpSecureStorage (GpSecureStorage&& aStorage)
{
    Set(std::move(aStorage));
}

GpSecureStorage::GpSecureStorage (GpRawPtrByteR aData)
{
    CopyFrom(aData);
}

GpSecureStorage::~GpSecureStorage (void) noexcept
{
    Clear();
}

GpSecureStorage&    GpSecureStorage::operator= (const GpSecureStorage& aStorage)
{
    CopyFrom(aStorage);
    return *this;
}

GpSecureStorage&    GpSecureStorage::operator= (GpSecureStorage&& aStorage)
{
    Set(std::move(aStorage));
    return *this;
}

void    GpSecureStorage::Clear (void)
{
    if (iData == nullptr)
    {
        return;
    }

    THROW_GPE_COND_CHECK_M(IsViewing() == false, "Storage is viewing");

    sodium_memzero(ViewRW().RW()._PtrBegin(), iSize.ValueAs<size_t>());

#if !defined(OS_BROWSER)
    sodium_free(iData);
#else
    std::free(iData);
#endif

    iData = nullptr;
    iSize = 0_byte;
}

void    GpSecureStorage::Allocate (const size_byte_t aSize)
{
    Clear();

    THROW_GPE_COND_CHECK_M(IsViewing() == false, "Storage is viewing");
    THROW_GPE_COND_CHECK_M((aSize >= 1_byte) && (aSize <= 8192_byte), "aSize is out of range"_sv);

#if !defined(OS_BROWSER)
    iData = reinterpret_cast<std::byte*>(sodium_malloc(aSize.ValueAs<size_t>()));
#else
    iData = reinterpret_cast<std::byte*>(std::aligned_alloc(?, aSize.ValueAs<size_t>()));
#endif

    THROW_GPE_COND_CHECK_M(iData != nullptr, "sodium_malloc return error"_sv);
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

void    GpSecureStorage::Allocate (const count_t aElementsCount, const size_byte_t aElementSize)
{
    Clear();

    THROW_GPE_COND_CHECK_M(IsViewing() == false, "Storage is viewing");

    const size_byte_t totalSize = aElementsCount.ValueAs<size_byte_t>() * aElementSize;
    THROW_GPE_COND_CHECK_M((totalSize >= 1_byte) && (totalSize <= 8192_byte), "aSize is out of range"_sv);

#if !defined(OS_BROWSER)
    iData = reinterpret_cast<std::byte*>(sodium_allocarray(aElementsCount.ValueAs<size_t>(), aElementSize.ValueAs<size_t>()));
#else
    const size_t alignment = aElementSize.ValueAs<size_t>();
    iData = reinterpret_cast<std::byte*>(std::aligned_alloc(alignment, totalSize.ValueAs<size_t>()));
#endif

    THROW_GPE_COND_CHECK_M(iData != nullptr, "sodium_malloc return error"_sv);
    iSize = totalSize;

#if !defined(OS_BROWSER)
    if (sodium_mlock(iData, iSize.ValueAs<size_t>()) != 0)
    {
        Clear();
        THROW_GPE("sodium_mlock return error"_sv);
    }
#endif//#if !defined(OS_BROWSER)

    LockRW();

    iIsEnableResize = false;
}

void    GpSecureStorage::Resize (const size_byte_t aSize)
{
    if (IsEmpty())
    {
        Allocate(aSize);
        return;
    }

    THROW_GPE_COND_CHECK_M(iIsEnableResize, "Resize disabled"_sv);
    THROW_GPE_COND_CHECK_M(IsViewing() == false, "Storage is viewing"_sv);

    GpSecureStorage tmpStorage;
    tmpStorage.Allocate(aSize);

    {
        GpSecureStorageViewRW   tmpView     = tmpStorage.ViewRW();
        GpSecureStorageViewR    thisView    = ViewR();

        const count_t size = std::min(tmpView.Size(), thisView.Size()).ValueAs<count_t>();

        GpRawPtrByteR thisViewSubrangePtr = thisView.R().Subrange(0_cnt, size);
        tmpView.RW().CopyFrom(thisViewSubrangePtr);
    }

    Set(std::move(tmpStorage));
}

void    GpSecureStorage::CopyFrom (const GpSecureStorage& aStorage)
{
    if (this == &aStorage)
    {
        return;
    }

    THROW_GPE_COND_CHECK_M(IsViewing() == false, "Storage is viewing");

    GpSecureStorageViewR viewR = aStorage.ViewR();
    CopyFrom(viewR.R());
}

void    GpSecureStorage::Set (GpSecureStorage&& aStorage)
{
    if (this == &aStorage)
    {
        return;
    }

    THROW_GPE_COND_CHECK_M(aStorage.IsViewing() == false, "aStorage is viewing");
    THROW_GPE_COND_CHECK_M(IsViewing() == false, "Storage is viewing");

    Clear();

    iData = aStorage.iData;
    iSize = aStorage.iSize;

    aStorage.iData = nullptr;
    aStorage.iSize = 0_byte;
}

void    GpSecureStorage::CopyFrom (GpRawPtrByteR aData)
{
    Resize(aData.SizeLeft());
    ViewRW().RW().CopyFrom(aData);
}

void    GpSecureStorage::CopyFrom (GpRawPtrByteRW aData)
{
    Resize(aData.SizeLeft());
    ViewRW().RW().CopyFrom(aData);
}

GpSecureStorageViewR    GpSecureStorage::ViewR (void) const
{
    THROW_GPE_COND_CHECK_M(IsViewing() == false, "Storage is viewing");

    return GpSecureStorageViewR(*this);
}

GpSecureStorageViewRW   GpSecureStorage::ViewRW (void)
{
    THROW_GPE_COND_CHECK_M(IsViewing() == false, "Storage is viewing");

    return GpSecureStorageViewRW(*this);
}

void    GpSecureStorage::LockRW (void) const
{
    if (iData == nullptr)
    {
        return;
    }

#if !defined(OS_BROWSER)
    if (sodium_mprotect_noaccess(iData) != 0)
    {
        THROW_GPE("sodium_mprotect_noaccess return error"_sv);
    }
#endif//#if !defined(OS_BROWSER)
}

void    GpSecureStorage::UnlockRW (void)
{
    if (iData == nullptr)
    {
        return;
    }

#if !defined(OS_BROWSER)
    if (sodium_mprotect_readwrite(iData) != 0)
    {
        THROW_GPE("sodium_mprotect_readwrite return error"_sv);
    }
#endif//#if !defined(OS_BROWSER)
}

void    GpSecureStorage::UnlockR (void) const
{
    if (iData == nullptr)
    {
        return;
    }

#if !defined(OS_BROWSER)
    if (sodium_mprotect_readonly(iData) != 0)
    {
        THROW_GPE("sodium_mprotect_readonly return error"_sv);
    }
#endif//#if !defined(OS_BROWSER)
}

GpRawPtrByteR   GpSecureStorage::DataR (void) const
{
    return GpRawPtrByteR(iData, iSize.ValueAs<count_t>());
}

GpRawPtrByteRW  GpSecureStorage::DataRW (void)
{
    return GpRawPtrByteRW(iData, iSize.ValueAs<count_t>());
}

}//namespace GPlatform
