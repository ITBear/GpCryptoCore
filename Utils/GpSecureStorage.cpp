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
    THROW_GPE_COND_CHECK_M(IsViewing() == false, "Storage is viewing");

    if (iData != nullptr)
    {
        sodium_memzero(ViewRW().RW()._PtrBegin(), iSizeAllocated.ValueAs<size_t>());

#if !defined(OS_BROWSER)
        sodium_free(iData);
#else
        std::free(iData);
#endif
    }

    iData           = nullptr;
    iSizeUsed       = 0_byte;
    iSizeAllocated  = 0_byte;
    iAlignment      = 1_byte;
    //iIsViewing    = false;//THROW_GPE_COND_CHECK_M(IsViewing() == false, "Storage is viewing");
}

void    GpSecureStorage::Resize (const size_byte_t aSize)
{
    Resize(aSize, iAlignment);
}

void    GpSecureStorage::Resize (const size_byte_t aSize, const size_byte_t aAlignment)
{
    Reserve(aSize, aAlignment);
    iSizeUsed = aSize;
}

void    GpSecureStorage::Reserve (const size_byte_t aSize)
{
    Reserve(aSize, iAlignment);
}

void    GpSecureStorage::Reserve (const size_byte_t aSize, const size_byte_t aAlignment)
{
    THROW_GPE_COND_CHECK_M(IsViewing() == false, "Storage is viewing"_sv);

    if (IsDataNullptr())
    {
        ClearAndAllocate(aSize, aAlignment);
        LockRW();
        return;
    }

    THROW_GPE_COND_CHECK_M((Alignment() % aAlignment) == 0_byte, "Wrong alignment"_sv);

    if (aSize <= iSizeAllocated)
    {
        return;
    }

    GpSecureStorage tmpStorage;
    tmpStorage.Reserve(aSize, Alignment());
    tmpStorage.CopyFrom(ViewR().R());
    Set(std::move(tmpStorage));
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

    iData           = aStorage.iData;
    iSizeUsed       = aStorage.iSizeUsed;
    iSizeAllocated  = aStorage.iSizeAllocated;
    iAlignment      = aStorage.iAlignment;

    aStorage.iData          = nullptr;
    aStorage.iSizeUsed      = 0_byte;
    aStorage.iSizeAllocated = 0_byte;
    aStorage.iAlignment     = 1_byte;
}

void    GpSecureStorage::CopyFrom (const GpSecureStorage& aStorage)
{
    if (this == &aStorage)
    {
        return;
    }

    THROW_GPE_COND_CHECK_M(aStorage.IsViewing() == false, "aStorage is viewing");
    THROW_GPE_COND_CHECK_M(IsViewing() == false, "Storage is viewing");
    THROW_GPE_COND_CHECK_M((Alignment() % aStorage.Alignment()) == 0_byte, "Wrong alignment"_sv);

    CopyFrom(aStorage.ViewR().R());
}

void    GpSecureStorage::CopyFrom (GpRawPtrByteR aData)
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

void    GpSecureStorage::SetViewing (const bool aValue) const
{
    THROW_GPE_COND_CHECK_M(iIsViewing != aValue, "Same value");

    iIsViewing = aValue;
}

GpRawPtrByteR   GpSecureStorage::DataR (void) const
{
    return GpRawPtrByteR(iData, iSizeUsed.ValueAs<count_t>());
}

GpRawPtrByteRW  GpSecureStorage::DataRW (void)
{
    return GpRawPtrByteRW(iData, iSizeUsed.ValueAs<count_t>());
}

void    GpSecureStorage::ClearAndAllocate (const size_byte_t aSize, const size_byte_t aAlignment)
{
    Clear();

    THROW_GPE_COND_CHECK_M((aSize >= 1_byte) && (aSize <= 32768_byte), "aSize is out of range"_sv);
    THROW_GPE_COND_CHECK_M((aSize % aAlignment) == 0_byte, "Wrong size for alignment"_sv);

#if !defined(OS_BROWSER)
    iData = reinterpret_cast<std::byte*>(sodium_allocarray((aSize / aAlignment).ValueAs<size_t>(), aAlignment.ValueAs<size_t>()));
#else
    iData = reinterpret_cast<std::byte*>(std::aligned_alloc(aAlignment.ValueAs<size_t>(), aSize.ValueAs<size_t>()));
#endif

    THROW_GPE_COND_CHECK_M(iData != nullptr, "sodium_malloc return error"_sv);

    iSizeAllocated  = aSize;
    iAlignment      = aAlignment;

#if !defined(OS_BROWSER)
    if (sodium_mlock(iData, iSizeAllocated.ValueAs<size_t>()) != 0)
    {
        Clear();
        THROW_GPE("sodium_mlock return error"_sv);
    }
#endif//#if !defined(OS_BROWSER)
}

}//namespace GPlatform
