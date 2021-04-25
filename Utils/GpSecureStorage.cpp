#include "GpSecureStorage.hpp"

GP_WARNING_PUSH()
GP_WARNING_DISABLE(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

#include <cstdlib>

namespace GPlatform {

GpSecureStorage::GpSecureStorage (void) noexcept
{
}

GpSecureStorage::~GpSecureStorage (void) noexcept
{
    Clear();
}

void    GpSecureStorage::Clear (void)
{
    THROW_GPE_COND(IsViewing() == false, "Storage is viewing"_sv);

    if (iData != nullptr)
    {
        sodium_memzero(ViewRW().RW().PtrBegin(), iSizeAllocated.As<size_t>());

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
    //iIsViewing    = false;//THROW_GPE_COND(IsViewing() == false, "Storage is viewing"_sv);
}

void    GpSecureStorage::Resize (const size_byte_t aSize)
{
    Resize(aSize, iAlignment);
}

void    GpSecureStorage::Resize
(
    const size_byte_t aSize,
    const size_byte_t aAlignment
)
{
    Reserve(aSize, aAlignment);
    iSizeUsed = aSize;
}

void    GpSecureStorage::Reserve (const size_byte_t aSize)
{
    Reserve(aSize, iAlignment);
}

void    GpSecureStorage::Reserve
(
    const size_byte_t aSize,
    const size_byte_t aAlignment
)
{
    THROW_GPE_COND
    (
        IsViewing() == false,
        "Storage is viewing"_sv
    );

    if (IsDataNullptr())
    {
        ClearAndAllocate(aSize, aAlignment);
        LockRW();
        return;
    }

    THROW_GPE_COND
    (
        (Alignment() % aAlignment) == 0_byte,
        "Wrong alignment"_sv
    );

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

    THROW_GPE_COND
    (
        aStorage.IsViewing() == false,
        "aStorage is viewing"_sv
    );

    THROW_GPE_COND
    (
        IsViewing() == false,
        "Storage is viewing"_sv
    );

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

    THROW_GPE_COND
    (
        aStorage.IsViewing() == false,
        "aStorage is viewing"_sv
    );

    THROW_GPE_COND
    (
        IsViewing() == false,
        "Storage is viewing"_sv
    );

    THROW_GPE_COND
    (
        (Alignment() % aStorage.Alignment()) == 0_byte,
        "Wrong alignment"_sv
    );

    CopyFrom(aStorage.ViewR().R());
}

void    GpSecureStorage::CopyFrom (GpRawPtrByteR aData)
{
    Resize(aData.SizeLeft());
    ViewRW().RW().CopyFrom(aData);
}

GpSecureStorageViewR    GpSecureStorage::ViewR (void) const
{
    THROW_GPE_COND
    (
        IsViewing() == false,
        "Storage is viewing"_sv
    );

    return GpSecureStorageViewR(*this);
}

GpSecureStorageViewRW   GpSecureStorage::ViewRW (void)
{
    THROW_GPE_COND
    (
        IsViewing() == false,
        "Storage is viewing"_sv
    );

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
    THROW_GPE_COND
    (
        iIsViewing != aValue,
        "Same value"_sv
    );

    iIsViewing = aValue;
}

GpRawPtrByteR   GpSecureStorage::DataR (void) const
{
    return GpRawPtrByteR(iData, iSizeUsed.As<count_t>());
}

GpRawPtrByteRW  GpSecureStorage::DataRW (void)
{
    return GpRawPtrByteRW(iData, iSizeUsed.As<count_t>());
}

void    GpSecureStorage::ClearAndAllocate (const size_byte_t aSize, const size_byte_t aAlignment)
{
    Clear();

    THROW_GPE_COND
    (
        (aSize >= 1_byte) && (aSize <= 32768_byte),
        "aSize is out of range"_sv
    );

    THROW_GPE_COND
    (
        (aSize % aAlignment) == 0_byte,
        "Wrong size for alignment"_sv
    );

#if !defined(OS_BROWSER)
    iData = reinterpret_cast<std::byte*>(sodium_allocarray((aSize / aAlignment).As<size_t>(), aAlignment.As<size_t>()));
    THROW_GPE_COND
    (
        iData != nullptr,
        "sodium_malloc return nullptr"_sv
    );
#else
    //iData = reinterpret_cast<std::byte*>(aligned_alloc(aAlignment.As<size_t>(), aSize.As<size_t>()));
    //THROW_GPE_COND(iData != nullptr, "aligned_alloc return nullptr"_sv);

    iData = reinterpret_cast<std::byte*>(std::malloc(aSize.As<size_t>()));
    THROW_GPE_COND(iData != nullptr, "std::malloc return nullptr"_sv);
#endif

    iSizeAllocated  = aSize;
    iAlignment      = aAlignment;

#if !defined(OS_BROWSER)
    if (sodium_mlock(iData, iSizeAllocated.As<size_t>()) != 0)
    {
        Clear();
        THROW_GPE("sodium_mlock return error"_sv);
    }
#endif//#if !defined(OS_BROWSER)
}

}//namespace GPlatform
