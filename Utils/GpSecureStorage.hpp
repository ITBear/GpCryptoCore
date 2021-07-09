#pragma once

#include "GpSecureStorageViewR.hpp"
#include "GpSecureStorageViewRW.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpSecureStorage
{
    friend class GpSecureStorageViewR;
    friend class GpSecureStorageViewRW;

public:
    CLASS_REMOVE_CTRS_MOVE_COPY(GpSecureStorage);
    CLASS_DECLARE_DEFAULTS(GpSecureStorage)

public:
                                GpSecureStorage     (void) noexcept;
                                ~GpSecureStorage    (void) noexcept;

    void                        Clear               (void);
    void                        Resize              (const size_byte_t aSize);
    void                        Resize              (const size_byte_t aSize, const size_byte_t aAlignment);
    void                        Reserve             (const size_byte_t aSize);
    void                        Reserve             (const size_byte_t aSize, const size_byte_t aAlignment);
    size_byte_t                 Size                (void) const noexcept {return iSizeUsed;}
    size_byte_t                 Alignment           (void) const noexcept {return iAlignment;}
    bool                        IsDataNullptr       (void) const noexcept {return iData == nullptr;}
    bool                        IsViewing           (void) const noexcept {return iIsViewing;}

    void                        Set                 (GpSecureStorage&& aStorage);
    void                        CopyFrom            (const GpSecureStorage& aStorage);
    void                        CopyFrom            (GpRawPtrByteR aData);

    GpSecureStorageViewR        ViewR               (void) const;
    GpSecureStorageViewRW       ViewRW              (void);

protected:
    void                        LockRW              (void) const;
    void                        UnlockRW            (void);
    void                        UnlockR             (void) const;
    void                        SetViewing          (const bool aValue) const;
    GpRawPtrByteR               DataR               (void) const;
    GpRawPtrByteRW              DataRW              (void);

private:
    void                        ClearAndAllocate    (const size_byte_t aSize, const size_byte_t aAlignment);

private:
    std::byte*                  iData           = nullptr;
    size_byte_t                 iSizeUsed       = 0_byte;
    size_byte_t                 iSizeAllocated  = 0_byte;
    size_byte_t                 iAlignment      = 1_byte;
    mutable bool                iIsViewing      = false;
};

}//namespace GPlatform
