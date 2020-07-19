#pragma once

#include "GpSecureStorageViewR.hpp"
#include "GpSecureStorageViewRW.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpSecureStorage
{
    friend class GpSecureStorageViewR;
    friend class GpSecureStorageViewRW;

public:
    CLASS_DECLARE_DEFAULTS(GpSecureStorage)

public:
                                GpSecureStorage     (void) noexcept;
                                GpSecureStorage     (const GpSecureStorage& aStorage);
                                GpSecureStorage     (GpSecureStorage&& aStorage);
    explicit                    GpSecureStorage     (GpRawPtrByteR aData);
                                ~GpSecureStorage    (void) noexcept;

    GpSecureStorage&            operator=           (const GpSecureStorage& aStorage);
    GpSecureStorage&            operator=           (GpSecureStorage&& aStorage);

    void                        Clear               (void);
    void                        Allocate            (const size_byte_t aSize);
    void                        Allocate            (const count_t aElementsCount, const size_byte_t aElementSize);
    void                        Resize              (const size_byte_t aSize);
    size_byte_t                 Size                (void) const noexcept {return iSize;}
    bool                        IsEmpty             (void) const noexcept {return (iData == nullptr) || (iSize == 0_byte);}
    bool                        IsViewing           (void) const noexcept {return iIsViewing;}

    void                        CopyFrom            (const GpSecureStorage& aStorage);
    void                        Set                 (GpSecureStorage&& aStorage);
    void                        CopyFrom            (GpRawPtrByteR aData);
    void                        CopyFrom            (GpRawPtrByteRW aData);

    GpSecureStorageViewR        ViewR               (void) const;
    GpSecureStorageViewRW       ViewRW              (void);

protected:
    void                        LockRW              (void) const;
    void                        UnlockRW            (void);
    void                        UnlockR             (void) const;
    void                        SetViewing          (const bool aValue) const noexcept {iIsViewing = aValue;}
    GpRawPtrByteR               DataR               (void) const;
    GpRawPtrByteRW              DataRW              (void);

private:
    std::byte*                  iData           = nullptr;
    size_byte_t                 iSize           = 0_byte;
    mutable bool                iIsViewing      = false;
    bool                        iIsEnableResize = true;
};

}//namespace GPlatform
