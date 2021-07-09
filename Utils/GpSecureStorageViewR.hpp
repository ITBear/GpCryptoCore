#pragma once

#include "../GpCryptoCore_global.hpp"

namespace GPlatform {

class GpSecureStorage;

class GPCRYPTOCORE_API GpSecureStorageViewR
{
    friend class GpSecureStorage;

public:
    CLASS_REMOVE_CTRS_DEFAULT_COPY(GpSecureStorageViewR)
    CLASS_DECLARE_DEFAULTS(GpSecureStorageViewR)

    using StorageOptT = std::optional<std::reference_wrapper<const GpSecureStorage>>;

private:
                                GpSecureStorageViewR    (const GpSecureStorage& aStorage);

public:
                                GpSecureStorageViewR    (GpSecureStorageViewR&& aView) noexcept;
                                ~GpSecureStorageViewR   (void) noexcept;

    GpSecureStorageViewR&       operator=               (GpSecureStorageViewR&& aView);

    GpRawPtrByteR               R                       (void) const;

    size_byte_t                 Size                    (void) const noexcept;
    bool                        IsEmpty                 (void) const noexcept {return Size() == 0_byte;}

    void                        Release                 (void);

private:
    StorageOptT                 iStorage;
};

}//namespace GPlatform
