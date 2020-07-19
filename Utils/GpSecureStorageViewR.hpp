#pragma once

#include "../GpCryptoCore_global.hpp"

namespace GPlatform {

class GpSecureStorage;

class GPCRYPTOCORE_API GpSecureStorageViewR
{
    friend class GpSecureStorage;

public:
    CLASS_REMOVE_CTRS_EXCEPT_MOVE(GpSecureStorageViewR)
    CLASS_DECLARE_DEFAULTS(GpSecureStorageViewR)

    using StorageOptT = std::optional<std::reference_wrapper<const GpSecureStorage>>;

private:
                                GpSecureStorageViewR    (const GpSecureStorage& aStorage);

public:
                                GpSecureStorageViewR    (GpSecureStorageViewR&& aView) noexcept;
                                ~GpSecureStorageViewR   (void) noexcept;

    GpRawPtrByteR               R                       (void) const;

    size_byte_t                 Size                    (void) const noexcept;
    bool                        IsEmpty                 (void) const noexcept;

private:
    StorageOptT                 iStorage;
};

}//namespace GPlatform
