#pragma once

#include "../GpCryptoCore_global.hpp"

namespace GPlatform {

class GpSecureStorage;

class GPCRYPTOCORE_API GpSecureStorageViewRW
{
    friend class GpSecureStorage;

public:
    CLASS_REMOVE_CTRS_DEFAULT_COPY(GpSecureStorageViewRW)
    CLASS_DECLARE_DEFAULTS(GpSecureStorageViewRW)

    using StorageOptT = std::optional<std::reference_wrapper<GpSecureStorage>>;

private:
                                GpSecureStorageViewRW   (GpSecureStorage& aStorage);

public:
                                GpSecureStorageViewRW   (GpSecureStorageViewRW&& aView) noexcept;
                                ~GpSecureStorageViewRW  (void) noexcept;

    GpSecureStorageViewRW&      operator=               (GpSecureStorageViewRW&& aView);

    GpRawPtrByteR               R                       (void) const;
    GpRawPtrByteRW              RW                      (void);
    size_byte_t                 Size                    (void) const noexcept;
    bool                        IsEmpty                 (void) const noexcept {return Size() == 0_byte;}

    void                        Release                 (void);

private:
    StorageOptT                 iStorage;
};

}//namespace GPlatform
