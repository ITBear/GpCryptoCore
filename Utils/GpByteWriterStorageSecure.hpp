#pragma once

#include "GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpByteWriterStorageSecure final: public GpByteWriterStorage
{
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpByteWriterStorageSecure)

public:
    inline                  GpByteWriterStorageSecure   (GpSecureStorage& aOut) noexcept;
    virtual                 ~GpByteWriterStorageSecure  (void) noexcept override final;

    virtual void            AllocateNext                (const size_byte_t aSize) override final;

private:
    GpSecureStorageViewRW   iViewRW;
    GpSecureStorage&        iOut;   
};

GpByteWriterStorageSecure::GpByteWriterStorageSecure (GpSecureStorage& aOut) noexcept:
GpByteWriterStorage(aOut.ViewRW().RW()),
iViewRW(aOut.ViewRW()),
iOut(aOut)
{
}

}//GPlatform
