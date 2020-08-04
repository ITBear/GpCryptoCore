#include "GpByteWriterStorageSecure.hpp"
#
namespace GPlatform {

GpByteWriterStorageSecure::~GpByteWriterStorageSecure (void) noexcept
{
}

void    GpByteWriterStorageSecure::AllocateNext (const size_byte_t aSize)
{
    const count_t sizeToWrite   = aSize.ValueAs<count_t>();
    const count_t left          = iDataOut.CountLeft();

    if (left >= sizeToWrite)
    {
        return;
    }

    const count_t used          = iDataOut.Offset();
    const count_t deltaToAdd    = sizeToWrite - left;
    const count_t newSize       = iOut.Size().ValueAs<count_t>() + deltaToAdd;

    {
        iViewRW.Release();
        iOut.Resize(newSize.ValueAs<size_byte_t>());
        iViewRW = iOut.ViewRW();
        iDataOut.Set(iViewRW.RW().PtrBegin(), newSize, used);
    }
}

}//namespace GPlatform
