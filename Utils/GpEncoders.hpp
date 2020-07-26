#pragma once

#include "GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpEncoders
{
    CLASS_REMOVE_CTRS(GpEncoders)

public:
    static GpBytesArray     SBinToBase64    (GpRawPtrByteR aData);
    static GpBytesArray     SBase64toBin    (GpRawPtrByteR aData);
};

}//namespace GPlatform

