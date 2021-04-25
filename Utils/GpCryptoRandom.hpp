#pragma once

#include "GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoRandom
{
    CLASS_REMOVE_CTRS(GpCryptoRandom)

public:
    static void                 SEntropy    (const size_byte_t  aSize,
                                             GpRawPtrByteRW     aResOut);
    static GpSecureStorage::SP  SEntropy    (const size_byte_t aSize);
};

}//namespace GPlatform
