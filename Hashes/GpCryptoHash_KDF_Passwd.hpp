#pragma once

#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHash_KDF_Passwd
{
public:
    CLASS_REMOVE_CTRS(GpCryptoHash_KDF_Passwd)

public:
    static GpSecureStorage      S_H (GpRawPtrByteR          aPassword,
                                     GpRawPtrByteR          aSalt,
                                     const size_bit_t       aBitLengthDerivedKey,
                                     const size_mebibyte_t  aMemoryLimit = 32_MiB);

};

}//GPlatform
