#pragma once

#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHash_KDF_Passwd
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoHash_KDF_Passwd)

public:
    static GpSecureStorage::CSP S_H (GpRawPtrByteR          aPassword,
                                     GpRawPtrByteR          aSalt,
                                     const size_bit_t       aBitLengthDerivedKey,
                                     const size_mibyte_t    aMemoryLimit = 32_MiB);

};

}//GPlatform
