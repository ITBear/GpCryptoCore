#pragma once

#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHash_PBKDF2
{
    CLASS_REMOVE_CTRS(GpCryptoHash_PBKDF2)

public:
    static GpSecureStorage::SP      S_HmacSHA512    (GpRawPtrByteR      aPassword,
                                                     GpRawPtrByteR      aSalt,
                                                     const count_t      aIterations,
                                                     const size_bit_t   aBitLengthDerivedKey);
    static GpSecureStorage::SP      S_HmacSHA256    (GpRawPtrByteR      aPassword,
                                                     GpRawPtrByteR      aSalt,
                                                     const count_t      aIterations,
                                                     const size_bit_t   aBitLengthDerivedKey);
};

}//GPlatform
