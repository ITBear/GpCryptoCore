#pragma once

#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHash_PBKDF2
{
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoHash_PBKDF2)

public:
    static GpSecureStorage::CSP     S_HmacSHA512    (GpRawPtrByteR      aPassword,
                                                     GpRawPtrByteR      aSalt,
                                                     const count_t      aIterations,
                                                     const size_bit_t   aBitLengthDerivedKey);
    static GpSecureStorage::CSP     S_HmacSHA256    (GpRawPtrByteR      aPassword,
                                                     GpRawPtrByteR      aSalt,
                                                     const count_t      aIterations,
                                                     const size_bit_t   aBitLengthDerivedKey);
};

}//GPlatform
