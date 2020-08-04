#pragma once

#include "../GpCryptoCore_global.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpEncryptionUtils
{
public:
    CLASS_REMOVE_CTRS(GpEncryptionUtils)

public:
    static void     SEncrypt        (GpByteReader&  aReader,
                                     GpByteWriter&  aWriter,
                                     GpRawPtrByteR  aKey);
    static void     SDecrypt        (GpByteReader&  aReader,
                                     GpByteWriter&  aWriter,
                                     GpRawPtrByteR  aKey);
};

}//GPlatform
