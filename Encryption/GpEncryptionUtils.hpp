#pragma once

#include "../GpCryptoCore_global.hpp"
#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpEncryptionUtils
{
public:
    CLASS_REMOVE_CTRS(GpEncryptionUtils)

public:
    static GpBytesArray     SEasyEncrypt    (GpRawPtrByteR  aSrcData,
                                             GpRawPtrCharR  aPassword,
                                             GpRawPtrCharR  aSalt);

    static GpSecureStorage  SEasyDecrypt    (GpRawPtrByteR  aSrcData,
                                             GpRawPtrCharR  aPassword,
                                             GpRawPtrCharR  aSalt);

    static void             SEncrypt        (GpByteReader&  aReader,
                                             GpByteWriter&  aWriter,
                                             GpRawPtrByteR  aKey);

    static void             SDecrypt        (GpByteReader&  aReader,
                                             GpByteWriter&  aWriter,
                                             GpRawPtrByteR  aKey);

    static GpSecureStorage  SPasswordToKey  (GpRawPtrCharR  aPassword,
                                             GpRawPtrCharR  aSalt);
};

}//GPlatform
