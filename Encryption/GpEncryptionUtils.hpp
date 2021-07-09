#pragma once

#include "../GpCryptoCore_global.hpp"
#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpEncryptionUtils
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpEncryptionUtils)

public:
    static GpBytesArray         SEasyEncrypt    (GpRawPtrByteR  aSrcData,
                                                 GpRawPtrCharR  aPassword,
                                                 GpRawPtrCharR  aSalt);

    static GpSecureStorage::CSP SEasyDecrypt    (GpRawPtrByteR  aSrcData,
                                                 GpRawPtrCharR  aPassword,
                                                 GpRawPtrCharR  aSalt);

    static void                 SEncrypt        (GpByteReader&  aReader,
                                                 GpByteWriter&  aWriter,
                                                 GpRawPtrByteR  aKey);

    static void                 SDecrypt        (GpByteReader&  aReader,
                                                 GpByteWriter&  aWriter,
                                                 GpRawPtrByteR  aKey);

    static GpSecureStorage::CSP SPasswordToKey  (GpRawPtrCharR  aPassword,
                                                 GpRawPtrCharR  aSalt);
};

}//GPlatform
