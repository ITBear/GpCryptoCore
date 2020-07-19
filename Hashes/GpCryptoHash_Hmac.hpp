#pragma once

#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHash_Hmac
{
    CLASS_REMOVE_CTRS(GpCryptoHash_Hmac)

public:
    using Res256T = GpArray<std::byte, 32>;
    using Res512T = GpArray<std::byte, 64>;

public:
    static void                     S_256       (GpRawPtrByteR  aData,
                                                 GpRawPtrByteR  aKey,
                                                 GpRawPtrByteRW aResOut);

    static Res256T                  S_256       (GpRawPtrByteR  aData,
                                                 GpRawPtrByteR  aKey);

    static void                     S_512       (GpRawPtrByteR  aData,
                                                 GpRawPtrByteR  aKey,
                                                 GpRawPtrByteRW aResOut);

    static Res512T                  S_512       (GpRawPtrByteR  aData,
                                                 GpRawPtrByteR  aKey);
};

}//GPlatform
