#pragma once

#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHash_Sha2
{
    CLASS_REMOVE_CTRS(GpCryptoHash_Sha2)

public:
    using Res256T = GpArray<std::byte, 32>;
    using Res512T = GpArray<std::byte, 64>;

public:
    static void                     S_256       (GpRawPtrByteR  aData,
                                                 GpRawPtrByteRW aResOut);
    static Res256T                  S_256       (GpRawPtrByteR  aData);

    static void                     S_512       (GpRawPtrByteR  aData,
                                                 GpRawPtrByteRW aResOut);
    static Res512T                  S_512       (GpRawPtrByteR  aData);
};

}//GPlatform
