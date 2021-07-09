#pragma once

#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHash_Ripemd160
{
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoHash_Ripemd160)

public:
    using Res160T = GpArray<std::byte, 20>;

public:
    static void                 S_H (GpRawPtrByteR  aData,
                                     GpRawPtrByteRW aResOut);

    static Res160T              S_H (GpRawPtrByteR aData);
};

}//GPlatform
