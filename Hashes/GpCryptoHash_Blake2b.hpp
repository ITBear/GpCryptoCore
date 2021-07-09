#pragma once

#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHash_Blake2b
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoHash_Blake2b)

public:
    using Res256T = GpArray<std::byte, 32>;

public:
    static void                 S_256   (GpRawPtrByteR                  aData,
                                         std::optional<GpRawPtrByteR>   aKey,
                                         GpRawPtrByteRW                 aResOut);

    static Res256T              S_256   (GpRawPtrByteR                  aData,
                                         std::optional<GpRawPtrByteR>   aKey = std::nullopt);
};

}//GPlatform
