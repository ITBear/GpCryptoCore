#include "GpCryptoRandom.hpp"

#include <libsodium/sodium.h>

namespace GPlatform {

void    GpCryptoRandom::SEntropy (const size_byte_t aSize,
                                  GpRawPtrByteRW    aResOut)
{
    size_byte_t bytesLeft   = aSize;
    u_int_32    randVal     = 0;

    GpRAIIonDestruct randValDestructor([&]()
    {
        sodium_memzero(&randVal, sizeof(randVal));
    });

    while (bytesLeft > 0_byte)
    {
        const size_byte_t bytesNeed = std::min(size_byte_t::SMake(sizeof(u_int_32)), bytesLeft);

        randVal = randombytes_random();

        aResOut.CopyFrom(reinterpret_cast<const std::byte*>(&randVal), bytesNeed.ValueAs<count_t>());

        aResOut.OffsetAdd(bytesNeed.ValueAs<count_t>());
        bytesLeft   -= bytesNeed;
    }
}

GpSecureStorage GpCryptoRandom::SEntropy (const size_byte_t aSize)
{
    GpSecureStorage entropy;
    entropy.Allocate(aSize);

    GpSecureStorageViewRW   entropyView = entropy.ViewRW();
    GpRawPtrByteRW          entropyData = entropyView.RW();

    SEntropy(aSize, entropyData);

    return entropy;
}

}//namespace GPlatform
