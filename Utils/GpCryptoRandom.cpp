#include "GpCryptoRandom.hpp"

GP_WARNING_PUSH()
GP_WARNING_DISABLE(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

void    GpCryptoRandom::SEntropy
(
    const size_byte_t   aSize,
    GpRawPtrByteRW      aResOut
)
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

        aResOut.CopyFrom(reinterpret_cast<const std::byte*>(&randVal), bytesNeed.As<count_t>());

        aResOut.OffsetAdd(bytesNeed.As<count_t>());
        bytesLeft   -= bytesNeed;
    }
}

GpSecureStorage::SP GpCryptoRandom::SEntropy (const size_byte_t aSize)
{
    GpSecureStorage::SP entropySP   = MakeSP<GpSecureStorage>();
    GpSecureStorage&    entropy     = entropySP.V();
    entropy.Resize(aSize);

    GpSecureStorageViewRW   entropyView = entropy.ViewRW();
    GpRawPtrByteRW          entropyData = entropyView.RW();

    SEntropy(aSize, entropyData);

    return entropySP;
}

}//namespace GPlatform
