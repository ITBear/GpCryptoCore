#include "GpCryptoHash_Blake2b.hpp"
#include <libsodium/sodium.h>

namespace GPlatform {

void    GpCryptoHash_Blake2b::S_256 (GpRawPtrByteR                  aData,
                                     std::optional<GpRawPtrByteR>   aKey,
                                     GpRawPtrByteRW                 aResOut)
{
    THROW_GPE_COND_CHECK_M(aResOut.CountLeft() >= count_t::SMake(std::tuple_size<Res256T>::value), "aRes size too small");

    unsigned char*          resDataPtr  = aResOut.PtrAs<unsigned char*>();
    constexpr size_t        resDataSize = std::tuple_size<Res256T>::value;
    const unsigned char*    dataPtr     = (aData.PtrAs<const unsigned char*>());
    const size_t            dataSize    = aData.CountLeftV<size_t>();
    const unsigned char*    keyPtr      = nullptr;
    size_t                  keySize     = 0;

    if (aKey.has_value())
    {
        GpRawPtrByteR& k = aKey.value();
        keyPtr  = k.PtrAs<const unsigned char*>();
        keySize = k.CountLeftV<size_t>();
    }

    crypto_generichash_blake2b(resDataPtr, resDataSize, dataPtr, dataSize, keyPtr, keySize);
}

GpCryptoHash_Blake2b::Res256T   GpCryptoHash_Blake2b::S_256 (GpRawPtrByteR                  aData,
                                                             std::optional<GpRawPtrByteR>   aKey)
{
    Res256T res;
    GpRawPtrByteRW r(res);
    S_256(aData, aKey, r);
    return res;
}

}//namespace GPlatform
