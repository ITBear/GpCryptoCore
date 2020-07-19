#include "GpCryptoHash_Sha2.hpp"
#include <libsodium/sodium.h>

namespace GPlatform {

void    GpCryptoHash_Sha2::S_256 (GpRawPtrByteR     aData,
                                  GpRawPtrByteRW    aResOut)
{
    THROW_GPE_COND_CHECK_M(aResOut.CountLeft() >= count_t::SMake(std::tuple_size<Res256T>::value), "aRes size too small");

    crypto_hash_sha256(aResOut.PtrAs<unsigned char*>(),
                       aData.PtrAs<const unsigned char*>(),
                       aData.CountLeftV<size_t>());
}

GpCryptoHash_Sha2::Res256T  GpCryptoHash_Sha2::S_256 (GpRawPtrByteR aData)
{
    Res256T res;
    GpRawPtrByteRW r(res);
    S_256(aData, r);
    return res;
}

void    GpCryptoHash_Sha2::S_512 (GpRawPtrByteR     aData,
                                  GpRawPtrByteRW    aResOut)
{
    THROW_GPE_COND_CHECK_M(aResOut.CountLeft() >= count_t::SMake(std::tuple_size<Res512T>::value), "aRes size too small");

    crypto_hash_sha512(aResOut.PtrAs<unsigned char*>(),
                       aData.PtrAs<const unsigned char*>(),
                       aData.CountLeftV<size_t>());
}

GpCryptoHash_Sha2::Res512T  GpCryptoHash_Sha2::S_512 (GpRawPtrByteR aData)
{
    Res512T res;
    GpRawPtrByteRW r(res);
    S_512(aData, r);
    return res;
}

}//namespace GPlatform
