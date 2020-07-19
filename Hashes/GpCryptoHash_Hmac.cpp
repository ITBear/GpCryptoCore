#include "GpCryptoHash_Hmac.hpp"

#include <libsodium/sodium.h>

namespace GPlatform {

void    GpCryptoHash_Hmac::S_256 (GpRawPtrByteR     aData,
                                  GpRawPtrByteR     aKey,
                                  GpRawPtrByteRW    aResOut)
{
    THROW_GPE_COND_CHECK_M(aResOut.CountLeft() >= count_t::SMake(std::tuple_size<Res256T>::value), "aRes size too small");

    crypto_auth_hmacsha256_state hCtx;
    GpRAIIonDestruct hCtxDestructor([&]()
    {
        sodium_memzero(&hCtx, sizeof(hCtx));
    });

    crypto_auth_hmacsha256_init(&hCtx,
                                aKey.PtrAs<const unsigned char*>(),
                                aKey.CountLeftV<size_t>());
    crypto_auth_hmacsha256_update(&hCtx,
                                  aData.PtrAs<const unsigned char*>(),
                                  aData.CountLeftV<size_t>());
    crypto_auth_hmacsha256_final(&hCtx,
                                 aResOut.PtrAs<unsigned char*>());
}

GpCryptoHash_Hmac::Res256T  GpCryptoHash_Hmac::S_256 (GpRawPtrByteR aData,
                                                      GpRawPtrByteR aKey)
{
    Res256T res;
    GpRawPtrByteRW r(res);
    S_256(aData, aKey, r);
    return res;
}

void    GpCryptoHash_Hmac::S_512 (GpRawPtrByteR     aData,
                                  GpRawPtrByteR     aKey,
                                  GpRawPtrByteRW    aResOut)
{
    THROW_GPE_COND_CHECK_M(aResOut.CountLeft() >= count_t::SMake(std::tuple_size<Res512T>::value), "aRes size too small");

    crypto_auth_hmacsha512_state hCtx;
    GpRAIIonDestruct hCtxDestructor([&]()
    {
        sodium_memzero(&hCtx, sizeof(hCtx));
    });

    crypto_auth_hmacsha512_init(&hCtx,
                                aKey.PtrAs<const unsigned char*>(),
                                aKey.CountLeftV<size_t>());
    crypto_auth_hmacsha512_update(&hCtx,
                                  aData.PtrAs<const unsigned char*>(),
                                  aData.CountLeftV<size_t>());
    crypto_auth_hmacsha512_final(&hCtx,
                                 aResOut.PtrAs<unsigned char*>());
}

GpCryptoHash_Hmac::Res512T  GpCryptoHash_Hmac::S_512 (GpRawPtrByteR aData,
                                                      GpRawPtrByteR aKey)
{
    Res512T res;
    GpRawPtrByteRW r(res);
    S_512(aData, aKey, r);
    return res;
}

}//namespace GPlatform
