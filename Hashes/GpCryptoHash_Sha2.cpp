#include "GpCryptoHash_Sha2.hpp"

GP_WARNING_PUSH()
GP_WARNING_DISABLE(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

void    GpCryptoHash_Sha2::S_256
(
    GpRawPtrByteR   aData,
    GpRawPtrByteRW  aResOut
)
{
    THROW_GPE_COND
    (
        aResOut.CountLeft() >= count_t::SMake(std::tuple_size<Res256T>::value),
        "aRes size too small"_sv
    );

    crypto_hash_sha256
    (
        aResOut.PtrAs<unsigned char*>(),
        aData.PtrAs<const unsigned char*>(),
        aData.CountLeft().As<size_t>()
    );
}

GpCryptoHash_Sha2::Res256T  GpCryptoHash_Sha2::S_256 (GpRawPtrByteR aData)
{
    Res256T res;
    GpRawPtrByteRW r(res);
    S_256(aData, r);
    return res;
}

void    GpCryptoHash_Sha2::S_512
(
    GpRawPtrByteR   aData,
    GpRawPtrByteRW  aResOut
)
{
    THROW_GPE_COND
    (
        aResOut.CountLeft() >= count_t::SMake(std::tuple_size<Res512T>::value),
        "aRes size too small"_sv
    );

    crypto_hash_sha512
    (
        aResOut.PtrAs<unsigned char*>(),
        aData.PtrAs<const unsigned char*>(),
        aData.CountLeft().As<size_t>()
    );
}

GpCryptoHash_Sha2::Res512T  GpCryptoHash_Sha2::S_512 (GpRawPtrByteR aData)
{
    Res512T res;
    GpRawPtrByteRW r(res);
    S_512(aData, r);
    return res;
}

}//namespace GPlatform
