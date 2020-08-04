#include "GpCryptoHash_Ripemd160.hpp"

#include "../ExtSources/ripemd160.hpp"

namespace GPlatform {

void    GpCryptoHash_Ripemd160::S_H (GpRawPtrByteR  aData,
                                     GpRawPtrByteRW aResOut)
{
    Ripemd160(aData, aResOut);
}

GpCryptoHash_Ripemd160::Res160T GpCryptoHash_Ripemd160::S_H (GpRawPtrByteR aData)
{
    Res160T res;
    GpRawPtrByteRW r(res);
    S_H(aData, r);
    return res;
}

}//namespace GPlatform
