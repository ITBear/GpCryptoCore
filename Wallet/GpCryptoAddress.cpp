#include "GpCryptoAddress.hpp"

namespace GPlatform {

GpCryptoAddress::GpCryptoAddress
(
    const GpUUID&           aUID,
    GpCryptoKeyPair::CSP    aKeyPair
) noexcept:
iUID(aUID),
iKeyPair(std::move(aKeyPair))
{   
}

GpCryptoAddress::~GpCryptoAddress (void) noexcept
{
    iKeyPair.Clear();
}

GpBytesArray    GpCryptoAddress::SignData (GpRawPtrByteR aData) const
{
    return iKeyPair->Sign(aData);
}

bool    GpCryptoAddress::VerifySign
(
    GpRawPtrByteR   aData,
    GpRawPtrByteR   aSign
) const
{
    return iKeyPair->VerifySign(aData, aSign);
}

void    GpCryptoAddress::RecalcAddrStr (void)
{
    auto res = OnRecalcAddrStr();

    iAddr       = std::get<0>(res);
    iAddrStr    = std::get<1>(res);
}

}//namespace GPlatform
