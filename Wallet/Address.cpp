#include "Address.hpp"

namespace GPlatform {

Address::Address
(
    std::string&&           aName,
    GpCryptoKeyPair::CSP    aKeyPair
) noexcept:
iName(std::move(aName)),
iKeyPair(std::move(aKeyPair))
{   
}

Address::~Address (void) noexcept
{
    iKeyPair.Clear();
}

GpBytesArray    Address::SignData (GpRawPtrByteR aData) const
{
    return iKeyPair->Sign(aData);
}

bool    Address::VerifySign
(
    GpRawPtrByteR   aData,
    GpRawPtrByteR   aSign
) const
{
    return iKeyPair->VerifySign(aData, aSign);
}

}//namespace GPlatform
