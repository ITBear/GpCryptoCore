#include "GpCryptoKeyPair.hpp"

namespace GPlatform {

GpCryptoKeyPair::GpCryptoKeyPair
(
    const TypeTE        aType,
    GpSecureStorage::SP aPrivateKey,
    GpBytesArray&&      aPublicKey
) noexcept:
iType(aType),
iPrivateKey(std::move(aPrivateKey)),
iPublicKey(std::move(aPublicKey))
{
}

GpCryptoKeyPair::~GpCryptoKeyPair (void) noexcept
{
    Clear();
}

void    GpCryptoKeyPair::Clear (void) noexcept
{
    iPublicKey.clear();
    iPrivateKey.Clear();
}

/*GpSecureStorage::SP   GpCryptoKeyPair::ToPrivateBytesWithPrefix (void) const
{
    const GpSecureStorage& privateBytes = PrivateBytes();

    THROW_GPE_COND
    (
        privateBytes.Size() > 0_byte,
        "Keypair is empty"_sv
    );

    GpRawPtrByteR                   prefixPtr   = PrivateBytesPrefix();
    GpSecureStorageViewR            privateView = privateBytes.ViewR();
    GpRawPtrByteR                   privatePtr  = privateView.R().Subrange(0_cnt, 32_cnt);

    const size_byte_t               resSize     = prefixPtr.SizeLeft() + privatePtr.SizeLeft();
    GpSecureStorage::SP             resSP       = MakeSP<GpSecureStorage>();
    GpSecureStorage&                res         = resSP.V();
    res.Resize(resSize);
    GpSecureStorageViewRW           resView     = res.ViewRW();
    GpByteWriterStorageFixedSize    resStorage(resView.RW());
    GpByteWriter                    resWriter(resStorage);

    resWriter.Bytes(prefixPtr);
    resWriter.Bytes(privatePtr);

    return resSP;
}

GpSecureStorage::SP GpCryptoKeyPair::ToPrivateStrHexWithPrefix (void) const
{
    GpSecureStorage::SP     privateData = ToPrivateBytesWithPrefix();
    GpSecureStorageViewR    privateView = privateData->ViewR();
    GpRawPtrByteR           privatePtr  = privateView.R();

    //Str hex data
    const size_byte_t       resSize = privatePtr.SizeLeft() * 2_byte;
    GpSecureStorage::SP     resSP   = MakeSP<GpSecureStorage>();
    GpSecureStorage&        res     = resSP.V();
    res.Resize(resSize);

    StrOps::SFromBytesHex(privatePtr, res.ViewRW().RW());

    return resSP;
}

GpBytesArray    GpCryptoKeyPair::ToPublicBytesWithPrefix (void) const
{
    THROW_GPE_COND
    (
        iPublicBytes.size() > 0,
        "Keypair is empty"_sv
    );

    GpRawPtrByteR                   prefixPtr   = PublicBytesPrefix();

    const size_byte_t               resSize     = prefixPtr.SizeLeft() + size_byte_t::SMake(iPublicBytes.size());
    GpBytesArray                    res;
    res.resize(resSize.As<size_t>());
    GpByteWriterStorageFixedSize    resStorage(res);
    GpByteWriter                    resWriter(resStorage);

    resWriter.Bytes(prefixPtr);
    resWriter.Bytes(iPublicBytes);

    return res;
}

GpBytesArray    GpCryptoKeyPair::ToPublicStrHexWithPrefix (void) const
{
    const GpBytesArray      publicData = ToPublicBytesWithPrefix();

    //Str hex data
    const size_byte_t       resSize = size_byte_t::SMake(publicData.size()) * 2_byte;
    GpBytesArray            res;
    res.resize(resSize.As<size_t>());

    StrOps::SFromBytesHex(publicData, res);

    return res;
}*/

}//namespace GPlatform
