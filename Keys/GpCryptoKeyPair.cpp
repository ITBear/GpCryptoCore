#include "GpCryptoKeyPair.hpp"

namespace GPlatform {

GpCryptoKeyPair::GpCryptoKeyPair (const TypeTE aType) noexcept:
iType(aType)
{
}

GpCryptoKeyPair::GpCryptoKeyPair (const TypeTE      aType,
                                  GpSecureStorage&& aPrivateBytes,
                                  GpBytesArray&&    aPublicBytes):
iType(aType),
iPrivateBytes(std::move(aPrivateBytes)),
iPublicBytes(std::move(aPublicBytes))
{
}

GpCryptoKeyPair::GpCryptoKeyPair (const GpCryptoKeyPair& aKeyPair):
iType(aKeyPair.iType),
iPrivateBytes(aKeyPair.iPrivateBytes),
iPublicBytes(aKeyPair.iPublicBytes)
{
}

GpCryptoKeyPair::GpCryptoKeyPair (GpCryptoKeyPair&& aKeyPair):
iType(std::move(aKeyPair.iType)),
iPrivateBytes(std::move(aKeyPair.iPrivateBytes)),
iPublicBytes(std::move(aKeyPair.iPublicBytes))
{
}

GpCryptoKeyPair::~GpCryptoKeyPair (void) noexcept
{
    Clear();
}

void    GpCryptoKeyPair::Clear (void) noexcept
{
    iPrivateBytes.Clear();
    iPublicBytes.clear();
}

GpSecureStorage GpCryptoKeyPair::ToPrivateBytesWithPrefix (void) const
{
    THROW_GPE_COND_CHECK_M(iPrivateBytes.Size() > 0_byte, "Keypair is empty"_sv);

    GpRawPtrByteR                   prefixPtr   = PrivateBytesPrefix();
    GpSecureStorageViewR            privateView = iPrivateBytes.ViewR();
    GpRawPtrByteR                   privatePtr  = privateView.R().Subrange(0_cnt, 32_cnt);

    const size_byte_t               resSize     = prefixPtr.SizeLeft() + privatePtr.SizeLeft();
    GpSecureStorage                 res;
    res.Resize(resSize);
    GpSecureStorageViewRW           resView     = res.ViewRW();
    GpByteWriterStorageFixedSize    resStorage(resView.RW());
    GpByteWriter                    resWriter(resStorage);

    resWriter.Bytes(prefixPtr);
    resWriter.Bytes(privatePtr);

    return res;
}

GpSecureStorage GpCryptoKeyPair::ToPrivateStrHexWithPrefix (void) const
{
    GpSecureStorage         privateData = ToPrivateBytesWithPrefix();
    GpSecureStorageViewR    privateView = privateData.ViewR();
    GpRawPtrByteR           privatePtr  = privateView.R();

    //Str hex data
    const size_byte_t       resSize = privatePtr.SizeLeft() * 2_byte;
    GpSecureStorage         res;
    res.Resize(resSize);

    StrOps::SFromBytes(privatePtr, res.ViewRW().RW());

    return res;
}

GpBytesArray    GpCryptoKeyPair::ToPublicBytesWithPrefix (void) const
{
    THROW_GPE_COND_CHECK_M(iPublicBytes.size() > 0, "Keypair is empty"_sv);

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

    StrOps::SFromBytes(publicData, res);

    return res;
}

void    GpCryptoKeyPair::SetKeys (GpRawPtrByteR aPrivateBytes,
                                  GpRawPtrByteR aPublicBytes)
{
    iPrivateBytes.ViewRW().RW().CopyFrom(aPrivateBytes);
    iPublicBytes = GpBytesArrayUtils::SMake(aPublicBytes);
}

void    GpCryptoKeyPair::SetKeys (GpSecureStorage&& aPrivateBytes,
                                  GpBytesArray&&    aPublicBytes)
{
    iPrivateBytes   = std::move(aPrivateBytes);
    iPublicBytes    = std::move(aPublicBytes);
}

}//namespace GPlatform
