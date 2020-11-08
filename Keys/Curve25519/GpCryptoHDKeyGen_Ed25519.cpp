#include "GpCryptoHDKeyGen_Ed25519.hpp"
#include "../../Hashes/GpCryptoHash_Hmac.hpp"
#include "../../Hashes/GpCryptoHash_Ripemd160.hpp"
#include "GpCryptoKeyPair_Ed25519.hpp"

namespace GPlatform {

GpCryptoHDKeyStorage    GpCryptoHDKeyGen_Ed25519::SMasterKeyPairFromSeed (GpRawPtrByteR aSeed)
{
    GpSecureStorage valI;
    valI.Resize(512_bit);

    GpCryptoHash_Hmac::S_512(aSeed,
                             "ed25519 seed"_sv,
                             valI.ViewRW().RW());

    GpSecureStorageViewR    valIViewR   = valI.ViewR();
    GpRawPtrByteR           valIViewPtr = valIViewR.R();
    GpRawPtrByteR           valIL       = valIViewPtr.Subrange(0_cnt, 32_cnt);
    GpRawPtrByteR           valIR       = valIViewPtr.Subrange(32_cnt, 32_cnt);

    GpSecureStorage chainCode;
    GpSecureStorage privateData;

    chainCode.CopyFrom(valIR);
    privateData.CopyFrom(valIL);

    return GpCryptoHDKeyStorage(GpCryptoHDSchemeType::SLIP10_ED25519,
                                std::move(chainCode),
                                std::move(privateData));
}

GpCryptoHDKeyStorage    GpCryptoHDKeyGen_Ed25519::SChildKeyPair (const GpCryptoHDKeyStorage&    aParentHDKeyStorage,
                                                                 const count_t                  aChildId)
{
    THROW_GPE_COND_CHECK_M(aParentHDKeyStorage.SchemeType() == GpCryptoHDSchemeType::SLIP10_ED25519,
                           "HD scheme type must be SLIP10_ED25519"_sv);

    //SLIP10_ED25519 only supports hardened keys
    const count_t childCode = aChildId + count_t::SMake(0x80000000);

    GpSecureStorage sourceData;

    //Always hardened
    {
        sourceData.Resize(1_byte + 32_byte + 4_byte);
        GpSecureStorageViewRW           sourceDataViewRW = sourceData.ViewRW();
        GpByteWriterStorageFixedSize    sourceDataStorage(sourceDataViewRW.RW());
        GpByteWriter                    sourceDataWriter(sourceDataStorage);

        sourceDataWriter.UInt8(0);
        sourceDataWriter.Bytes(aParentHDKeyStorage.KeyData().ViewR().R());
        sourceDataWriter.UInt32(childCode.As<u_int_32>());
    }

    GpSecureStorage valI;
    valI.Resize(512_bit);

    GpCryptoHash_Hmac::S_512(sourceData.ViewR().R(),
                             aParentHDKeyStorage.ChainCode().ViewR().R(),
                             valI.ViewRW().RW());

    GpSecureStorageViewR    valIViewR   = valI.ViewR();
    GpRawPtrByteR           valIViewPtr = valIViewR.R();
    GpRawPtrByteR           valIL       = valIViewPtr.Subrange(0_cnt, 32_cnt);
    GpRawPtrByteR           valIR       = valIViewPtr.Subrange(32_cnt, 32_cnt);

    GpSecureStorage chainCode;
    GpSecureStorage privateData;

    chainCode.CopyFrom(valIR);
    privateData.CopyFrom(valIL);

    return GpCryptoHDKeyStorage(GpCryptoHDSchemeType::SLIP10_ED25519,
                                std::move(chainCode),
                                std::move(privateData));
}

}//GPlatform
