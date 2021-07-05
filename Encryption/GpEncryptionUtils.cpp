#include "GpEncryptionUtils.hpp"
#include "../Hashes/GpCryptoHash_KDF_Passwd.hpp"
#include "../Utils/GpByteWriterStorageSecure.hpp"

GP_WARNING_PUSH()
GP_WARNING_DISABLE(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

GpBytesArray    GpEncryptionUtils::SEasyEncrypt
(
    GpRawPtrByteR   aSrcData,
    GpRawPtrCharR   aPassword,
    GpRawPtrCharR   aSalt
)
{
    GpSecureStorage::CSP key = SPasswordToKey(aPassword, aSalt);

    GpByteReaderStorage srcDataReaderStorage(aSrcData);
    GpByteReader        srcDataReader(srcDataReaderStorage);

    GpBytesArray encriptedData;
    encriptedData.reserve(aSrcData.SizeLeft().As<size_t>());

    GpByteWriterStorageByteArray    encriptedDataWriterStorage(encriptedData);
    GpByteWriter                    encriptedDataWriter(encriptedDataWriterStorage);

    GpEncryptionUtils::SEncrypt
    (
        srcDataReader,
        encriptedDataWriter,
        key.VC().ViewR().R()
    );

    return encriptedData;
}

GpSecureStorage::CSP    GpEncryptionUtils::SEasyDecrypt
(
    GpRawPtrByteR   aSrcData,
    GpRawPtrCharR   aPassword,
    GpRawPtrCharR   aSalt
)
{
    GpSecureStorage::CSP key = SPasswordToKey(aPassword, aSalt);

    GpByteReaderStorage srcDataReaderStorage(aSrcData);
    GpByteReader        srcDataReader(srcDataReaderStorage);

    GpSecureStorage::SP     decriptedDataSP = MakeSP<GpSecureStorage>();
    GpSecureStorage&        decriptedData   = decriptedDataSP.V();
    decriptedData.Reserve(aSrcData.SizeLeft());

    GpByteWriterStorageSecure   decriptedDataWriterStorage(decriptedData);
    GpByteWriter                decriptedDataWriter(decriptedDataWriterStorage);

    GpEncryptionUtils::SDecrypt
    (
        srcDataReader,
        decriptedDataWriter,
        key.VC().ViewR().R()
    );

    return decriptedDataSP;
}

void    GpEncryptionUtils::SEncrypt
(
    GpByteReader&   aReader,
    GpByteWriter&   aWriter,
    GpRawPtrByteR   aKey
)
{
    THROW_GPE_COND
    (
        aKey.CountLeft() >= count_t::SMake(crypto_secretstream_xchacha20poly1305_KEYBYTES),
        "Wrong key length"_sv
    );

    constexpr size_byte_t CHUNK_SIZE = 4096_byte;
    GpArray<unsigned char, crypto_secretstream_xchacha20poly1305_HEADERBYTES>                       encryptHeader;
    GpArray<unsigned char, CHUNK_SIZE.As<size_t>() + crypto_secretstream_xchacha20poly1305_ABYTES>  encryptChunk;

    crypto_secretstream_xchacha20poly1305_state encryptState;

    if (crypto_secretstream_xchacha20poly1305_init_push
        (
            &encryptState,
            encryptHeader.data(),
            aKey.PtrAs<const unsigned char*>()
        ) != 0)
    {
        THROW_GPE("crypto_secretstream_xchacha20poly1305_init_push return error"_sv);
    }

    // Write Header
    aWriter.BytesWithLen(encryptHeader);

    while (aReader.SizeLeft() > 0_byte)
    {
        GpRawPtrByteR chunkPtr = aReader.TryBytes(CHUNK_SIZE);

        // Encrypt
        const unsigned char tag = (aReader.SizeLeft() == 0_byte) ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;

        unsigned long long encryptChunkActualSize = NumOps::SConvert<unsigned long long>(encryptChunk.size());
        if (crypto_secretstream_xchacha20poly1305_push
            (
                &encryptState,
                encryptChunk.data(),
                &encryptChunkActualSize,
                chunkPtr.PtrBeginAs<const unsigned char *>(),
                chunkPtr.CountTotal().As<size_t>(),
                nullptr,
                0,
                tag
            ) != 0)
        {
            THROW_GPE("crypto_secretstream_xchacha20poly1305_push return error"_sv);
        }

        // Write encrypted chunk
        aWriter.BytesWithLen({encryptChunk.data(), count_t::SMake(encryptChunkActualSize)});
    }
}

void    GpEncryptionUtils::SDecrypt
(
    GpByteReader&   aReader,
    GpByteWriter&   aWriter,
    GpRawPtrByteR   aKey
)
{
    THROW_GPE_COND
    (
        aKey.CountLeft() >= count_t::SMake(crypto_secretstream_xchacha20poly1305_KEYBYTES),
        "Wrong key length"_sv
    );

    constexpr size_byte_t CHUNK_SIZE = 4096_byte;
    GpArray<unsigned char, crypto_secretstream_xchacha20poly1305_HEADERBYTES>   encryptHeader;
    GpRawPtrByteRW                                                              encryptHeaderPtr(encryptHeader);
    GpSecureStorage                                                             decryptChunk;
    decryptChunk.Resize(CHUNK_SIZE + size_byte_t::SMake(crypto_secretstream_xchacha20poly1305_ABYTES));
    GpSecureStorageViewRW   decryptChunkViewRW  = decryptChunk.ViewRW();
    GpRawPtrByteRW          decryptChunkPtr     = decryptChunkViewRW.RW();

    crypto_secretstream_xchacha20poly1305_state encryptState;

    // Read Header
    encryptHeaderPtr.CopyFrom(aReader.Bytes(size_byte_t::SMake(encryptHeader.size())));

    if (crypto_secretstream_xchacha20poly1305_init_pull(&encryptState,
                                                        encryptHeaderPtr.PtrBeginAs<const unsigned char*>(),
                                                        aKey.PtrAs<const unsigned char*>()) != 0)
    {
        THROW_GPE("crypto_secretstream_xchacha20poly1305_init_pull return error"_sv);
    }

    // Read chunks
    while (aReader.SizeLeft() > 0_byte)
    {
        GpRawPtrByteR chunkPtr  = aReader.BytesWithLen();
        unsigned char tag       = 0;

        unsigned long long decryptChunkActualSize = decryptChunkPtr.CountTotal().As<unsigned long long>();
        if (crypto_secretstream_xchacha20poly1305_pull
            (
                &encryptState,
                decryptChunkPtr.PtrBeginAs<unsigned char*>(),
                &decryptChunkActualSize,
                &tag,
                chunkPtr.PtrBeginAs<const unsigned char *>(),
                chunkPtr.CountTotal().As<size_t>(),
                nullptr,
                0
            ) != 0)
        {
            THROW_GPE("crypto_secretstream_xchacha20poly1305_pull return error"_sv);
        }

        if (   (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
            && (aReader.SizeLeft() > 0_byte))
        {
            THROW_GPE("end of file reached before the end of the stream"_sv);
        }

        // Write decrypted chunk
        aWriter.Bytes(decryptChunkPtr.Subrange(0_cnt, count_t::SMake(decryptChunkActualSize)));
    }
}

GpSecureStorage::CSP    GpEncryptionUtils::SPasswordToKey
(
    GpRawPtrCharR aPassword,
    GpRawPtrCharR aSalt
)
{
    return GpCryptoHash_KDF_Passwd::S_H(aPassword, aSalt, 32_byte, 32_MiB);
}

}//GPlatform
