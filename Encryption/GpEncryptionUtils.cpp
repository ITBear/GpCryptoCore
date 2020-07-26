#include "GpEncryptionUtils.hpp"
#include "../Utils/GpSecureStorage.hpp"
#include <libsodium/sodium.h>

namespace GPlatform {

//https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream

void    GpEncryptionUtils::SEncrypt (GpByteReader&  aReader,
                                     GpByteWriter&  aWriter,
                                     GpRawPtrByteR  aKey)
{
    constexpr size_byte_t CHUNK_SIZE = 4096_byte;
    GpArray<unsigned char, crypto_secretstream_xchacha20poly1305_HEADERBYTES>                           encryptHeader;
    GpArray<unsigned char, CHUNK_SIZE.ValueAs<size_t>() + crypto_secretstream_xchacha20poly1305_ABYTES> encryptChunk;

    crypto_secretstream_xchacha20poly1305_state encryptState;

    if (crypto_secretstream_xchacha20poly1305_init_push(&encryptState,
                                                        encryptHeader.data(),
                                                        aKey.PtrBeginAs<const unsigned char*>()) != 0)
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
        if (crypto_secretstream_xchacha20poly1305_push(&encryptState,
                                                       encryptChunk.data(),
                                                       &encryptChunkActualSize,
                                                       chunkPtr.PtrBeginAs<const unsigned char *>(),
                                                       chunkPtr.CountTotalV<size_t>(),
                                                       nullptr,
                                                       0,
                                                       tag) != 0)
        {
            THROW_GPE("crypto_secretstream_xchacha20poly1305_push return error"_sv);
        }

        // Write encrypted chunk
        aWriter.BytesWithLen({encryptChunk.data(), count_t::SMake(encryptChunkActualSize)});
    }
}

void    GpEncryptionUtils::SDecrypt (GpByteReader&  aReader,
                                     GpByteWriter&  aWriter,
                                     GpRawPtrByteR  aKey)
{
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
                                                        aKey.PtrBeginAs<const unsigned char*>()) != 0)
    {
        THROW_GPE("crypto_secretstream_xchacha20poly1305_init_pull return error"_sv);
    }

    // Read chunks
    while (aReader.SizeLeft() > 0_byte)
    {
        GpRawPtrByteR chunkPtr  = aReader.BytesWithLen();
        unsigned char tag       = 0;

        unsigned long long decryptChunkActualSize = decryptChunkPtr.CountTotalV<unsigned long long>();
        if (crypto_secretstream_xchacha20poly1305_pull(&encryptState,
                                                       decryptChunkPtr.PtrBeginAs<unsigned char*>(),
                                                       &decryptChunkActualSize,
                                                       &tag,
                                                       chunkPtr.PtrBeginAs<const unsigned char *>(),
                                                       chunkPtr.CountTotalV<size_t>(),
                                                       nullptr,
                                                       0) != 0)
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

}//GPlatform
