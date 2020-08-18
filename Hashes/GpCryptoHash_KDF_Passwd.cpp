#include "GpCryptoHash_KDF_Passwd.hpp"
#include <libsodium/sodium.h>

namespace GPlatform {


GpSecureStorage GpCryptoHash_KDF_Passwd::S_H (GpRawPtrByteR         aPassword,
                                              GpRawPtrByteR         aSalt,
                                              const size_bit_t      aBitLengthDerivedKey,
                                              const size_mebibyte_t aMemoryLimit)
{
    THROW_GPE_COND_CHECK_M(   (aPassword.CountLeft() >= count_t::SMake(crypto_pwhash_PASSWD_MIN))
                           && (aPassword.CountLeft() <= count_t::SMake(crypto_pwhash_PASSWD_MAX)),
                           "Wrong password length"_sv);
    THROW_GPE_COND_CHECK_M(aSalt.CountLeft() == count_t::SMake(crypto_pwhash_SALTBYTES), "Wrong salt length (must be 16 bytes)"_sv);
    THROW_GPE_COND_CHECK_M(   (aBitLengthDerivedKey >= size_byte_t::SMake(crypto_pwhash_BYTES_MIN))
                           && (aBitLengthDerivedKey <= size_byte_t::SMake(crypto_pwhash_BYTES_MAX))
                           && (aBitLengthDerivedKey % 8_bit == 0_bit), "Wrong aBitLengthDerivedKey length"_sv);


    const size_byte_t derivedKeySize = size_byte_t(aBitLengthDerivedKey);

    GpSecureStorage derivedKey;
    derivedKey.Resize(derivedKeySize);

    //https://libsodium.gitbook.io/doc/password_hashing/default_phf
    if (crypto_pwhash(derivedKey.ViewRW().RW().PtrAs<unsigned char*>(),
                      derivedKeySize.ValueAs<size_t>(),
                      aPassword.PtrAs<const char*>(),
                      aPassword.CountLeftV<size_t>(),
                      aSalt.PtrAs<const unsigned char*>(),
                      3,//crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      aMemoryLimit.ValueAs<size_t>(),//crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0)
    {
        THROW_GPE("crypto_pwhash return error"_sv);
    }

    return derivedKey;
}

}//namespace
