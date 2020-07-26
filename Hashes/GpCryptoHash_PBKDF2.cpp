#include "GpCryptoHash_PBKDF2.hpp"
#include <libsodium/sodium.h>

namespace GPlatform {

GpSecureStorage GpCryptoHash_PBKDF2::S_HmacSHA512 (GpRawPtrByteR    aPassword,
                                                   GpRawPtrByteR    aSalt,
                                                   const count_t    aIterations,
                                                   const size_bit_t aBitLengthDerivedKey)
{
    THROW_GPE_COND_CHECK_M(aPassword.CountLeft() > 0_cnt, "Wrong password length"_sv);
    THROW_GPE_COND_CHECK_M(aSalt.CountLeft() > 0_cnt, "Wrong salt length"_sv);
    THROW_GPE_COND_CHECK_M(   (aBitLengthDerivedKey > 0_bit)
                           && (aBitLengthDerivedKey % 8_bit == 0_bit)
                           && (aBitLengthDerivedKey <= 0x1fffffffe0_bit), "Wrong aBitLengthDerivedKey length"_sv);

    const size_byte_t   derivedKeySize      = size_byte_t(aBitLengthDerivedKey);
    size_byte_t         derivedKeyLeftBytes = derivedKeySize;

    GpSecureStorage derivedKey;
    derivedKey.Resize(derivedKeySize);
    GpSecureStorageViewRW   derivedKeyViewRW    = derivedKey.ViewRW();
    GpRawPtrByteRW          derivedKeyPtrRW     = derivedKeyViewRW.RW();

    GpSecureStorage buf_U_T;
    constexpr size_byte_t sizeU = size_byte_t::SMake(crypto_auth_hmacsha512_BYTES);
    constexpr size_byte_t sizeT = size_byte_t::SMake(crypto_auth_hmacsha512_BYTES);
    buf_U_T.Resize(sizeU + sizeT);
    GpSecureStorageViewRW   buf_U_T_KeyViewRW   = buf_U_T.ViewRW();
    GpRawPtrByteRW          buf_U_T_KeyPtrRW    = buf_U_T_KeyViewRW.RW();
    GpRawPtrByteRW          dataU               = buf_U_T_KeyPtrRW.Subrange(0_cnt, sizeU.ValueAs<count_t>());
    GpRawPtrByteRW          dataT               = buf_U_T_KeyPtrRW.Subrange(sizeU.ValueAs<count_t>(), sizeT.ValueAs<count_t>());

    crypto_auth_hmacsha512_state pshCtx, hCtx;
    GpRAIIonDestruct hCtxDestructor([&]()
    {
        sodium_memzero(&pshCtx, sizeof(pshCtx));
        sodium_memzero(&hCtx, sizeof(hCtx));
    });

    crypto_auth_hmacsha512_init(&pshCtx, aPassword.PtrAs<const unsigned char*>(), aPassword.SizeLeftV<size_t>());
    crypto_auth_hmacsha512_update(&pshCtx, aSalt.PtrAs<const unsigned char*>(), aSalt.SizeLeftV<size_t>());

    count_t partsCount = (derivedKeySize / sizeT).ValueAs<count_t>();
    if ((derivedKeySize % sizeT) > 0_byte)
    {
        partsCount++;
    }

    for (count_t partId = 0_cnt; partId < partsCount; partId++)
    {
        u_int_32 ivecVal = (partId + 1_cnt).ValueAs<u_int_32>();
        ivecVal = BitOps::H2N(ivecVal);

        MemOps::SCopy(hCtx, pshCtx);
        crypto_auth_hmacsha512_update(&hCtx, reinterpret_cast<const unsigned char*>(&ivecVal), sizeof(ivecVal));
        crypto_auth_hmacsha512_final(&hCtx, dataU.PtrAs<unsigned char*>());

        dataT.CopyFrom(dataU);

        for (count_t j = 2_cnt; j <= aIterations; j++)
        {
            crypto_auth_hmacsha512_init(&hCtx, aPassword.PtrAs<const unsigned char*>(), aPassword.SizeLeftV<size_t>());
            crypto_auth_hmacsha512_update(&hCtx, dataU.PtrAs<const unsigned char*>(), sizeU.ValueAs<size_t>());
            crypto_auth_hmacsha512_final(&hCtx, dataU.PtrAs<unsigned char*>());

            {
                std::byte*          ptrT    = dataT.Ptr();
                const std::byte*    ptrU    = dataU.Ptr();
                const size_t        count   = size_t(crypto_auth_hmacsha512_BYTES);

                for (size_t k = 0; k < count; k++)
                {
                    *ptrT++ ^= *ptrU++;
                }
            }
        }

        const count_t clen = std::min(derivedKeyLeftBytes, sizeT).ValueAs<count_t>();
        derivedKeyPtrRW.CopyFrom(dataT.SubrangeAs<GpRawPtrByteR>(0_cnt, clen));
        derivedKeyLeftBytes -= clen.ValueAs<size_byte_t>();
        derivedKeyPtrRW     += clen;
    }

    return derivedKey;
}

GpSecureStorage GpCryptoHash_PBKDF2::S_HmacSHA256 (GpRawPtrByteR    aPassword,
                                                   GpRawPtrByteR    aSalt,
                                                   const count_t    aIterations,
                                                   const size_bit_t aBitLengthDerivedKey)
{
    THROW_GPE_COND_CHECK_M(aPassword.CountLeft() > 0_cnt, "Wrong password"_sv);
    THROW_GPE_COND_CHECK_M(aSalt.CountLeft() > 0_cnt, "Wrong salt"_sv);
    THROW_GPE_COND_CHECK_M(   (aBitLengthDerivedKey > 0_bit)
                           && (aBitLengthDerivedKey % 8_bit == 0_bit)
                           && (aBitLengthDerivedKey <= 0x1fffffffe0_bit), "Wrong aBitLengthDerivedKey"_sv);

    const size_byte_t   derivedKeySize      = size_byte_t(aBitLengthDerivedKey);
    size_byte_t         derivedKeyLeftBytes = derivedKeySize;

    GpSecureStorage derivedKey;
    derivedKey.Resize(derivedKeySize);
    GpSecureStorageViewRW   derivedKeyViewRW    = derivedKey.ViewRW();
    GpRawPtrByteRW          derivedKeyPtrRW     = derivedKeyViewRW.RW();

    GpSecureStorage buf_U_T;
    constexpr size_byte_t sizeU = size_byte_t::SMake(crypto_auth_hmacsha256_BYTES);
    constexpr size_byte_t sizeT = size_byte_t::SMake(crypto_auth_hmacsha256_BYTES);
    buf_U_T.Resize(sizeU + sizeT);
    GpSecureStorageViewRW   buf_U_T_KeyViewRW   = buf_U_T.ViewRW();
    GpRawPtrByteRW          buf_U_T_KeyPtrRW    = buf_U_T_KeyViewRW.RW();
    GpRawPtrByteRW          dataU               = buf_U_T_KeyPtrRW.Subrange(0_cnt, sizeU.ValueAs<count_t>());
    GpRawPtrByteRW          dataT               = buf_U_T_KeyPtrRW.Subrange(sizeU.ValueAs<count_t>(), sizeT.ValueAs<count_t>());

    crypto_auth_hmacsha256_state pshCtx, hCtx;
    GpRAIIonDestruct hCtxDestructor([&]()
    {
        sodium_memzero(&pshCtx, sizeof(pshCtx));
        sodium_memzero(&hCtx, sizeof(hCtx));
    });

    crypto_auth_hmacsha256_init(&pshCtx, aPassword.PtrAs<const unsigned char*>(), aPassword.SizeLeftV<size_t>());
    crypto_auth_hmacsha256_update(&pshCtx, aSalt.PtrAs<const unsigned char*>(), aSalt.SizeLeftV<size_t>());

    count_t partsCount = (derivedKeySize / sizeT).ValueAs<count_t>();
    if ((derivedKeySize % sizeT) > 0_byte)
    {
        partsCount++;
    }

    for (count_t partId = 0_cnt; partId < partsCount; partId++)
    {
        u_int_32 ivecVal = (partId + 1_cnt).ValueAs<u_int_32>();
        ivecVal = BitOps::H2N(ivecVal);

        MemOps::SCopy(hCtx, pshCtx);
        crypto_auth_hmacsha256_update(&hCtx, reinterpret_cast<const unsigned char*>(&ivecVal), sizeof(ivecVal));
        crypto_auth_hmacsha256_final(&hCtx, dataU.PtrAs<unsigned char*>());

        dataT.CopyFrom(dataU);

        for (count_t j = 2_cnt; j <= aIterations; j++)
        {
            crypto_auth_hmacsha256_init(&hCtx, aPassword.PtrAs<const unsigned char*>(), aPassword.SizeLeftV<size_t>());
            crypto_auth_hmacsha256_update(&hCtx, dataU.PtrAs<const unsigned char*>(), sizeU.ValueAs<size_t>());
            crypto_auth_hmacsha256_final(&hCtx, dataU.PtrAs<unsigned char*>());

            {
                std::byte*          ptrT    = dataT.Ptr();
                const std::byte*    ptrU    = dataU.Ptr();
                const size_t        count   = size_t(crypto_auth_hmacsha256_BYTES);

                for (size_t k = 0; k < count; k++)
                {
                    *ptrT++ ^= *ptrU++;
                }
            }
        }

        const count_t clen = std::min(derivedKeyLeftBytes, sizeT).ValueAs<count_t>();
        derivedKeyPtrRW.CopyFrom(dataT.SubrangeAs<GpRawPtrByteR>(0_cnt, clen));
        derivedKeyLeftBytes -= clen.ValueAs<size_byte_t>();
        derivedKeyPtrRW     += clen;
    }

    return derivedKey;
}

}//namespace GPlatform
