#include "GpCryptoHash_PBKDF2.hpp"

GP_WARNING_PUSH()
GP_WARNING_DISABLE(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

GpSecureStorage::SP GpCryptoHash_PBKDF2::S_HmacSHA512
(
    GpRawPtrByteR       aPassword,
    GpRawPtrByteR       aSalt,
    const count_t       aIterations,
    const size_bit_t    aBitLengthDerivedKey
)
{
    THROW_GPE_COND
    (
        aPassword.CountLeft() > 0_cnt,
        "Wrong password length"_sv
    );

    THROW_GPE_COND
    (
        aSalt.CountLeft() > 0_cnt,
        "Wrong salt length"_sv
    );

    THROW_GPE_COND
    (
           (aBitLengthDerivedKey > 0_bit)
        && (aBitLengthDerivedKey % 8_bit == 0_bit)
        && (aBitLengthDerivedKey <= 0x1fffffffe0_bit),
        "Wrong aBitLengthDerivedKey length"_sv
    );

    const size_byte_t   derivedKeySize      = size_byte_t(aBitLengthDerivedKey);
    size_byte_t         derivedKeyLeftBytes = derivedKeySize;

    GpSecureStorage::SP derivedKeySP    = MakeSP<GpSecureStorage>();
    GpSecureStorage&    derivedKey      = derivedKeySP.V();
    derivedKey.Resize(derivedKeySize);
    GpSecureStorageViewRW   derivedKeyViewRW    = derivedKey.ViewRW();
    GpRawPtrByteRW          derivedKeyPtrRW     = derivedKeyViewRW.RW();

    GpSecureStorage buf_U_T;
    constexpr size_byte_t sizeU = size_byte_t::SMake(crypto_auth_hmacsha512_BYTES);
    constexpr size_byte_t sizeT = size_byte_t::SMake(crypto_auth_hmacsha512_BYTES);
    buf_U_T.Resize(sizeU + sizeT);
    GpSecureStorageViewRW   buf_U_T_KeyViewRW   = buf_U_T.ViewRW();
    GpRawPtrByteRW          buf_U_T_KeyPtrRW    = buf_U_T_KeyViewRW.RW();
    GpRawPtrByteRW          dataU               = buf_U_T_KeyPtrRW.Subrange(0_cnt, sizeU.As<count_t>());
    GpRawPtrByteRW          dataT               = buf_U_T_KeyPtrRW.Subrange(sizeU.As<count_t>(), sizeT.As<count_t>());

    crypto_auth_hmacsha512_state pshCtx, hCtx;
    GpRAIIonDestruct hCtxDestructor([&]()
    {
        sodium_memzero(&pshCtx, sizeof(pshCtx));
        sodium_memzero(&hCtx, sizeof(hCtx));
    });

    crypto_auth_hmacsha512_init(&pshCtx, aPassword.PtrAs<const unsigned char*>(), aPassword.SizeLeft().As<size_t>());
    crypto_auth_hmacsha512_update(&pshCtx, aSalt.PtrAs<const unsigned char*>(), aSalt.SizeLeft().As<size_t>());

    count_t partsCount = (derivedKeySize / sizeT).As<count_t>();
    if ((derivedKeySize % sizeT) > 0_byte)
    {
        partsCount++;
    }

    for (count_t partId = 0_cnt; partId < partsCount; partId++)
    {
        u_int_32 ivecVal = (partId + 1_cnt).As<u_int_32>();
        ivecVal = BitOps::H2N(ivecVal);

        MemOps::SCopy(hCtx, pshCtx);
        crypto_auth_hmacsha512_update(&hCtx, reinterpret_cast<const unsigned char*>(&ivecVal), sizeof(ivecVal));
        crypto_auth_hmacsha512_final(&hCtx, dataU.PtrAs<unsigned char*>());

        dataT.CopyFrom(dataU);

        for (count_t j = 2_cnt; j <= aIterations; j++)
        {
            crypto_auth_hmacsha512_init(&hCtx, aPassword.PtrAs<const unsigned char*>(), aPassword.SizeLeft().As<size_t>());
            crypto_auth_hmacsha512_update(&hCtx, dataU.PtrAs<const unsigned char*>(), sizeU.As<size_t>());
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

        const count_t clen = std::min(derivedKeyLeftBytes, sizeT).As<count_t>();
        derivedKeyPtrRW.CopyFrom(dataT.SubrangeAs<GpRawPtrByteR>(0_cnt, clen));
        derivedKeyLeftBytes -= clen.As<size_byte_t>();
        derivedKeyPtrRW     += clen;
    }

    return derivedKeySP;
}

GpSecureStorage::SP GpCryptoHash_PBKDF2::S_HmacSHA256
(
    GpRawPtrByteR       aPassword,
    GpRawPtrByteR       aSalt,
    const count_t       aIterations,
    const size_bit_t    aBitLengthDerivedKey
)
{
    THROW_GPE_COND
    (
        aPassword.CountLeft() > 0_cnt,
        "Wrong password"_sv
    );

    THROW_GPE_COND
    (
        aSalt.CountLeft() > 0_cnt,
        "Wrong salt"_sv
    );

    THROW_GPE_COND
    (
           (aBitLengthDerivedKey > 0_bit)
        && (aBitLengthDerivedKey % 8_bit == 0_bit)
        && (aBitLengthDerivedKey <= 0x1fffffffe0_bit),
        "Wrong aBitLengthDerivedKey"_sv
    );

    const size_byte_t   derivedKeySize      = size_byte_t(aBitLengthDerivedKey);
    size_byte_t         derivedKeyLeftBytes = derivedKeySize;

    GpSecureStorage::SP derivedKeySP    = MakeSP<GpSecureStorage>();
    GpSecureStorage&    derivedKey      = derivedKeySP.V();
    derivedKey.Resize(derivedKeySize);
    GpSecureStorageViewRW   derivedKeyViewRW    = derivedKey.ViewRW();
    GpRawPtrByteRW          derivedKeyPtrRW     = derivedKeyViewRW.RW();

    GpSecureStorage buf_U_T;
    constexpr size_byte_t sizeU = size_byte_t::SMake(crypto_auth_hmacsha256_BYTES);
    constexpr size_byte_t sizeT = size_byte_t::SMake(crypto_auth_hmacsha256_BYTES);
    buf_U_T.Resize(sizeU + sizeT);
    GpSecureStorageViewRW   buf_U_T_KeyViewRW   = buf_U_T.ViewRW();
    GpRawPtrByteRW          buf_U_T_KeyPtrRW    = buf_U_T_KeyViewRW.RW();
    GpRawPtrByteRW          dataU               = buf_U_T_KeyPtrRW.Subrange(0_cnt, sizeU.As<count_t>());
    GpRawPtrByteRW          dataT               = buf_U_T_KeyPtrRW.Subrange(sizeU.As<count_t>(), sizeT.As<count_t>());

    crypto_auth_hmacsha256_state pshCtx, hCtx;
    GpRAIIonDestruct hCtxDestructor([&]()
    {
        sodium_memzero(&pshCtx, sizeof(pshCtx));
        sodium_memzero(&hCtx, sizeof(hCtx));
    });

    crypto_auth_hmacsha256_init(&pshCtx, aPassword.PtrAs<const unsigned char*>(), aPassword.SizeLeft().As<size_t>());
    crypto_auth_hmacsha256_update(&pshCtx, aSalt.PtrAs<const unsigned char*>(), aSalt.SizeLeft().As<size_t>());

    count_t partsCount = (derivedKeySize / sizeT).As<count_t>();
    if ((derivedKeySize % sizeT) > 0_byte)
    {
        partsCount++;
    }

    for (count_t partId = 0_cnt; partId < partsCount; partId++)
    {
        u_int_32 ivecVal = (partId + 1_cnt).As<u_int_32>();
        ivecVal = BitOps::H2N(ivecVal);

        MemOps::SCopy(hCtx, pshCtx);
        crypto_auth_hmacsha256_update(&hCtx, reinterpret_cast<const unsigned char*>(&ivecVal), sizeof(ivecVal));
        crypto_auth_hmacsha256_final(&hCtx, dataU.PtrAs<unsigned char*>());

        dataT.CopyFrom(dataU);

        for (count_t j = 2_cnt; j <= aIterations; j++)
        {
            crypto_auth_hmacsha256_init(&hCtx, aPassword.PtrAs<const unsigned char*>(), aPassword.SizeLeft().As<size_t>());
            crypto_auth_hmacsha256_update(&hCtx, dataU.PtrAs<const unsigned char*>(), sizeU.As<size_t>());
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

        const count_t clen = std::min(derivedKeyLeftBytes, sizeT).As<count_t>();
        derivedKeyPtrRW.CopyFrom(dataT.SubrangeAs<GpRawPtrByteR>(0_cnt, clen));
        derivedKeyLeftBytes -= clen.As<size_byte_t>();
        derivedKeyPtrRW     += clen;
    }

    return derivedKeySP;
}

}//namespace GPlatform
