#include "GpMnemonicCodeGen.hpp"
#include "../Hashes/GpCryptoHash_Sha2.hpp"
#include "../Hashes/GpCryptoHash_PBKDF2.hpp"
#include "../Utils/GpCryptoRandom.hpp"
#include "../../utf8proc/utf8proc.hpp"

GP_WARNING_PUSH()
GP_WARNING_DISABLE(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

static const GpArray<GpTuple<size_bit_t, size_bit_t, count_t>, size_t(GpMnemonicCodeGen::EntropySize::_LAST)>
GpMnemonicCodeGen_sMnemonicK =
{
    //ENT, CS, MS
    GpTuple<size_bit_t, size_bit_t, count_t>{128_bit, 4_bit, 12_cnt},//ES_128
    GpTuple<size_bit_t, size_bit_t, count_t>{160_bit, 5_bit, 15_cnt},//ES_160
    GpTuple<size_bit_t, size_bit_t, count_t>{192_bit, 6_bit, 18_cnt},//ES_192
    GpTuple<size_bit_t, size_bit_t, count_t>{224_bit, 7_bit, 21_cnt},//ES_224
    GpTuple<size_bit_t, size_bit_t, count_t>{256_bit, 8_bit, 24_cnt} //ES_256
};

GpSecureStorage::CSP    GpMnemonicCodeGen::SGenerateNewMnemonic
(
    const WordListT&    aWordList,
    const std::string   aSpaceChar,
    const EntropySize   aEntropySize
)
{
    const auto&         conf            = GpMnemonicCodeGen_sMnemonicK.at(size_t(aEntropySize));
    const size_bit_t    entropySize     = std::get<0>(conf);
    const size_bit_t    checksumLength  = std::get<1>(conf);
    const count_t       wordsCount      = std::get<2>(conf);

    GpSecureStorage::CSP                entropySP       = GpCryptoRandom::SEntropy(entropySize);
    const GpSecureStorage&              entropy         = entropySP.VC();
    const GpCryptoHash_Sha2::Res256T    entropySha256   = GpCryptoHash_Sha2::S_256(entropy.ViewR().R());
    const u_int_8                       checksumMask    = ~u_int_8((1 << (8 - checksumLength.As<size_t>()))-1);
    const u_int_8                       checksum        = u_int_8(u_int_8(entropySha256.at(0)) & checksumMask);

    GpSecureStorage entropyWithChecksum;
    entropyWithChecksum.Resize(entropySize + 1_byte/*cheksum*/);

    {
        GpSecureStorageViewRW entropyWithChecksumViewRW = entropyWithChecksum.ViewRW();

        GpByteWriterStorageFixedSize    entropyWithChecksumStorage(entropyWithChecksumViewRW.RW());
        GpByteWriter                    entropyWithChecksumWriter(entropyWithChecksumStorage);

        entropyWithChecksumWriter.Bytes(entropy.ViewR().R());
        entropyWithChecksumWriter.UInt8(checksum);
    }

    // Generate mnemonic phrase
    GpSecureStorage::SP mnemonicPhraseSP    = MakeSP<GpSecureStorage>();
    GpSecureStorage&    mnemonicPhrase      = mnemonicPhraseSP.V();
    size_byte_t     mnemonicPhraseActualSize = 0_byte;

    {
        const count_t           spaceSize   = count_t::SMake(aSpaceChar.size());
        constexpr const count_t maxWordSize = 10_cnt;
        mnemonicPhrase.Resize((wordsCount*maxWordSize/*words*/ + (wordsCount - 1_cnt)*spaceSize/*spaces*/).As<size_byte_t>());
        GpSecureStorageViewRW           mnemonicPhraseViewRW    = mnemonicPhrase.ViewRW();
        GpByteWriterStorageFixedSize    mnemonicPhraseStorage(mnemonicPhraseViewRW.RW());
        GpByteWriter                    mnemonicPhraseWriter(mnemonicPhraseStorage);

        GpSecureStorageViewR    entropyWithChecksumViewR = entropyWithChecksum.ViewR();
        GpBitReader             entropyBitReader(entropyWithChecksumViewR.R());

        for (size_t wordId = 0; wordId < wordsCount.Value(); ++wordId)
        {
            if (wordId > 0)
            {
                mnemonicPhraseWriter.Bytes(aSpaceChar);
            }

            const u_int_16 wid = entropyBitReader.UInt16(11_bit, 0_bit);
            mnemonicPhraseWriter.Bytes(aWordList.at(wid));
        }

        mnemonicPhraseActualSize = mnemonicPhraseStorage.DataOut().Offset().As<size_byte_t>();
    }

    mnemonicPhrase.Resize(mnemonicPhraseActualSize);

    return mnemonicPhraseSP;
}

bool    GpMnemonicCodeGen::SValidateMnemonic
(
    const WordListT&        aWordList,
    const std::string       aSpaceChar,
    const GpSecureStorage&  aMnemonic
)
{
    return SValidateMnemonic(aWordList, aSpaceChar, aMnemonic.ViewR().R());
}

bool    GpMnemonicCodeGen::SValidateMnemonic
(
    const WordListT&    aWordList,
    const std::string   aSpaceChar,
    GpRawPtrCharR       aMnemonic
)
{
    GpVector<GpRawPtrCharR> mnemonicWords = StrOps::SSplit
    (
        aMnemonic.AsStringView(),
        aSpaceChar,
        0_cnt,
        0_cnt,
        Algo::SplitMode::SKIP_ZERO_LENGTH_PARTS
    );

    const auto& conf = GpMnemonicCodeGen_sMnemonicK.at(SFindConfByWordsCount(count_t::SMake(mnemonicWords.size())));

    const size_bit_t    entropySize     = std::get<0>(conf);
    const size_bit_t    checksumLength  = std::get<1>(conf);
    const u_int_8       checksumMask    = ~u_int_8((1 << (8 - checksumLength.As<size_t>()))-1);

    // ------------- Reconstruct entropy with checksum ---------------
    GpSecureStorage entropyWithChecksum;
    entropyWithChecksum.Resize(entropySize + 1_byte/*cheksum*/);
    {
        GpSecureStorageViewRW entropyWithChecksumViewRW = entropyWithChecksum.ViewRW();

        GpBitWriterStorageFixedSize entropyWithChecksumStorage(entropyWithChecksumViewRW.RW());
        GpBitWriter                 entropyWithChecksumWriter(entropyWithChecksumStorage);

        for (const GpRawPtrCharR& word: mnemonicWords)
        {
            const u_int_16 wid = SFindWordId(aWordList, word);
            entropyWithChecksumWriter.UInt16(wid, 11_bit);
        }
    }

    // ------------- Calculate checksum ---------------
    {
        const count_t entropCnt = size_byte_t(entropySize).As<count_t>();

        GpSecureStorageViewR                entropyWithChecksumViewR    = entropyWithChecksum.ViewR();
        GpRawPtrByteR                       entropyWithChecksumPtrR     = entropyWithChecksumViewR.R();
        GpRawPtrByteR                       entropy                     = entropyWithChecksumPtrR.Subrange(0_cnt, entropCnt);
        const GpCryptoHash_Sha2::Res256T    entropySha256 = GpCryptoHash_Sha2::S_256(entropy);

        const u_int_8 checksumIn    = u_int_8(entropyWithChecksumPtrR.At(entropCnt));
        const u_int_8 checksumCalc  = u_int_8(u_int_8(entropySha256.at(0)) & checksumMask);

        /*return   (checksumIn   & checksumMask)
                == (checksumCalc & checksumMask);*/

        //TODO check GpBitWriter

        return true;
    }
}

GpSecureStorage::CSP    GpMnemonicCodeGen::SSeedFromMnemonic
(
    const WordListT&        aWordList,
    const std::string       aSpaceChar,
    const GpSecureStorage&  aMnemonic,
    const GpSecureStorage&  aPassword,
    const count_t           aIterations,
    const size_bit_t        aBitLengthDerivedKey
)
{
    return SSeedFromMnemonic
    (
        aWordList,
        aSpaceChar,
        aMnemonic.ViewR().R(),
        aPassword.ViewR().R(),
        aIterations,
        aBitLengthDerivedKey
    );
}

GpSecureStorage::CSP    GpMnemonicCodeGen::SSeedFromMnemonic
(
    const WordListT&    aWordList,
    const std::string   aSpaceChar,
    GpRawPtrCharR       aMnemonic,
    GpRawPtrCharR       aPassword,
    const count_t       aIterations,
    const size_bit_t    aBitLengthDerivedKey
)
{
    THROW_GPE_COND
    (
        aMnemonic.CountLeft() > 0_cnt,
        "Mnemonic is empty"_sv
    );

    // Validate mnemonic
    THROW_GPE_COND
    (
        SValidateMnemonic(aWordList, aSpaceChar, aMnemonic),
        "Invalid mnemonic phrase"_sv
    );

    // Mnemonic normalization
    GpSecureStorage normalizedMnemonic;
    {
        const count_t cnt = UTF8Proc::S_MaxCountUTF32(UTF8NFType::NFKD, aMnemonic.AsStringView());

        GpSecureStorage tmpStorage;
        tmpStorage.Resize(cnt.As<size_byte_t>() * GpRawPtrSI32_RW::value_size_v,
                          size_byte_t::SMake(alignof(GpRawPtrSI32_RW::value_type)));
        GpSecureStorageViewRW   tmpStorageViewRW    = tmpStorage.ViewRW();
        GpRawPtrSI32_RW         tmpStoragePtrRW     = tmpStorageViewRW.RW().ReinterpretAs<GpRawPtrSI32_RW>();

        const size_byte_t actualSize = UTF8Proc::S_Process(UTF8NFType::NFKD, aMnemonic.AsStringView(), tmpStoragePtrRW);
        normalizedMnemonic.CopyFrom(tmpStoragePtrRW.As<GpRawPtrByteR>().Subrange(0_cnt, actualSize.As<count_t>()));
    }

    // Password normalization
    GpSecureStorage normalizedPassword;
    if (aPassword.CountLeft() > 0_cnt)
    {
        const count_t cnt = UTF8Proc::S_MaxCountUTF32(UTF8NFType::NFKD, aPassword.AsStringView());

        GpSecureStorage tmpStorage;
        tmpStorage.Resize(cnt.As<size_byte_t>() * GpRawPtrSI32_RW::value_size_v,
                          size_byte_t::SMake(alignof(GpRawPtrSI32_RW::value_type)));
        GpSecureStorageViewRW   tmpStorageViewRW    = tmpStorage.ViewRW();
        GpRawPtrSI32_RW         tmpStoragePtrRW     = tmpStorageViewRW.RW().ReinterpretAs<GpRawPtrSI32_RW>();

        const size_byte_t actualSize = UTF8Proc::S_Process(UTF8NFType::NFKD, aPassword.AsStringView(), tmpStoragePtrRW);
        normalizedPassword.CopyFrom(tmpStoragePtrRW.As<GpRawPtrByteR>().Subrange(0_cnt, actualSize.As<count_t>()));
    }

    // Salt
    GpSecureStorage salt;
    {
        std::string_view    saltPrefix  = "mnemonic"_sv;
        size_byte_t         saltSize    = size_byte_t::SMake(saltPrefix.size());

        if (normalizedPassword.Size() > 0_byte)
        {
            saltSize += normalizedPassword.Size();
        }

        salt.Resize(saltSize);

        GpSecureStorageViewRW           saltViewRW = salt.ViewRW();
        GpByteWriterStorageFixedSize    saltStorage(saltViewRW.RW());
        GpByteWriter                    saltWriter(saltStorage);

        saltWriter.Bytes(saltPrefix);

        if (normalizedPassword.Size() > 0_byte)
        {
            saltWriter.Bytes(normalizedPassword.ViewR().R());
        }
    }

    GpSecureStorage::CSP res = GpCryptoHash_PBKDF2::S_HmacSHA512
    (
        normalizedMnemonic.ViewR().R(),
        salt.ViewR().R(),
        aIterations,
        aBitLengthDerivedKey
    );

    return res;
}

size_t  GpMnemonicCodeGen::SFindConfByWordsCount (const count_t aWordsCount)
{
    for (size_t id = 0; id < size_t(EntropySize::_LAST); ++id)
    {
        const auto&     conf        = GpMnemonicCodeGen_sMnemonicK.at(id);
        const count_t   wordsCount  = std::get<2>(conf);

        if (aWordsCount == wordsCount)
        {
            return id;
        }
    }

    THROW_GPE("Wrong words count"_sv);
}

u_int_16    GpMnemonicCodeGen::SFindWordId
(
    const WordListT&    aWordList,
    GpRawPtrCharR       aWord
)
{
    std::string_view word = aWord.AsStringView();
    size_t id = 0;
    for (const auto& wordFromList: aWordList)
    {
        if (word == wordFromList)
        {
            return u_int_16(id);
        }

        ++id;
    }

    THROW_GPE("Word '"_sv + word + "' was not found in list"_sv);
}

}//namespace GPlatform
