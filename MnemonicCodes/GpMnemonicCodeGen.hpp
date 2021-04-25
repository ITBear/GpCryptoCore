#pragma once

#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpMnemonicCodeGen
{
    CLASS_REMOVE_CTRS(GpMnemonicCodeGen)

public:
    using WordListT = GpArray<std::string, 2048>;

    enum EntropySize
    {
        ES_128,
        ES_160,
        ES_192,
        ES_224,
        ES_256,
        _LAST
    };

public:
    static GpSecureStorage::SP  SGenerateNewMnemonic    (const WordListT&   aWordList,
                                                         const std::string  aSpaceChar,
                                                         const EntropySize  aEntropySize);

    [[nodiscard]] static bool   SValidateMnemonic       (const WordListT&       aWordList,
                                                         const std::string      aSpaceChar,
                                                         const GpSecureStorage& aMnemonic);

    [[nodiscard]] static bool   SValidateMnemonic       (const WordListT&   aWordList,
                                                         const std::string  aSpaceChar,
                                                         GpRawPtrCharR      aMnemonic);

    static GpSecureStorage::SP  SSeedFromMnemonic       (const WordListT&       aWordList,
                                                         const std::string      aSpaceChar,
                                                         const GpSecureStorage& aMnemonic,
                                                         const GpSecureStorage& aPassword,
                                                         const count_t          aIterations,
                                                         const size_bit_t       aBitLengthDerivedKey);

    static GpSecureStorage::SP  SSeedFromMnemonic       (const WordListT&   aWordList,
                                                         const std::string  aSpaceChar,
                                                         GpRawPtrCharR      aMnemonic,
                                                         GpRawPtrCharR      aPassword,
                                                         const count_t      aIterations,
                                                         const size_bit_t   aBitLengthDerivedKey);
private:
    static size_t               SFindConfByWordsCount   (const count_t aWordsCount);
    static u_int_16             SFindWordId             (const WordListT&   aWordList,
                                                         GpRawPtrCharR      aWord);
};

}//GPlatform
