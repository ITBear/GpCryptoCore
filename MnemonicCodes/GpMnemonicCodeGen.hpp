#pragma once

#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpMnemonicCodeGen
{
	CLASS_REMOVE_CTRS(GpMnemonicCodeGen);

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
	static GpSecureStorage	SGenerateNewMnemonic	(const WordListT&	aWordList,
													 const EntropySize	aEntropySize,
													 const std::string	aSpaceChar);

	static bool				SValidateMnemonic		(const WordListT&		aWordList,
													 const GpSecureStorage& aMnemonic,
													 const std::string		aSpaceChar);

	static GpSecureStorage	SSeedFromMnemonic		(const GpSecureStorage&	aMnemonic,
													 const GpSecureStorage&	aPassword,
													 const count_t			aIterations,
													 const size_bit_t		aBitLengthDerivedKey);

	static GpSecureStorage	SSeedFromMnemonic		(std::string_view	aMnemonic,
													 std::string_view	aPassword,
													 const count_t		aIterations,
													 const size_bit_t	aBitLengthDerivedKey);
private:
	static size_t			SFindConfByWordsCount	(const count_t aWordsCount);
	static u_int_16			SFindWordId				(const WordListT&	aWordList,
													 std::string_view	aWord);
};

}//GPlatform
