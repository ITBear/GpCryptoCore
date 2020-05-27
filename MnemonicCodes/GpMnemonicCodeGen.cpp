#include "GpMnemonicCodeGen.hpp"
#include "../Hashes/GpCryptoHash_Sha2.hpp"
#include "../Hashes/GpCryptoHash_PBKDF2.hpp"
#include "../Utils/GpCryptoRandom.hpp"
#include "../../utf8proc/utf8proc.hpp"

#include <libsodium/sodium.h>

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

GpSecureStorage	GpMnemonicCodeGen::SGenerateNewMnemonic (const WordListT&	aWordList,
														 const EntropySize	aEntropySize,
														 const std::string	aSpaceChar)
{
	const auto&			conf			= GpMnemonicCodeGen_sMnemonicK.at(size_t(aEntropySize));
	const size_bit_t	entropySize		= std::get<0>(conf);
	//const size_bit_t	checksumLength	= std::get<1>(conf);
	const count_t		wordsCount		= std::get<2>(conf);

	// Generate entropy
	GpSecureStorage entropy = GpCryptoRandom::SEntropy(count_t::SMake(entropySize.ValueAs<size_t>() / size_t(8)));

	// Add control sum to entropy
	GpBytesArray entropySha256 = GpCryptoHash_Sha2::S_256(entropy);

	GpSecureStorage entropyWithChecksum;
	entropyWithChecksum.Allocate(entropy.Size() + 1_cnt/*cheksum*/);

	{
		GpSecureStorageViewRW	entropyWithChecksumView = entropyWithChecksum.ViewRW();
		GpSecureStorageViewR	entropyView				= entropy.ViewR();

		GpByteOStreamFixedSize	entropyWithChecksumOStream(entropyWithChecksumView.Data(),
														   entropyWithChecksumView.Size());

		entropyWithChecksumOStream.Bytes(entropyView.AsStringView());
		entropyWithChecksumOStream.Bytes(entropySha256.data(), 1_cnt);
	}

	// Generate mnemonic phrase
	GpSecureStorage mnemonicPhrase;

	size_t mnemonicPhraseLength = 0;
	{
		mnemonicPhrase.Allocate(wordsCount*10_cnt + (wordsCount - 1_cnt));
		GpSecureStorageViewRW	mnemonicPhraseView	= mnemonicPhrase.ViewRW();
		GpByteOStreamFixedSize	mnemonicPhraseStream(mnemonicPhraseView.Data(),
													 mnemonicPhraseView.Size());
		GpSecureStorageViewR	entropyWithChecksumView = entropyWithChecksum.ViewR();
		GpBitIStream			entropyBitStream(entropyWithChecksumView.AsStringView());

		for (size_t wordId = 0; wordId < wordsCount.Value(); ++wordId)
		{
			if (wordId > 0)
			{
				mnemonicPhraseStream.Bytes(aSpaceChar);
				mnemonicPhraseLength += aSpaceChar.length();
			}

			u_int_16 wid = 0;
			entropyBitStream.Bits(reinterpret_cast<std::byte*>(&wid), 11_bit);
#if defined(GP_ORDER_BIG_ENDIAN)
			wid = BitOps::BSwap(wid);
#endif

			std::string_view word = aWordList.at(wid);
			mnemonicPhraseLength += word.length();
			mnemonicPhraseStream.Bytes(word);
		}
	}

	mnemonicPhrase.Resize(count_t::SMake(mnemonicPhraseLength));

	return mnemonicPhrase;
}

bool	GpMnemonicCodeGen::SValidateMnemonic (const WordListT&			aWordList,
											  const GpSecureStorage&	aMnemonic,
											  const std::string			aSpaceChar)
{
	GpSecureStorageViewR		mnemonicView	= aMnemonic.ViewR();
	GpVector<std::string_view>	mnemonicWords	= GpStringOps::SSplitToView(mnemonicView.AsStringView(),
																			aSpaceChar,
																			0_cnt,
																			0_cnt,
																			Algo::SplitMode::SKIP_ZERO_LENGTH_PARTS);


	const auto& conf = GpMnemonicCodeGen_sMnemonicK.at(SFindConfByWordsCount(count_t::SMake(mnemonicWords.size())));

	const size_bit_t	entropySize		= std::get<0>(conf);
	const size_bit_t	checksumLength	= std::get<1>(conf);

	// ------------- Reconstruct entropy with checksum ---------------
	GpSecureStorage entropyWithChecksum;
	entropyWithChecksum.Allocate(count_t::SMake(size_byte_t(entropySize).Value()) + 1_cnt);
	{
		GpSecureStorageViewRW	entropyWithChecksumView = entropyWithChecksum.ViewRW();
		GpBitOStreamFixedSize	entropyWithChecksumOStream(entropyWithChecksumView.Data(),
														   size_byte_t::SMake(entropyWithChecksumView.Size().Value()),
														   0_bit);

		for (std::string_view word: mnemonicWords)
		{
			u_int_16 wid = SFindWordId(aWordList, word);
#if defined(GP_ORDER_BIG_ENDIAN)
			wid = BitOps::BSwap(wid);
#endif
			entropyWithChecksumOStream.Bits(reinterpret_cast<const std::byte*>(&wid), 11_bit);
		}
	}

	// ------------- Calculate checksum ---------------
	GpSecureStorageViewR entropyWithChecksumView = entropyWithChecksum.ViewR();
	GpBytesArray entropySha256 = GpCryptoHash_Sha2::S_256(entropyWithChecksumView.Data(),
														  entropyWithChecksumView.Size() - 1_cnt);

	u_int_8 checksumIn		= reinterpret_cast<const u_int_8*>(entropyWithChecksumView.Data())[size_byte_t(entropySize).ValueAs<size_t>()];
	u_int_8 checksumCalc	= reinterpret_cast<const u_int_8*>(entropySha256.data())[0];

	return	   (checksumIn   & ((1 << checksumLength.Value()) - 1))
			== (checksumCalc & ((1 << checksumLength.Value()) - 1));
}

GpSecureStorage	GpMnemonicCodeGen::SSeedFromMnemonic (const GpSecureStorage&	aMnemonic,
													  const GpSecureStorage&	aPassword,
													  const count_t				aIterations,
													  const size_bit_t			aBitLengthDerivedKey)
{
	GpSecureStorageViewR mnemonicView	= aMnemonic.ViewR();
	GpSecureStorageViewR passwordView	= aPassword.ViewR();

	return SSeedFromMnemonic(mnemonicView.AsStringView(),
							 passwordView.AsStringView(),
							 aIterations,
							 aBitLengthDerivedKey);
}

GpSecureStorage	GpMnemonicCodeGen::SSeedFromMnemonic (std::string_view	aMnemonic,
													  std::string_view	aPassword,
													  const count_t		aIterations,
													  const size_bit_t	aBitLengthDerivedKey)
{
	THROW_GPE_COND_CHECK_M(aMnemonic.size() > 0, "Mnemonic is empty");

	// Mnemonic normalization
	GpSecureStorage normalizedMnemonic;
	UTF8Proc::S_NFKD(aMnemonic, normalizedMnemonic);

	// Password normalization
	GpSecureStorage normalizedPassword;
	if (aPassword.size() > 0)
	{
		UTF8Proc::S_NFKD(aPassword, normalizedMnemonic);
	}

	// Salt
	GpSecureStorage salt;
	{
		std::string_view	saltPrefix	= "mnemonic"_sv;
		count_t				saltSize	= count_t::SMake(saltPrefix.size());

		if (normalizedPassword.Size() > 0_cnt)
		{
			saltSize += normalizedPassword.Size();
		}

		salt.Resize(saltSize);
		GpSecureStorageViewRW saltView = salt.ViewRW();

		GpByteOStreamFixedSize saltOStream(saltView.Data(),
										   saltView.Size());
		saltOStream.Bytes(saltPrefix);

		if (normalizedPassword.Size() > 0_cnt)
		{
			GpSecureStorageViewR	normalizedPasswordView	= normalizedPassword.ViewR();
			saltOStream.Bytes(normalizedPasswordView.Data(),
							  normalizedPasswordView.Size());
		}
	}

	GpSecureStorage res = GpCryptoHash_PBKDF2::S_HmacSHA512(normalizedMnemonic,
															salt,
															aIterations,
															aBitLengthDerivedKey);

	return res;
}

size_t	GpMnemonicCodeGen::SFindConfByWordsCount (const count_t aWordsCount)
{
	for (size_t id = 0; id < size_t(EntropySize::_LAST); ++id)
	{
		const auto&		conf		= GpMnemonicCodeGen_sMnemonicK.at(id);
		const count_t	wordsCount	= std::get<2>(conf);

		if (aWordsCount == wordsCount)
		{
			return id;
		}
	}

	THROW_GPE("Wrong words count"_sv);
}

u_int_16	GpMnemonicCodeGen::SFindWordId (const WordListT&	aWordList,
											std::string_view	aWord)
{
	size_t id = 0;
	for (const auto& word: aWordList)
	{
		if (word == aWord)
		{
			return u_int_16(id);
		}

		++id;
	}

	THROW_GPE("Word '"_sv + aWord + "' was not found in list"_sv);
}

}//namespace GPlatform
