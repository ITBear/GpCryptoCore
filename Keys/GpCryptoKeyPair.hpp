#pragma once

#include "GpCryptoKeyType.hpp"
#include "../Utils/GpSecureStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoKeyPair
{
public:
	CLASS_REMOVE_CTRS_EXCEPT_MOVE(GpCryptoKeyPair);
	CLASS_DECLARE_DEFAULTS(GpCryptoKeyPair);

	using TypeT		= GpCryptoKeyType;
	using TypeTE	= TypeT::EnumT;

protected:
								GpCryptoKeyPair				(const TypeTE aType) noexcept;
								GpCryptoKeyPair				(GpCryptoKeyPair&& aKeyPair) noexcept;

public:
	virtual						~GpCryptoKeyPair			(void) noexcept;

	void						Clear						(void) noexcept;

	TypeTE						Type						(void) const noexcept {return iType;}

	virtual void				GenerateNew					(void) = 0;
	void						GenerateNewSS				(const GpSecureStorage& aSeed);
	virtual void				GenerateNewSV				(std::string_view aSeed) = 0;
	void						ImportPrivateBytesSS		(const GpSecureStorage& aPrivateBytes);
	virtual void				ImportPrivateBytesSV		(std::string_view aPrivateBytes) = 0;
	void						ImportPrivateStrHexSS		(const GpSecureStorage& aPrivateStrHex);
	virtual void				ImportPrivateStrHexSV		(std::string_view aPrivateStrHex) = 0;

	const GpSecureStorage&		PrivateBytes				(void) const noexcept {return iPrivateBytes;}
	const GpBytesArray&			PublicBytes					(void) const noexcept {return iPublicBytes;}

	GpBytesArray				ToPublicBytesWithPrefix		(void) const;
	GpSecureStorage				ToPrivateStrHexWithPrefix	(void) const;
	std::string					ToPublicStrHexWithPrefix	(void) const;

	virtual std::string_view	PrivateBytesPrefix			(void) const noexcept = 0;
	virtual std::string_view	PublicBytesPrefix			(void) const noexcept = 0;
	virtual std::string_view	PrivateStrHexPrefix			(void) const noexcept = 0;
	virtual std::string_view	PublicStrHexPrefix			(void) const noexcept = 0;

protected:
	const TypeTE				iType;
	GpSecureStorage				iPrivateBytes;
	GpBytesArray				iPublicBytes;
};

}//namespace GPlatform
