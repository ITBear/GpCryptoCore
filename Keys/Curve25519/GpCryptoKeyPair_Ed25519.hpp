#pragma once

#include "../GpCryptoKeyPair.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoKeyPair_Ed25519 final : public GpCryptoKeyPair
{
public:
	CLASS_REMOVE_CTRS_EXCEPT_DEFAULT(GpCryptoKeyPair_Ed25519);
	CLASS_DECLARE_DEFAULTS(GpCryptoKeyPair_Ed25519);

public:
								GpCryptoKeyPair_Ed25519		(void) noexcept;
	virtual						~GpCryptoKeyPair_Ed25519	(void) noexcept override final;

	GpBytesArray				Sign						(const GpBytesArray& aMessage) const;

	virtual void				GenerateNew					(void) override final;
	virtual void				GenerateNewSV				(std::string_view aSeed) override final;
	virtual void				ImportPrivateBytesSV		(std::string_view aPrivateBytes) override final;
	virtual void				ImportPrivateStrHexSV		(std::string_view aPrivateStrHex) override final;

	virtual std::string_view	PrivateBytesPrefix			(void) const noexcept override final;
	virtual std::string_view	PublicBytesPrefix			(void) const noexcept override final;
	virtual std::string_view	PrivateStrHexPrefix			(void) const noexcept override final;
	virtual std::string_view	PublicStrHexPrefix			(void) const noexcept override final;
};

}//namespace GPlatform
