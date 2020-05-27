#pragma once

#include "GpCryptoHDKeyStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHDKeyPublic final: public GpCryptoHDKeyStorage
{
public:
	CLASS_REMOVE_CTRS_EXCEPT_DEFAULT_MOVE(GpCryptoHDKeyPublic);
	CLASS_DECLARE_DEFAULTS(GpCryptoHDKeyPublic);

public:
	inline						GpCryptoHDKeyPublic		(void) noexcept;
	inline						GpCryptoHDKeyPublic		(GpCryptoHDKeyPublic&& aKey) noexcept;
	virtual						~GpCryptoHDKeyPublic	(void) noexcept override final = default;

	inline GpCryptoHDKeyPublic&	operator=				(GpCryptoHDKeyPublic&& aKey) noexcept;
};

GpCryptoHDKeyPublic::GpCryptoHDKeyPublic (void) noexcept:
GpCryptoHDKeyStorage(KeyTypeTE::PUBLIC)
{
}

GpCryptoHDKeyPublic::GpCryptoHDKeyPublic (GpCryptoHDKeyPublic&& aKey) noexcept:
GpCryptoHDKeyStorage(std::move(aKey))
{
}

GpCryptoHDKeyPublic&	GpCryptoHDKeyPublic::operator= (GpCryptoHDKeyPublic&& aKey) noexcept
{
	GpCryptoHDKeyStorage::operator=(std::move(aKey));
	return *this;
}

}//GPlatform
