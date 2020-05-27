#pragma once

#include "GpCryptoHDKeyStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHDKeyPrivate final: public GpCryptoHDKeyStorage
{
public:
	CLASS_REMOVE_CTRS_EXCEPT_DEFAULT_MOVE(GpCryptoHDKeyPrivate);
	CLASS_DECLARE_DEFAULTS(GpCryptoHDKeyPrivate);

public:
	inline							GpCryptoHDKeyPrivate	(void) noexcept;
	inline							GpCryptoHDKeyPrivate	(GpCryptoHDKeyPrivate&& aKey) noexcept;
	virtual							~GpCryptoHDKeyPrivate	(void) noexcept override final = default;

	inline GpCryptoHDKeyPrivate&	operator=				(GpCryptoHDKeyPrivate&& aKey) noexcept;
};

GpCryptoHDKeyPrivate::GpCryptoHDKeyPrivate (void) noexcept:
GpCryptoHDKeyStorage(KeyTypeTE::PRIVATE)
{
}

GpCryptoHDKeyPrivate::GpCryptoHDKeyPrivate (GpCryptoHDKeyPrivate&& aKey) noexcept:
GpCryptoHDKeyStorage(std::move(aKey))
{
}

GpCryptoHDKeyPrivate&	GpCryptoHDKeyPrivate::operator= (GpCryptoHDKeyPrivate&& aKey) noexcept
{
	GpCryptoHDKeyStorage::operator=(std::move(aKey));
	return *this;
}

}//GPlatform
