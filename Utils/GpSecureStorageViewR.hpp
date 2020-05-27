#pragma once

#include "../GpCryptoCore_global.hpp"

namespace GPlatform {

class GpSecureStorage;

class GPCRYPTOCORE_API GpSecureStorageViewR final: public GpMemoryStorageViewR
{
public:
	CLASS_DECLARE_DEFAULTS(GpSecureStorageViewR);

public:
								GpSecureStorageViewR	(void) noexcept = delete;
								GpSecureStorageViewR	(const GpSecureStorage& aStorage);
								GpSecureStorageViewR	(const GpSecureStorageViewR& aView) noexcept = delete;
								GpSecureStorageViewR	(GpSecureStorageViewR&& aView) noexcept;
	virtual						~GpSecureStorageViewR	(void) noexcept override final;

	virtual const std::byte*	Data					(void) const noexcept override final;
	virtual count_t				Size					(void) const noexcept override final;
	virtual std::string_view	AsStringView			(void) const noexcept override final;
	virtual std::string_view	AsStringView			(const count_t aOffset, const count_t aSize) const override final;
	virtual bool				IsEmpty					(void) const noexcept override final;

private:
	const GpSecureStorage*		iStorage = nullptr;
};

}//namespace GPlatform
