#pragma once

#include "../GpCryptoCore_global.hpp"

namespace GPlatform {

class GpSecureStorage;

class GPCRYPTOCORE_API GpSecureStorageViewRW final: public GpMemoryStorageViewRW
{
public:
	CLASS_DECLARE_DEFAULTS(GpSecureStorageViewRW);

public:
								GpSecureStorageViewRW	(void) noexcept = delete;
								GpSecureStorageViewRW	(GpSecureStorage& aStorage);
								GpSecureStorageViewRW	(const GpSecureStorageViewRW& aView) noexcept = delete;
								GpSecureStorageViewRW	(GpSecureStorageViewRW&& aView) noexcept;
	virtual						~GpSecureStorageViewRW	(void) noexcept override final;

	virtual const std::byte*	Data					(void) const noexcept override final;
	virtual std::byte*			Data					(void) noexcept override final;
	virtual count_t				Size					(void) const noexcept override final;
	virtual std::string_view	AsStringView			(void) const noexcept override final;
	virtual std::string_view	AsStringView			(const count_t aOffset, const count_t aSize) const override final;
	virtual bool				IsEmpty					(void) const noexcept override final;

private:
	GpSecureStorage*			iStorage = nullptr;
};

}//namespace GPlatform
