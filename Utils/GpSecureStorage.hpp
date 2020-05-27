#pragma once

#include "GpSecureStorageViewR.hpp"
#include "GpSecureStorageViewRW.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpSecureStorage final: public GpMemoryStorage
{
	friend class GpSecureStorageViewR;
	friend class GpSecureStorageViewRW;

public:
	CLASS_DECLARE_DEFAULTS(GpSecureStorage);

public:
								GpSecureStorage		(void) noexcept;
								GpSecureStorage		(const GpSecureStorage&) noexcept = delete;
								GpSecureStorage		(GpSecureStorage&& aStorage) noexcept;
	virtual						~GpSecureStorage	(void) noexcept override final;

	GpSecureStorage&			operator=			(GpSecureStorage&& aStorage) noexcept;

	virtual void				Clear				(void) noexcept override final;
	virtual void				Allocate			(count_t aSize) override final;
	virtual void				Resize				(count_t aSize) override final;
	virtual void				Set					(GpMemoryStorage&& aStorage) override final;
	virtual void				Set					(std::string_view aData) override final;
	virtual count_t				Size				(void) const noexcept override final {return iSize;}
	virtual bool				IsEmpty				(void) const noexcept override final {return (iData == nullptr) || (iSize == 0_cnt);}

	virtual GpMemoryStorage::SP	New					(void) const override final;

	virtual ViewR::SP			ViewRead			(void) const override final {return GpSecureStorageViewR::SP::SNew(*this);}
	virtual ViewRW::SP			ViewReadWrite		(void) override final {return GpSecureStorageViewRW::SP::SNew(*this);}

	GpSecureStorageViewR		ViewR				(void) const{return GpSecureStorageViewR(*this);}
	GpSecureStorageViewRW		ViewRW				(void) {return GpSecureStorageViewRW(*this);}

protected:
	void						LockRW				(void) const;
	void						UnlockRW			(void);
	void						UnlockR				(void) const;

private:
	std::byte*					iData	= nullptr;
	count_t						iSize	= 0_cnt;
};

}//namespace GPlatform
