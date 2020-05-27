#include "GpCryptoRandom.hpp"

#include <libsodium/sodium.h>

namespace GPlatform {

GpSecureStorage	GpCryptoRandom::SEntropy (const count_t aSize)
{
	size_t size = aSize.ValueAs<size_t>();

	GpSecureStorage entropy;
	entropy.Allocate(aSize);

	{
		GpSecureStorageViewRW	entropyView = entropy.ViewRW();
		std::byte*				entropyData	= entropyView.Data();
		size_t					bytesNeed	= 0;

		u_int_32 v = 0;

		while (size > 0)
		{
			v			= randombytes_random();
			bytesNeed	= std::min(sizeof(u_int_32), size);

			std::memcpy(entropyData, &v, bytesNeed);

			entropyData += bytesNeed;
			size		-= bytesNeed;
		}

		sodium_memzero(&v, sizeof(v));
	}

	return entropy;
}

}//namespace GPlatform
