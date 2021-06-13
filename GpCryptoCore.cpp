#include "GpCryptoCore.hpp"
#include <libsodium/sodium.h>

#if defined(GP_OS_LINUX)
#   include <fcntl.h>
#   include <unistd.h>
#   include <sys/ioctl.h>
#   include <linux/random.h>
#endif//#if defined(GP_OS_LINUX)

namespace GPlatform {

void    GpCryptoCore::SInit (void)
{
    GpSRandom::S().SetSeedFromRD();
    SCheckEntropyCapacity();

    if (sodium_init() == -1)
    {
        THROW_GPE("libsodium sodium_init() == -1"_sv);
    }
}

void    GpCryptoCore::SClear (void)
{
    //NOP
}

void    GpCryptoCore::SCheckEntropyCapacity (void)
{
#if defined(GP_OS_LINUX) && defined(RNDGETENTCNT)
    int fd;
    int c;

    if ((fd = open("/dev/random", O_RDONLY)) != -1)
    {
        bool isEnough = true;

        if (ioctl(fd, RNDGETENTCNT, &c) == 0 && c < 160)
        {
            isEnough = false;
        }

        close(fd);

        if (!isEnough)
        {
            THROW_GPE("This system doesn't provide enough entropy to quickly generate high-quality random numbers"_sv);
        }
    }
#endif//#if defined(GP_OS_LINUX) && defined(RNDGETENTCNT)
}

}//GPlatform
