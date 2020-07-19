#pragma once

#include "../GpCore2/GpCore.hpp"

#if defined(GPCRYPTOCORE_LIBRARY)
    #define GPCRYPTOCORE_API GP_DECL_EXPORT
#else
    #define GPCRYPTOCORE_API GP_DECL_IMPORT
#endif
