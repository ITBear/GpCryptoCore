#pragma once

#include "Keys/GpCryptoKeys.hpp"
#include "Utils/GpCryptoUtils.h"
#include "Hashes/GpCryptoHashes.hpp"
#include "MnemonicCodes/GpMnemonicCodes.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoCore
{
    CLASS_REMOVE_CTRS(GpCryptoCore)

public:
    static void         SInit                   (void);
    static void         SClear                  (void);

private:
    static void         SCheckEntropyCapacity   (void);
};

}//GPlatform
