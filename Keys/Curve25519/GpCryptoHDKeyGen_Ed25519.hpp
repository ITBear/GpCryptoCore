#pragma once

#include "../HD/GpCryptoHDKeyStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHDKeyGen_Ed25519
{
public:
    CLASS_REMOVE_CTRS(GpCryptoHDKeyGen_Ed25519)

public:
    static GpCryptoHDKeyStorage::SP     SMasterKeyPairFromSeed  (GpRawPtrByteR  aSeed);
    static GpCryptoHDKeyStorage::SP     SChildKeyPair           (const GpCryptoHDKeyStorage&    aParentHDKeyStorage,
                                                                 const count_t                  aChildId);
};

}//GPlatform
