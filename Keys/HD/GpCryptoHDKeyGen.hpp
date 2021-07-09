#pragma once

#include "GpCryptoHDKeyStorage.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoHDKeyGen
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoHDKeyGen)

    using SchemeTypeT   = GpCryptoHDSchemeType;
    using SchemeTypeTE  = SchemeTypeT::EnumT;

public:
    static GpCryptoHDKeyStorage::SP     SMasterKeyPairFromSeed  (GpRawPtrByteR          aSeed,
                                                                 const SchemeTypeTE     aSchemeType);

    static GpCryptoHDKeyStorage::SP     SChildKeyPair           (const GpCryptoHDKeyStorage&    aParentHDKeyStorage,
                                                                 const count_t                  aChildId);
};

}//GPlatform
