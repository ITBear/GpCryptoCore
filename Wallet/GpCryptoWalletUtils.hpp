#pragma once

#include "GpCryptoAddressFactory.hpp"
#include "../MnemonicCodes/GpMnemonicCodes.hpp"

namespace GPlatform {

class GPCRYPTOCORE_API GpCryptoWalletUtils
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoWalletUtils)

public:
    static GpSecureStorage::CSP         SNewMnemonic                    (void);
    static bool                         SValidateMnemonic               (GpRawPtrCharR aMnemonic);
    static GpSecureStorage::CSP         SSeedFromMnemonic               (GpRawPtrCharR aMnemonic,
                                                                         GpRawPtrCharR aPassword);
    static GpCryptoHDKeyStorage::CSP    SGenerateBip44                  (GpRawPtrByteR aSeed);
    static GpCryptoKeyFactory::SP       SNewHDKeyFactory                (GpCryptoHDKeyStorage::CSP aBip44RootHD);
    static GpCryptoKeyFactory::SP       SNewHDKeyFactoryMnemonic        (GpRawPtrCharR aMnemonic, GpRawPtrCharR aPassword);
    static GpCryptoKeyFactory::SP       SNewRndKeyFactory               (void);
    static GpCryptoAddress::SP          SNewAddrFromFactory             (GpCryptoAddressFactory&    aAddrFactory,
                                                                         GpCryptoKeyFactory&        aKeyFactory);
    static GpCryptoAddress::SP          SNewAddrFromPrivateKey          (GpCryptoAddressFactory&    aAddrFactory,
                                                                         GpSecureStorage::CSP       aPrivateKey);
    static GpCryptoAddress::SP          SNewAddrFromPrivateKeyStrHex    (GpCryptoAddressFactory&    aAddrFactory,
                                                                         GpSecureStorage::CSP       aPrivateKeyStrHex);

private:
    static const GpMnemonicCodeGen::WordListT   sWordListEN;
};

}//namespace GPlatform
