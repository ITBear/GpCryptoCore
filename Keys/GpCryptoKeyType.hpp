#pragma once

#include "../GpCryptoCore_global.hpp"

namespace GPlatform {

GP_ENUM(GPCRYPTOCORE_API, GpCryptoKeyType,
    ED_25519,           //Edwards-curve Digital Signature Algorithm (EdDSA) over Curve25519
    X_25519             //Elliptic Curve Diffie-Hellman (ECDH) over Curve25519
);

}//namespace GPlatform
