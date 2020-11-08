TEMPLATE        = lib
#CONFIG         += staticlib
VER_MAJ		    = 0
VER_MIN		    = 1
VER_PAT		    = 2
QMAKE_CXXFLAGS += -DGP_MODULE_UUID=fdc6d09a-3103-4002-bb48-03483f3808a4
QMAKE_CXXFLAGS += -DGP_TYPE_SYSTEM_STATIC_ADD_TO_MANAGER
DEFINES		   += GPCRYPTOCORE_LIBRARY
PACKET_NAME     = GpCryptoCore
DIR_LEVEL       = ./..

include(../../QtGlobalPro.pri)

#------------------------------ LIBS BEGIN ---------------------------------
os_windows{
	GP_CORE_LIB_V		= 2
	GP_UTF8_PROC_LIB_V	= 0
}

os_linux{
}

LIBS += -lGpCore2$$TARGET_POSTFIX$$GP_CORE_LIB_V
LIBS += -lutf8proc$$TARGET_POSTFIX$$GP_UTF8_PROC_LIB_V
LIBS += -lsodium
#------------------------------ LIBS END ---------------------------------

SOURCES += \
	Encryption/GpEncryptionUtils.cpp \
	ExtSources/ripemd160.cpp \
	Hashes/GpCryptoHash_Blake2b.cpp \
	Hashes/GpCryptoHash_Hmac.cpp \
	Hashes/GpCryptoHash_KDF_Passwd.cpp \
	Hashes/GpCryptoHash_PBKDF2.cpp \
	Hashes/GpCryptoHash_Ripemd160.cpp \
	Hashes/GpCryptoHash_Sha2.cpp \
	Keys/Curve25519/GpCryptoHDKeyGen_Ed25519.cpp \
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_HD.cpp \
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_Import.cpp \
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_Rnd.cpp \
	Keys/Curve25519/GpCryptoKeyPair_Ed25519.cpp \
	Keys/Curve25519/GpCryptoKeyPair_X25519.cpp \
	Keys/GpCryptoKeyPair.cpp \
	Keys/GpCryptoKeyType.cpp \
	GpCryptoCore.cpp \
	Keys/HD/GpCryptoHDKeyGen.cpp \
	Keys/HD/GpCryptoHDKeyStorage.cpp \
	Keys/HD/GpCryptoHDSchemeType.cpp \
	MnemonicCodes/GpMnemonicCodeGen.cpp \
	Utils/GpByteWriterStorageSecure.cpp \
	Utils/GpCryptoRandom.cpp \
	Utils/GpSecureStorage.cpp \
	Utils/GpSecureStorageViewR.cpp \
	Utils/GpSecureStorageViewRW.cpp

HEADERS += \
	Encryption/GpEncryption.hpp \
	Encryption/GpEncryptionUtils.hpp \
	ExtSources/ripemd160.hpp \
	GpCryptoCore.hpp \
	GpCryptoCore_global.hpp \
	Hashes/GpCryptoHash_Blake2b.hpp \
	Hashes/GpCryptoHash_Hmac.hpp \
	Hashes/GpCryptoHash_KDF_Passwd.hpp \
	Hashes/GpCryptoHash_PBKDF2.hpp \
	Hashes/GpCryptoHash_Ripemd160.hpp \
	Hashes/GpCryptoHash_Sha2.hpp \
	Hashes/GpCryptoHashes.hpp \
	Keys/Curve25519/GpCryptoHDKeyGen_Ed25519.hpp \
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_HD.hpp \
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_Import.hpp \
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_Rnd.hpp \
	Keys/Curve25519/GpCryptoKeyPair_Ed25519.hpp \
	Keys/Curve25519/GpCryptoKeyPair_X25519.hpp \
	Keys/Curve25519/GpCurve25519.hpp \
	Keys/GpCryptoKeyFactory.hpp \
	Keys/GpCryptoKeyPair.hpp \
	Keys/GpCryptoKeyType.hpp \
	Keys/GpCryptoKeys.hpp \
	Keys/HD/GpCryptoHDKeyGen.hpp \
	Keys/HD/GpCryptoHDKeyStorage.hpp \
	Keys/HD/GpCryptoHDKeys.hpp \
	Keys/HD/GpCryptoHDSchemeType.hpp \
	MnemonicCodes/GpMnemonicCodeGen.hpp \
	MnemonicCodes/GpMnemonicCodes.hpp \
	Utils/GpByteWriterStorageSecure.hpp \
	Utils/GpCryptoRandom.hpp \
	Utils/GpCryptoUtils.h \
	Utils/GpSecureStorage.hpp \
	Utils/GpSecureStorageViewR.hpp \
	Utils/GpSecureStorageViewRW.hpp
