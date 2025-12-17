// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.0;

/// @custom:security-contact security@ata.network
library TPMConstants {
    // All constants related to TPM2 are defined here
    // Reference: TPM-Rev-2.0-Part-2-Structures-01.38.pdf
    // (https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf)

    // TPM_ALG_ID Constants
    // Table 9
    uint16 constant TPM_ALG_ERROR = 0x0000;
    uint16 constant TPM_ALG_RSA = 0x0001;
    uint16 constant TPM_ALG_SHA1 = 0x0004;
    uint16 constant TPM_ALG_HMAC = 0x0005;
    uint16 constant TPM_ALG_AES = 0x0006;
    uint16 constant TPM_ALG_MGF1 = 0x0007;
    uint16 constant TPM_ALG_KEYEDHASH = 0x0008;
    uint16 constant TPM_ALG_XOR = 0x000A;
    uint16 constant TPM_ALG_SHA256 = 0x000B;
    uint16 constant TPM_ALG_SHA384 = 0x000C;
    uint16 constant TPM_ALG_SHA512 = 0x000D;
    uint16 constant TPM_ALG_NULL = 0x0010;
    uint16 constant TPM_ALG_SM3_256 = 0x0012;
    uint16 constant TPM_ALG_SM4 = 0x0013;
    uint16 constant TPM_ALG_RSASSA = 0x0014;
    uint16 constant TPM_ALG_RSAES = 0x0015;
    uint16 constant TPM_ALG_RSAPSS = 0x0016;
    uint16 constant TPM_ALG_OAEP = 0x0017;
    uint16 constant TPM_ALG_ECDSA = 0x0018;
    uint16 constant TPM_ALG_ECDH = 0x0019;
    uint16 constant TPM_ALG_ECDAA = 0x001A;
    uint16 constant TPM_ALG_SM2 = 0x001B;
    uint16 constant TPM_ALG_ECSCHNORR = 0x001C;
    uint16 constant TPM_ALG_ECMQV = 0x001D;
    uint16 constant TPM_ALG_KDF1_SP800_56A = 0x0020;
    uint16 constant TPM_ALG_KDF2 = 0x0021;
    uint16 constant TPM_ALG_KDF1_SP800_108 = 0x0022;
    uint16 constant TPM_ALG_ECC = 0x0023;
    uint16 constant TPM_ALG_SYMCIPHER = 0x0025;
    uint16 constant TPM_ALG_CAMELLIA = 0x0026;
    uint16 constant TPM_ALG_CTR = 0x0040;
    uint16 constant TPM_ALG_OFB = 0x0041;
    uint16 constant TPM_ALG_CBC = 0x0042;
    uint16 constant TPM_ALG_CFB = 0x0043;
    uint16 constant TPM_ALG_ECB = 0x0044;

    // TPM_ECC_CURVE Constants
    // Table 10
    uint16 constant TPM_ECC_NONE = 0x0000;
    uint16 constant TPM_ECC_NIST_P192 = 0x0001;
    uint16 constant TPM_ECC_NIST_P224 = 0x0002;
    uint16 constant TPM_ECC_NIST_P256 = 0x0003;
    uint16 constant TPM_ECC_NIST_P384 = 0x0004;
    uint16 constant TPM_ECC_NIST_P521 = 0x0005;
    uint16 constant TPM_ECC_BN_P256 = 0x0010;
    uint16 constant TPM_ECC_BN_P638 = 0x0011;
    uint16 constant TPM_ECC_SM2_P256 = 0x0020;

    // X.509 Object Identifiers (OIDs)
    // https://oidref.com/2.5.29
    bytes constant OID_BASIC_CONSTRAINTS = hex"551d13";
    bytes constant OID_KEY_USAGE = hex"551d0f";
    bytes constant OID_EXTENDED_KEY_USAGE = hex"551d25";
}
