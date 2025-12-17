// SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.27;

import {
    RsaSignatureSizeMismatchModulusSize,
    UnsupportedHashAlgorithm,
    UnsupportedSignatureScheme
} from "../types/Errors.sol";
import {RSA} from "@openzeppelin/contracts/utils/cryptography/RSA.sol";
import {CertPubkey, SignatureAlgorithm, LibX509, TPMConstants} from "./LibX509.sol";

/// @title LibX509Verify
/// @notice A library for verifying X.509 certificate signatures
/// @dev This library provides cryptographic signature verification for X.509 certificate chains.
///      It supports both RSA (PKCS#1 v1.5) and ECDSA (P-256) signature schemes with SHA-256 hash.
///
/// @dev Supported algorithms:
///      - RSA: RSASSA-PKCS1-v1_5 with SHA-256 (OID: 1.2.840.113549.1.1.11)
///      - ECDSA: P-256 with SHA-256 (OID: 1.2.840.10045.4.3.2)
///
/// @dev Implementation notes:
///      - RSA verification uses OpenZeppelin's RSA library
///      - ECDSA P-256 verification delegates to an external verifier contract (RIP-7212 compatible)
///      - The default P256_VERIFIER address is a widely-deployed RIP-7212 implementation
///
/// @custom:security-contact security@ata.network
library LibX509Verify {
    /// @notice Default address of the P256 ECDSA signature verifier contract
    /// @dev This address points to a RIP-7212 compatible P-256 signature verifier.
    ///      RIP-7212 defines a precompile for secp256r1 (P-256) curve signature verification.
    ///      The interface expects: abi.encode(digest, r, s, x, y) and returns 1 for valid, 0 for invalid.
    ///      This particular address (0xc2b78104907F722DABAc4C69f826a522B2754De4) is the canonical
    ///      deployment of the P256Verifier contract used across multiple EVM chains.
    ///      Repo: https://github.com/daimo-eth/p256-verifier
    address public constant P256_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;

    /// @notice Verifies a cryptographic signature using the provided public key and algorithm
    /// @dev This function validates signatures for both RSA and ECDSA algorithms.
    /// @param key The public key to verify against
    /// @param sigAlgo Signature algorithm parameters (scheme + hash algorithm)
    /// @param message The original message that was signed
    /// @param signature The signature bytes to verify
    /// @param ecdsaP256Verifier Address of P256 ECDSA verifier contract (for EC signatures)
    /// @return True if signature is valid, false otherwise
    ///
    /// @dev Supported algorithm combinations:
    ///      - RSASSA (PKCS#1 v1.5) + SHA256
    ///      - EC P-256 + ECDSA + SHA256
    ///
    /// @dev Reverts with:
    ///      - UnsupportedHashAlgorithm: Hash algorithm not supported
    ///      - UnsupportedSignatureScheme: Signature scheme incompatible with public key
    ///      - RsaSignatureSizeMismatchModulusSize: RSA signature length doesn't match modulus
    function verifySignature(
        CertPubkey memory key,
        SignatureAlgorithm memory sigAlgo,
        bytes memory message,
        bytes memory signature,
        address ecdsaP256Verifier
    ) internal view returns (bool) {
        bytes32 digest;
        if (sigAlgo.hashAlgo == TPMConstants.TPM_ALG_SHA256) {
            digest = sha256(message);
        } else {
            revert UnsupportedHashAlgorithm();
        }

        if (key.algo == TPMConstants.TPM_ALG_RSA) {
            if (sigAlgo.scheme == TPMConstants.TPM_ALG_RSASSA) {
                // Extract RSA public key parameters
                (bytes memory n, bytes memory e) = key.rsa();

                // Validate signature length matches modulus size
                require(signature.length == n.length, RsaSignatureSizeMismatchModulusSize());

                // RSASSA (PKCS#1 v1.5) verification
                return RSA.pkcs1Sha256(digest, signature, e, n);
            }
        } else if (key.algo == TPMConstants.TPM_ALG_ECC) {
            // Validate signature scheme is ECDSA
            if (sigAlgo.scheme == TPMConstants.TPM_ALG_ECDSA && key.params == TPMConstants.TPM_ECC_NIST_P256) {
                // Decode DER-encoded ECDSA signature into r and s components
                (bytes32 r, bytes32 s) = LibX509.decodeEcdsaSignature(signature);

                // Extract P-256 public key coordinates
                (bytes32 x, bytes32 y) = key.ecP256();

                // Verify ECDSA signature using P256 verifier
                return ecdsaVerify(ecdsaP256Verifier, digest, r, s, x, y);
            }
        }

        revert UnsupportedSignatureScheme(sigAlgo.scheme, key.algo);
    }

    /// @notice Verifies an ECDSA signature using an external P256 verifier contract
    /// @dev This function delegates ECDSA P-256 signature verification to an external
    ///      verifier contract (e.g., RIP-7212 precompile or fallback implementation).
    ///
    /// @param verifier Address of the P256 ECDSA verifier contract
    /// @param digest The message digest (hash) that was signed
    /// @param r The r component of the ECDSA signature
    /// @param s The s component of the ECDSA signature
    /// @param x The x coordinate of the P-256 public key
    /// @param y The y coordinate of the P-256 public key
    /// @return verified True if the signature is valid, false otherwise
    ///
    /// @dev The verifier contract is expected to follow the RIP-7212 interface:
    ///      - Input: abi.encode(digest, r, s, x, y)
    ///      - Output: uint256 (0 = invalid, 1 = valid)
    ///      - Never reverts (always returns 0 or 1)
    function ecdsaVerify(address verifier, bytes32 digest, bytes32 r, bytes32 s, bytes32 x, bytes32 y)
        internal
        view
        returns (bool verified)
    {
        // Call the P256 verifier contract with signature and public key data
        bytes memory args = abi.encode(digest, r, s, x, y);
        (bool success, bytes memory ret) = verifier.staticcall(args);

        if (!success || ret.length != 32) {
            return false;
        }

        // Decode return value: 1 = valid signature, 0 = invalid signature
        verified = abi.decode(ret, (uint256)) == 1;
    }
}
