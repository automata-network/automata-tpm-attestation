# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Solidity library for on-chain verification of TPM 2.0 (Trusted Platform Module) attestations. Enables Ethereum smart contracts to verify TPM quotes, validate PCR measurements, verify X.509 certificate chains, and perform TPM2_Certify key certification. Built by Automata Network.

## Build & Development Commands

```bash
# Build contracts (with size report)
forge build --sizes

# Run all tests (verbose)
forge test -vvv

# Run a single test file
forge test --match-path test/TPMTest.t.sol -vvv

# Run a single test function
forge test --match-test testVerifyQuoteRSA -vvv

# Check formatting
forge fmt --check

# Apply formatting
forge fmt
```

CI runs: `forge fmt --check` → `forge build --sizes` → `forge test -vvv`

## Compiler Configuration

- **Solidity:** 0.8.27, EVM target: Prague
- **Optimizer:** enabled, 500 runs, via_ir = true
- **Remappings:** `@openzeppelin/contracts/` → `lib/openzeppelin-contracts/contracts/`, `@solady/` → `lib/solady/src/`

## Architecture

### Contract Hierarchy

```
TpmAttestation (main entry point)
  └── extends CertChainRegistry (abstract, manages trusted CAs + X.509 chain verification)
        └── extends Ownable (OpenZeppelin)
```

Both contracts implement their respective interfaces: `ITpmAttestation` and `ICertChainRegistry`.

### Core Verification Flows

**TPM Quote Verification** (`verifyTpmQuote`): Verifies AK certificate chain → extracts AK public key → verifies TPM quote signature (RSA or ECDSA) → returns AK pubkey + extraData.

**Trusted AK Shortcut** (`verifyTpmQuoteWithTrustedAkPub`): Skips cert chain verification when AK public key is already trusted. Gas-efficient path.

**PCR Measurement Checking** (`checkPcrMeasurements`): Parses TPM quote structure → validates PCR selection bitmap → recomputes SHA-256 digest from provided PCR values → compares against quote digest. PCR values must be sorted by index. Supports event log replay (extending events into PCR value via iterated SHA-256).

**Key Certification** (`verifyTpmKeyCertification`): Verifies AK signature over certifyInfo → parses certified key name → computes expected name from TPMT_PUBLIC → compares → optionally validates object attribute bits.

### Library Modules (`src/lib/`)

- **LibX509.sol** (1500+ lines) — X.509 DER certificate parsing: pubkey extraction, validity checks, CA constraint verification, DN extraction, CRL parsing, AKID/SKID chain linkage. The largest and most complex module.
- **LibTpm.sol** — TPM 2.0 structure parsing: quote headers, signature parsing (RSA/ECDSA), certifyInfo parsing, TPMT_PUBLIC key extraction, key name computation.
- **LibX509Verify.sol** — Signature dispatch: routes to OpenZeppelin RSA or P-256 ECDSA verifier based on algorithm.
- **Asn1Decode.sol** — Low-level ASN.1 DER decoder using a uint256 pointer encoding (5 bytes per node: type, content offset, content end, total end).
- **BytesUtils.sol** — Byte array slicing, comparison, and base32 decoding.
- **LibBytes.sol** — Byte-level reads (uint8/uint16/uint32/uint64) at arbitrary offsets with bounds checking.

### Key Design Patterns

- **Certificate chain order:** `[leaf, intermediate(s)..., root]` — max 4 certs.
- **Intermediate caching:** Verified intermediates are cached with chain-binding hashes to avoid re-verifying the same chain. Binding hash = `keccak256(abi.encode(parentBindingHash, keccak256(cert)))` prevents cross-CA substitution attacks.
- **CRL management:** Anti-rollback protection (new CRL's `thisUpdate` must be ≥ cached). Strict CRL mode can be enabled to require valid CRL for all issuers.
- **P-256 verifier:** Injected at construction. Supports RIP-7212 precompile (`0x100`) or daimo-eth P256Verifier (`0xc2b78104907F722DABAc4C69f826a522B2754De4`). Tests deploy daimo-eth via CREATE2.
- **Custom errors everywhere** — no error strings, for gas efficiency. All errors defined in `src/types/Errors.sol`.
- **TPM constants** in `src/types/TPMConstants.sol` reference TPM-Rev-2.0-Part-2-Structures-01.38.

### TPM Quote Binary Layout

Documented in `TpmAttestation.sol` natspec. Key offsets are variable-length due to `qualified_signer` and `extra_data` fields. The quote parsing uses progressive offset tracking, not fixed positions.

### Test Structure

Tests use `SetupBase.sol` which deploys the daimo-eth P256 verifier via raw CREATE2 bytecode, then instantiates `TpmAttestation`. Test data is binary blobs in `test/testdata/` (real GCP TPM attestation examples). The large test files (`CertChainRegistry.t.sol` at ~27k lines, `LibX509.t.sol` at ~21k lines) contain inline hex-encoded certificates and CRLs.

### Dependencies

- **OpenZeppelin:** `Ownable` (access control), `RSA` (RSASSA-PKCS1-v1.5 verification)
- **Solady:** `DateTimeLib` (X.509 certificate time parsing)
- **forge-std:** testing framework
