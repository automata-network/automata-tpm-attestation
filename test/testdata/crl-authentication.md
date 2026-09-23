# CRL authentication regression fixtures

Generated on 2026-09-24 with OpenSSL using synthetic RSA-2048 keys. The JSON
contains public DER certificates and CRLs only. No production identity, private
key, RPC endpoint, or external issuer service is required by the tests.

Tests fix the clock at 2026-09-24 12:00 UTC. Certificates normally span
2025-01-01 through 2035-01-01. The expired intermediate ends on 2026-09-23.
Initial CRLs end on 2026-09-26; refresh CRLs span 2026-09-27 through 2026-10-01.

- `root` and `attacker` have the same subject and SKID but different keys.
- `root_reissued`, `root_no_crlsign`, and `root_short` reuse the root key and
  subject, with distinct serials and the indicated constraints.
- `intermediate_no_crlsign` and `intermediate_expired` reuse the intermediate
  key and subject; the root signs both certificates.
- Leaf serials are 100 (root-issued), 101 (intermediate-issued), and 102
  (second-intermediate-issued). The intermediate serial is 2.
- Revocation lists cover these synthetic serials. The attacker signs its own
  list revoking serial 100. The root and intermediate also sign genuine lists.
- `root_delta` contains a delta-CRL extension. `root_partitioned` contains an
  issuing-distribution-point extension, without a delta-CRL extension.

All keys are test-only. The regression assertions depend on these relationships,
not on a particular randomly generated modulus.
