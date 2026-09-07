# CSD issuance authorization

New CSD registrations and note issuances require both Ed25519 and ML-DSA-65.
This covers the authority's issuance signature; it does not replace the note's
curve-based value, ownership, or anonymity proofs.

## Registered authority and wire format

A CSD definition retains its 32-byte Ed25519 public key and requires a separate
1,952-byte ML-DSA-65 public key. Both keys are bound into the definition digest
and the VM state root. The RPC field is `pqPublicKey`.
The registration uses the existing governance authorization. An issuer ID is
immutable; it cannot be reused to overwrite either registered key.

Issuance carries the existing 64-byte `issuerSignature` and the mandatory
3,309-byte `issuerPqSignature`. Both sign the same issuance authorization
digest. ML-DSA additionally uses the common crypto backend's fixed Attestation
purpose and standalone ML-DSA-65 suite context. The digest declares
`ed25519-and-mldsa65-attestation-v1`; CSD definition, issuance authorization,
and final issuance statement domains are version 2.

The VM verifies the governance approval, active issuer status, asset permission,
registered validity interval, issuance age, and both authority signatures before
inserting a note. Corruption, missing/extra signature bytes, another PQ key, and
a signature made for another purpose are rejected. The VM persistence format
requires the PQ public key; legacy registrations are never silently upgraded.

To replace an issuer key pair, enroll a new issuer ID through governance and use
the existing suspend/revoke operation on the old issuer. Existing issuer records
are not deleted or rewritten by this change.

## Process-isolated signing

The pretrade harness requires the following public configuration in addition to
the existing classical signer options:

- `--csd-signer-pq-key-id`: independently held ML-DSA-65 key identifier.
- `--csd-signer-pq-public`: pinned ML-DSA-65 public key, hex encoded.

`CommandCsdSigner` invokes the configured executable separately for each key.
Protocol version 1 remains the bounded Ed25519 request/response protocol.
Version 2 exclusively means ML-DSA-65 with the Attestation purpose. Each response
must match its requested version and key ID and verify against the corresponding
pinned public key. The response limit is 8 KiB; process timeouts and request
limits apply to both algorithms.

`zkpi-hsm-signer --initialize` generates two independent keys in the encrypted
key store and returns only their IDs and public keys. On each request the helper
restores the selected key and checks its current lifecycle state. The caller
never receives a private key. This helper is a software acceptance emulator and
reports `hardware_backed=false`; it is not evidence of a physical HSM or a
production KMS integration.

Public Docker/laboratory bootstrap paths retain explicitly labeled deterministic
fixture authorities. These fixtures are not deployment key provisioning.
Production signer APIs require an independently provisioned PQ signer/key handle.

## Verification targets

Run on the repository's required remote Rust runner:

- `cargo test -p defmi --features avalanche --test note_chain`
- The VM CSD registration and note issuance test in `qomm-avalanche-vm`.
- `cargo test -p defmi-harness --test csd_external_signer`
- `cargo test -p qomm-transport --test external_signer`

The external process test initializes a real encrypted store, restores and signs
with both keys, rejects a wrong pinned PQ key, revokes the PQ key, and verifies
that the remaining working Ed25519 key cannot satisfy the PQ signing request.

The canonical issuance digest test uses fixed, shape-only PQ signature bytes
because real ML-DSA signing is randomized. Real signature acceptance and tamper
rejection are separate tests. Source availability is not a test-pass claim;
record the remote runner's result before reporting integration as verified.

