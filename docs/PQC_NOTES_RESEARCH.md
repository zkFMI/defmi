# Fresh-network PQC notes: incomplete research implementation

The opt-in `pqc-notes-research` feature introduces a separate note family. It
does not enable transaction acceptance, change existing notes or migrate a
ledger. The user's approval to implement this format is not security or
deployment approval.

## Implemented boundary

`rust/defmi/src/pqc_notes.rs` implements public wire syntax, canonical identities
and wallet-local opening generation, authenticated delivery and recovery.
`NoteOpening` and the separate recipient-local `SpendingKey` deliberately have no
`Debug`, `Clone` or `Serialize` implementation; their owned private buffers use
`zeroize::Zeroizing`. Asset and value accessors
are wallet-local. There is no public source-note ID or membership index in an
anonymous spend, no caller-supplied `verified` flag and no state-application API.

The exact 232-byte private opening is:

| Byte offsets, end exclusive | Field |
| --- | --- |
| 0..32 | Asset identifier |
| 32..40 | Unsigned value, big endian |
| 40..104 | Commitment salt |
| 104..168 | Nullifier secret |
| 168..232 | Recipient spending-key commitment |

The sender samples the salt and nullifier secret (128 bytes) from a cryptographic
random generator. The recipient independently samples a 64-byte spending key and
shares only its domain-separated commitment with the sender. The spending key
itself is never included in an opening or recipient envelope. Knowing all bytes
of the sender-created opening must not grant the sender authority to spend it.
Zero asset identifiers and all-zero individual secret fields are rejected.
Zero-valued notes are representable; operation validity is a separate relation.

For domain `D`, policy encoding `P` and body `B`, the identity function is:

```text
SHA-512(u64be(len(D)) || D || u64be(len(P)) || P || u64be(len(B)) || B)
```

The policy must be exactly version 1, mode On, with its deployment identifier.
Opening commitments use domain `DEFMI:PQC-NOTE-OPENING:v1` and all 232 private
bytes. Nullifiers use `DEFMI:PQC-NOTE-NULLIFIER:v1`, the full 64-byte opening
commitment, the 64-byte nullifier secret and the separate 64-byte spending secret.
The wallet first checks that the spending key hashes to the recipient commitment
inside the opening. Spending-key commitments use domain
`DEFMI:PQC-NOTE-SPENDING-KEY:v1` and the 64-byte secret. The proof must compute
these exact preimages and the ownership equality privately, not merely accept
their public digests as metadata. Receiver key storage/recovery and the
authenticated off-chain delivery of receiving commitments remain integration
work; these in-memory types do not implement a durable wallet or key directory.

Recipient delivery uses the existing X25519 + ML-KEM-768 envelope and AES-256-GCM
implementation with `NoteOpening` purpose. The caller independently pins the
recipient key and existing 32-byte delivery context; the opening commitment is
not truncated to manufacture that context. On recovery, authenticated decryption
is followed by full opening-commitment verification under the expected policy
and a match against the recipient's separate spending-key commitment. An
authentically encrypted note that remains owned by its sender is rejected.
This wallet check is not a public proof of correct output encryption.

The opt-in proof feature also provides `NoteOpening::seal_for_private_proof`.
It returns the ordinary interoperable envelope and a separate sender-local
`SealingWitness` retaining the two independently sampled 32-byte KEM seeds.
This witness is zeroizing and has no `Debug`, `Clone` or `Serialize`
implementation. It is not included in the note or delivered to a verifier.
Retaining entropy makes the exact encryption computation reproducible inside a
future private relation; it does not itself prove that computation.

Public note IDs bind the full commitment and complete serialized ciphertext.
Transition digests bind the canonical parent, separate note-membership root,
operation, nullifiers, outputs and reservation heads. Syntax checks reject
duplicate nullifiers, duplicate output IDs, duplicate reservation IDs, unbound
digests and oversized collections. Fill syntax additionally checks distinct cash
and securities reservations, round/output bindings and the existing eight-slot
bound. These checks do not prove those bindings are authoritative.

## Earliest unresolved gate

There is no verifier-complete operational note relation yet. Required work
includes hidden accumulator membership and ownership; range/asset conservation;
issuance, reservation and claim authority; exact matching/settlement economics;
expiry and stale-head checks; publicly proved recipient-encryption correctness;
and canonical application/recovery through the actual QOMM/OCLOB/DeFMI path.

The legacy CoCode integration circuit is a fixed four-account circuit with
1,024 witnesses and 1,024 constraints. It cannot be re-labelled as a note proof.
The separate dynamic Boolean/R1CS adapter imports the SHA-512 circuit from
[mkskeller/bristol-fashion](https://github.com/mkskeller/bristol-fashion), commit
`1603ed6aa12348c2ef15ed8395b9b96e4c558b7f`, together with the Swanky reader at
`ad4a93b412ca8f0d2a5ca033acbe43b30e940af4`
([reader](https://github.com/GaloisInc/swanky/blob/ad4a93b412ca8f0d2a5ca033acbe43b30e940af4/edge/simple-arith-circuit/src/reader.rs)).
The adapter, hash padding and variable-sized private relation live in
`zkfmi-crypto/research/cosnark-trial`; they are not yet an accepted DeFMI note
proof. A deterministic one-byte relation ran through seven actual owner-local
native proof workers and independent proof verification in 871.55 seconds.
Its public proof was 85,528,922 bytes. That plumbing test did not execute the
full SHA-512 note relation or any operational note lifecycle.

Private encryption-circuit integration uses pinned, unmodified algorithm cores:
mlkem-native for ML-KEM-768 and BearSSL for X25519, HKDF-SHA256 and AES-256-GCM.
Native C public known answers match the existing Rust implementations exactly.
The envelope known answer tests the arithmetic boundary; its fixed KEM bytes
are not a valid encapsulation and are not whole-envelope proof evidence.
No generated encryption circuit is accepted: direct compilation has exhausted
memory (including a 128-GiB ML-KEM attempt), and modular compilation has failed
compiler validation or terminated abnormally. Compilation, complete unrolling,
actual circuit evaluation and cross-implementation agreement are required
before connecting any generated circuit to the private proof relation.

A complete encryption/anonymous-note relation and practical distributed proof
representation remain implementation dependencies. No successful note proof
experiment, canonical state acceptance or new-note ledger lifecycle is claimed.

## Verification

Build and test only on the authorized remote Linux host, through the configured
OmenX-to-SoftBank route. The focused deterministic gate is:

```sh
cargo test --locked --release -j8 -p defmi --features pqc-notes-research --lib pqc_notes::tests
cargo test --locked --release -j8 -p defmi --test notes --test recipient_delivery
cargo clippy --locked --release -j8 -p defmi --features pqc-notes-research --lib --tests -- -D warnings
```

The tests use actual generated hybrid recipient keys and authenticated
envelopes. They exercise recovery and wrong recipient/context/policy,
ciphertext/commitment tampering, sender-retained ownership, canonical digest
encoding, hidden-source wire shape and bounds. The default-feature regression
uses the existing integration test targets, not the empty `notes::tests` unit
filter. The old-note envelope caller explicitly dereferences its `Arc` key for
the existing `KemDecapsulator` trait API; no old-note wire or economics change.
Passing these checks does not establish a public proof,
venue integration, independent operator custody or production PQ security.
