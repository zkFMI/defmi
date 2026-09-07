# PQ archival checkpoints and offline VM recovery

The VM exposes a checkpoint API and a `qomm-avalanche-vm recovery` CLI.
They reuse the existing canonical state-sync snapshot, block encoding, state
validation, and hybrid governance quorum. No new signature algorithm or
application dependency is introduced.

A checkpoint attests to the exact snapshot and retained archive bytes at its
issue time. It does **not** establish that an old classical signature was
quantum resistant when it was originally made.

## Trust and lifecycle

The checkpoint statement binds its format version, the
`defmi-hybrid-governance-v2` authority protocol, canonical state summary,
archive digest, and issue time. The summary binds the network, chain, genesis,
block, height, timestamp, state root, snapshot digest, and chunk Merkle root.

Checkpoint publication requires a current hybrid governance quorum and keys
valid at both publication and the recorded issue time. Publication permits at
most five minutes between those times.

Recovery requires two separate authorizations:

1. Verify the archival checkpoint using independently pinned historical
   governance keys at its issue time.
2. Verify a fresh recovery approval using independently pinned current
   governance keys at the host's current time.

The fresh approval binds an independently obtained recovery policy: exact
checkpoint digest, network, chain, genesis, minimum height, target identifier,
nonce, not-before time, and expiry. The approval window is at most one hour.
The checkpoint approval cannot be reused as the recovery approval. A retired or
expired committee cannot authorize a new recovery.

The caller must obtain the policy and both committee records through an
authenticated operator channel. They are not discovered from the untrusted
backup. In particular, accepting a checkpoint's own claimed digest as the
expected checkpoint would defeat rollback protection.

Both signatures in each governance approval are mandatory, duplicate node votes
are rejected by the existing quorum verifier, and a single node cannot satisfy
a committee configured with a larger threshold.

## Existing canonical snapshot

A checkpoint operates on:

- `summary.bin`: existing `StateSummary::encode()` bytes.
- `snapshot.bin`: existing `state_sync::build_summary()` snapshot.
- `archive.bin`: exact retained records or an operator-maintained archival
  manifest, bounded to 64 MiB.

The archive digest attests to the supplied bytes; it does not independently
verify every historical signature in an archival manifest or its external
objects. Retain those objects and their original provenance separately.

Unknown application state is rejected by the default DeFMI CLI. Application
hosts call the library API with their own `ApplicationRuntime`; its
`validate_state` hook runs before checkpoint preparation and before a
restored state is returned. DeFMI does not import Aethel or any other application.

## CLI workflow

All output files must be new. The caller supplies paths; private signing keys
never enter this CLI.

```text
qomm-avalanche-vm recovery prepare \
  --summary summary.bin --snapshot snapshot.bin --archive archive.bin \
  --out checkpoint-statement.json

qomm-avalanche-vm recovery seal \
  --statement checkpoint-statement.json --approval checkpoint-approval.json \
  --committee historical-committee.bin --out checkpoint.json

qomm-avalanche-vm recovery request \
  --checkpoint checkpoint.json --policy independently-pinned-policy.json \
  --out restore-request.json

qomm-avalanche-vm recovery restore \
  --checkpoint checkpoint.json --snapshot snapshot.bin --archive archive.bin \
  --policy independently-pinned-policy.json \
  --historical-committee historical-committee.bin \
  --current-committee current-committee.bin \
  --approval fresh-restore-approval.json --out-dir restored
```

Committee files use the existing canonical `Genesis` encoding to carry
epoch, threshold, and public member records. The current committee file is a
trusted committee record, not an instruction to create a new chain or replace
the original genesis hash.

`prepare` and `request` expose the statement and before-root to sign.
The existing governance participants produce `QuorumApproval` values using
their custody-backed signer handles. `ApprovalWire` uses the same JSON
field names as the existing governance RPC approval.

A successful restore writes canonical `state.json`, `block.bin`,
`summary.bin`, and a final `restored.json` receipt into a newly
created private directory. It refuses to overwrite an existing directory.
Every authorization, archive hash, snapshot, and application validation check
finishes before that directory is created.

This is an **offline recovery handoff**. It does not replace a running
validator's database, select a live network frontier, prove WAN consensus, or
activate a new validator. Operators must use the host's normal validated
installation/cutover procedure. A restored offline snapshot is not a claim that
an independent multi-operator disaster recovery exercise has been completed.

## Verification

The remote `qomm-avalanche-vm --test recovery` target uses real generated
hybrid governance keys and actual VM asset-registration transactions. It tests:

- State recovery after archival keys expire, with a fresh current quorum.
- Preservation of the applied-transaction index and rejection of a replay.
- Successful new VM execution after restoration.
- Rejection of old-authority new transactions, insufficient approvals, missing
  PQ halves, signature tampering, altered archive/snapshot bytes, rollback,
  mismatched genesis, changed nonce, expired recovery policy, unknown versions,
  trailing checkpoint bytes, and unsupported application state.
- The real prepare → seal → request → restore CLI pipeline in child processes,
  canonical output readback, and refusal to overwrite a previous recovery.

These are deterministic local-network/offline acceptance tests executed on the
required remote Rust runner. Report their actual command result separately from
source availability and from live operator deployment evidence.

