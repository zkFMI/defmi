# DeFMI VM deployment for Avalanche L1

The product VM is implemented in Rust at `rust/defmi-avalanche-vm`. This
directory contains its Avalanche L1 genesis configuration and reproducible
acceptance launchers. No QOMM-owned alternative VM implementation is retained.

The VM is a dedicated non-EVM state machine. AvalancheGo remains an external
consensus host and launches the Rust executable as a separate process through
RPCChainVM protocol 45. The focused protocol fork lives at
`rust/vendor/avalanche-rs-qomm`; DeFMI transactions, validation, canonical
state, ordering, reservations and settlement live in QOMM Rust crates.

The authoritative product rail is account-free. CSD-authorized confidential
notes are reserved before quoting, a seven-party MPC committee finalizes zkPI,
and DeFMI atomically consumes the delegated one-use notes without a Maker or
Taker signature after the quote.

## Build

```sh
cd rust
env -u MP_SPDZ_ROOT cargo build --release \
  -p defmi-avalanche-vm --bin qomm-avalanche-vm \
  -p defmi-harness --bin run_avalanche_l1_acceptance
```

The VM deliberately does not link `libSPDZ`. Stock MP-SPDZ runs as seven
external processes only in the full product gate.

## Acceptance gates

Set `AVALANCHEGO_PATH` and `AVALANCHE_NETWORK_RUNNER` to pinned executable
paths. The scripts never download or silently substitute either binary.

- `scripts/run-local-l1.sh` checks five validators, native state transitions,
  state-root agreement and validator restart recovery. It writes
  `artifacts/avalanche_l1_acceptance.json`.
- `scripts/run-full-qomm-l1.sh` additionally checks external KYB evidence,
  process-isolated CSD signing, seven external MP-SPDZ parties, pre-quote note
  reservations, shared legal-entity caps, rejection of a concurrent excess
  RFQ, threshold zkPI, atomic multi-RFQ DvP, no post-quote owner signature,
  account-free settlement and restart recovery. It writes
  `artifacts/avalanche_qomm_full_acceptance.json`.
