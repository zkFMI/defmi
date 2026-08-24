# DeFMI VM for Avalanche L1

This is a dedicated Avalanche custom VM. It does not execute EVM bytecode and
does not require Solidity. Avalanche consensus orders three native transition
types:

1. register an asset rail;
2. open an opaque committed account on that rail;
3. atomically apply a multi-leg zkPI settlement.

Every transition carries the same configurable k-of-n Ed25519 approval used by
the QOMM/DeFMI service. The VM independently checks the statement, signer
epoch, threshold, its own Avalanche Chain ID, the signed pre-state root,
deadline, nullifier, asset rail, account sequence and before commitment. A
committee signature issued for another L1 or an earlier global state is not a
valid transaction here. Only commitments and digests become chain data.

The lifecycle scaffolding is adapted from AvalancheGo's maintained XSVM at the
commit and license recorded in `THIRD_PARTY_NOTICES.md`; the DeFMI transaction,
authorization and state code is project-specific.

## Local gates

```sh
go test ./...
go vet ./...
go build -trimpath -o build/defmivm ./cmd/defmivm
```

`scripts/run-local-l1.sh` is the deployment acceptance entrypoint. Set
`AVALANCHEGO_PATH` and `AVALANCHE_NETWORK_RUNNER` to pinned executable paths (or
put those binaries on `PATH`) and run it from any directory. It builds and
installs the VM into a disposable plugin directory, starts a five-node local L1,
submits registration, account and settlement transactions through the JSON-RPC
surface, restarts one validator, verifies root convergence, writes
`artifacts/avalanche_l1_acceptance.json`, and stops the network. The script does
not download or silently replace either external binary.
