# Third-party notice

The Rust RPCChainVM boundary is a focused fork of Ava Labs'
`ava-labs/avalanche-rs` at commit
`1bfa6d5e87e8c5ad0b855a928a3b447e594daa63`. Its exact provenance and protocol
adaptations are recorded in `rust/vendor/avalanche-rs-qomm/UPSTREAM.md`.

The fork is distributed under the Ava Labs Ecosystem License 1.1. The complete,
unmodified license is retained at `rust/vendor/avalanche-rs-qomm/LICENSE` and
must accompany source and binary distributions. Production use must remain on
the Avalanche Authorized Platform as defined by that license.

RPCChainVM protocol schemas are pinned to AvalancheGo v1.14.2, commit
`6e5acf909c7a16b991142d6b3979bac5699bdb68`. The full acceptance artifact
records the exact AvalancheGo and network-runner binary hashes used with the
fork. Those schemas, including the HTTP reader and response-writer callback
services, retain AvalancheGo's BSD 3-Clause license at
`rust/vendor/avalanche-rs-qomm/AVALANCHEGO_LICENSE`.
