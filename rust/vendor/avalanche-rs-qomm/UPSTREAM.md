# Local avalanche-rs protocol fork

This directory is a focused local fork of the official
[`ava-labs/avalanche-rs`](https://github.com/ava-labs/avalanche-rs) RPCChainVM
layer. The upstream base inspected for this fork is commit
`1bfa6d5e87e8c5ad0b855a928a3b447e594daa63`.

The pinned upstream base emitted RPCChainVM protocol 33. QOMM targets
AvalancheGo `v1.14.2` (commit
`6e5acf909c7a16b991142d6b3979bac5699bdb68`), whose required protocol is 45.
The protobuf files under
`crates/avalanche-rpcchainvm/proto/{vm,http,rpcdb,appsender,io/reader}`,
including `http/responsewriter`, are exact copies from that AvalancheGo release.
They remain under AvalancheGo's BSD 3-Clause license, retained in
`AVALANCHEGO_LICENSE`. `metrics.proto` comes from
`prometheus/client_model` `v0.6.2`; the Google well-known schemas come from the
Protocol Buffers distribution.

QOMM adds a bounded Rust client for AvalancheGo's temporary reader and response
writer services. Ordinary HTTP/1 JSON-RPC continues to use `HandleSimple`;
ordinary HTTP/2 requests use this callback bridge. Protocol upgrades such as
WebSockets are explicitly rejected because the QOMM API has no streaming
method.

Only the language-neutral Avalanche process boundary belongs here. DeFMI
transactions, validation, canonical state, ordering, and settlement remain in
QOMM Rust crates. Any future AvalancheGo upgrade must update the pinned source,
protocol number, generated-binding tests, and five-validator acceptance result
together.
