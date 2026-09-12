# Fresh-network PQC policy

This implementation selects the governance signature suite when a new DeFMI
network is created. It does not switch a running ledger and it does not migrate
existing state. Existing genesis bytes and policy-free saved state retain their
previous behavior.

## Policy and genesis

A fresh deployment supplies one canonical JSON policy:

```json
{
  "version": 1,
  "deployment_id": "example-fresh-deployment",
  "mode": "on"
}
```

`mode: "off"` selects Ed25519 governance signatures. `mode: "on"` selects the
hybrid Ed25519 **and** ML-DSA-65 suite. The `deployment_id` and mode are fixed by
genesis; changing either creates a different deployment identity.

Policy-free genesis continues to encode as `QOMMGEN2`. A genesis carrying the
policy encodes as `QOMMGEN3` and appends the canonical policy bytes. Committee
keys must use the suite selected by the policy. The policy is also committed by
the committee digest, initial state root, every persisted state, restart and
historical-block load, and state-sync validation. State-sync already binds its
peer exchange to the genesis hash, so peers with a different policy do not
share a chain identity. `defmivm.genesis` returns the exact policy for external
readback.

The public deterministic committee helpers are lab fixtures. They demonstrate
the two suites but are not independent operator custody or production key
enrollment.

## Consensus execution boundary

Every state transition first requires exact equality between the state's policy
and the governance authority's policy. Under a fresh `mode: "on"` research
build, the executor is closed to these converted methods only:

- `defmivm.issueResearchCoCodePolicy`
- `defmivm.issueResearchCoCodeBook`
- `defmivm.issueResearchCoCodeProofBegin`
- `defmivm.issueResearchCoCodeProofChunk`
- `defmivm.issueResearchCoCodeCommit`

Names are matched exactly. Established or similarly named methods fail closed.
The research policy must use the query-agreement-v2 protocol, carry a canonical
lowercase SHA-512 roster pin, and use the same deployment ID as genesis. The
default build contains none of the research methods. Policy-free deployments
retain their established hybrid-governance behavior, while fresh `mode: "off"`
deployments retain the established executor surface with Ed25519 governance.

## Acceptance driver

The opt-in driver accepts the policy separately from the live-network config:

```sh
cocode-canonical-acceptance OUTPUT_DIR \
  --deployment-policy POLICY.json \
  --query-roster-sha512 LOWERCASE_128_HEX \
  --live-config LIVE.json
```

For `mode: "on"`, the roster pin is required and must equal the proof policy's
pin. The driver requires exact policy equality across its input, the proof
deployment, live genesis readback, restart readback, and the top-level and live
receipts. JSON tooling that cannot preserve 64-bit integers must not round
committee key validity fields when constructing genesis.

## Evidence boundary

This is a greenfield research integration. Passing a same-host five-validator
run demonstrates the selected suite, canonical proof path, equal roots and
restart recovery for that frozen binary. It does not establish independent
operators, protected key custody, a full QOMM or OCLOB venue conversion,
formal QROM/composition security, an independent cryptographic review, or
production approval.

### 2026-09-09 bounded acceptance snapshot

The frozen `mode: "on"` research run completed 740 accepted canonical
transitions, including fill and no-fill proofs, on five same-host AvalancheGo
validators. All five ended at root
`0d14f6c910106635f027ad0f7d588ae10367985c83eb76e344dfbbe87f4704b9`.
A 256,567,624-byte pending state (367 proof chunks) recovered through a node-3
restart in 769 ms, and the final state recovered in 704 ms. All eight declared
negative gates rejected. The run verdict is `smoke_only`, with primary metric
1 and elapsed time 1,131.302320571 seconds.

The live receipt is
`../zkfmi-crypto/research/cosnark-trial/artifacts/greenfield-live-002/live-receipt.json`
(SHA-256
`e6a38200e23bcd014189e1a418b1c1eddebd5c04c2d0d3b60a2295c3d6a4073f`).
The canonical receipt SHA-256 is
`209c637cfbc619bbbb28c2d9c2899000688d18b6f0fa0b743927235d779ff241`.
The run used frozen VM SHA-256
`584d5644906c4c6b27c6f9222db9b61f20d26f9e7a70df577baa20c6a58d9d34`
and driver SHA-256
`3858f41036e6b57b9dc1b1ba4a78ced1245633e36b15f3dab089bdc0f8b667fd`.

Current-source tests and warnings-denied Clippy were run from a later frozen
snapshot. Its only executable difference from the live snapshot restores the
established legacy invalid-committee diagnostic; the other changes are focused
tests and formatting. The current-source VM and driver SHA-256 values are,
respectively,
`708a4c60d1607628467b4fd19207f41027e9c847146b70bbc6a1577fe81fe4f4`
and
`6e707ba73b122f79bc298898e4be0d924c35818230c8fdbf1616c329cbd950e4`.
These two evidence sets are deliberately not presented as byte-identical.
