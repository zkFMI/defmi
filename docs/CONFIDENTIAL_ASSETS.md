# Confidential assets on the native Ristretto rail

Status: research implementation. A five-validator native lifecycle, restart and
recipient RPC recovery were observed; see [the execution record](CONFIDENTIAL_ASSETS_ACCEPTANCE_2026-09-12.md). This is not an independently audited construction or a
post-quantum proof system. PQC On refuses these operations.

## Public and recipient data

A confidential note uses the existing `assetID` slot for a randomized Pedersen
commitment to an asset identifier. It is not the plaintext ID or a deterministic
hash. A public `AssetIdentity` binds that commitment to a blinded asset generator
and a public eligible registry cohort. A same-branch CDS OR proof establishes
that both describe one registered asset. Cohorts contain 2 to 64 sorted, distinct,
registered identifiers, with no artificial padding.

The amount commitment uses that blinded generator. The existing Triptych proof
binds ownership and amount to the same hidden input in a mixed-asset note ring.
Canonical input note IDs retain each input identity; they are not relabelled with
the output identity. Recipients decrypt a versioned hybrid-encrypted opening
containing the real asset identifier, tag blinding, quantity and effective value
blinding. This identifies even a zero-quantity output. Positive-value asset
conservation relies on the independent asset generators and the existing amount
and balance proofs. A zero commitment alone does not encode a unique asset type.

Asset definitions and eligible cohorts remain public. A facility retains its
randomized identity through reservation and settlement. Fresh issuances and
ordinary transfers can choose fresh identities. This does not hide venue, market,
issuer, timing, recipient disclosure or other metadata that can narrow the cohort.
Do not claim transaction unlinkability or a minimum effective anonymity set from
the cohort size alone.

## Native operations

- `defmivm.issueConfidentialAssetIdentity`: register a proved randomized identity.
- `defmivm.issueConfidentialNote`: issuer-authorized issuance with a range proof.
- `defmivm.issueConfidentialNoteTransfer`: canonical mixed-asset spend and outputs.
- `defmivm.issueConfidentialNoteReservation`: note funding plus the existing credit
  transition, joined by a same-value proof across generators.
- `defmivm.issueConfidentialNoteFill`: version 3 application fill, full existing
  threshold DvP verification, asset linkage and four claim conversions under one
  committee certificate.

The normal claim-redemption and release endpoints recognize confidential state.
Each partial fill stores its already-certified refund conversion and encrypted
asset opening. Expiry can release the remainder without a new secret or later
committee approval. Redemptions produce recipient-encrypted confidential notes
that can be spent again.

The public legacy methods continue to require legacy values. A bare version 3
fill cannot execute on the legacy fill endpoint. The new version currently
rejects batch certificates. Existing venue clients are not automatically switched
by adding these methods; callers must create and verify the confidential wrapper
and sign its complete statement.

## Wallet read APIs

- `defmivm.listConfidentialNotes` accepts only `after` and `limit`; it returns
  canonical notes with their proved identities without asking for an asset.
- `defmivm.confidentialAssetIdentity` returns a canonical identity by its public
  randomized commitment.
- `defmivm.confidentialNoteClaim` returns the claim, its identity and the hybrid
  encrypted asset opening needed by the recipient.

The matching `AvalancheRpcClient` methods validate identity proofs, canonical
note IDs, page order, roots and claim bindings. Callers must pin a state root
while combining pages. The live run uses these SDK methods for actual wallet
recovery. Committee members can call `ConfidentialFill::verify_unsigned` before
signing; the ordinary signed verifier remains mandatory for native execution.

## References and boundary

The generator construction follows [Elements Confidential Assets](https://elementsproject.org/features/issued-assets/investigation).
The asset-membership adapter uses the [CDS OR composition](https://ir.cwi.nl/pub/1456/1456D.pdf),
with a shared challenge for the two relations in each branch. No source code was
copied from either reference. Existing Tari Triptych remains pinned at
`bf0cb42fff55636a8bb037020411fb3a050af23f` under BSD-3-Clause. The equality-of-value,
range, threshold authorization and note proof cores retain existing dependencies.

The rough harness seals contract and source hashes, performs build preflight,
launches the whole canonical lifecycle, saves every transaction and state readback,
and records the final wallet balances. Its one synthetic lifecycle can produce
only `smoke_only` or `rejected`. It does not establish live consensus, independent
MPC parties, private DeKYX service approval, venue integration or cryptographic
security review. See each run manifest, outcome and receipt for exact evidence.
