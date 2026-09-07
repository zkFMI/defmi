# Soundness finding: general opening proofs where a zero-opening is required

Date: 2026-09-07. Status: **fixed the same day** in all three copies (zkpi, defmi, qomm): every site below now uses the zero-relation opening, the threshold assembly gives the linkage and winner nonces no value component (`threshold_sigma::Relation::Zero`), the rule audit proves `!=` as an inverse pinned to a commitment to one, and the tests below pass as regressions. Original status at discovery: open. Found while writing the
zkfmi.com page "Cryptography in use"; confirmed by the two tests below, run
against `defmi/rust` at HEAD on the day (both fail, i.e. both forgeries are
accepted). Tests were run locally on macOS; nothing in the repository was
changed.

## 要約（日本語）

値の成分が 0 であることを示す必要のある 5 か所の検証器が、一般の開封証明
（`verify_opening`: `residual = g·v + h·r` を開ける (v, r) を知っている、という
主張）を検査している。開封値を知る証明者は任意の v についてこの証明を作れる
ので、これらの証明は「合計が一致する」「値が範囲内にある」「公開値が commitment
の値である」を何も保証しない。値を 0 に固定する `prove_zero_opening` /
`verify_zero_opening`（`z_value == 0` を要求し、value 生成元を identity にして
検証する）は crate に既にあり、note の支出の残高証明（N3 の修正）で使われて
いる。修正はこれを 5 か所で使うこと。閾値版では各ノードの連結 nonce の値成分
を 0 にする（`linkage_nonce = (0, k')`）。トランスクリプトに `relation` が
一つ増えるので、zkPI のテストベクタは再生成が必要。対象 crate は
zkpi・defmi・qomm の 3 リポジトリに複製されており、すべてに同じ変更が要る。

## The gap

`qomm-zk/src/sigma.rs`: `prove_opening` / `verify_opening` prove knowledge of
`(v, r)` with `C = g·v + h·r`. `prove_zero_opening` / `verify_zero_opening`
(added as the N3 fix) additionally force `z_value = 0` and verify under a key
whose value generator is the identity, so they prove `C = h·r`.

Every site below forms a residual that must be a pure multiple of `h` and then
checks it with the *general* proof. The holder of the openings can prove a
general opening of the residual for any claimed value.

| site | statement intended | file (defmi copy) | also in |
|---|---|---|---|
| reconciliation against a register | `Σ C_i − A_a·N` is a multiple of `h` (totals agree) | `qomm-defmi/src/reconcile.rs:133,170` | qomm |
| bit-decomposition range linkage | `C − Σ 2^j C_j` is a multiple of `h` | `qomm-zk/src/bitrange.rs:129-136,181` | zkpi, qomm |
| threshold range linkage (zkPI ranges, threshold DvP remainders) | same | `qomm-proofs/src/threshold_range.rs:1019-1044,1098` | zkpi, qomm |
| quote proof, winner opens to revealed value | `C_winner − g·v` is a multiple of `h` | `qomm-proofs/src/quote_proof.rs:1352-1362` | zkpi, qomm |
| rule audit, equality step | commitment equality | `qomm-proofs/src/rule_audit.rs:791` | zkpi, qomm |

Production exposure: the threshold range proofs are what `RangeEvidence::Threshold`
carries in zkPI and what `qomm-avalanche-vm/src/execution.rs`, `qomm-transport`
(`zkpi_issuer.rs`, `proof_party.rs`, `binding.rs`) and `oclob-settlement`
verify. Until fixed, a range proof produced by a colluding quorum, or by anyone
holding the opening, is accepted for a value outside the range; the proofs add
no soundness beyond trust in the signing quorum. Bulletproof range proofs on
the account and note rails are unaffected. The quote proof's minimality ranges
are Bulletproofs and unaffected; only the "winner opens to the revealed value"
step is.

## Fix

1. `reconcile.rs`: `prove_zero_opening` / `verify_zero_opening` on the residual.
2. `bitrange.rs`: same for the linkage.
3. `threshold_range.rs`: each node's `linkage_nonce` becomes `(Scalar::ZERO, k')`
   and its `linkage` announcement `h·k'`; the assembled `linkage.z_value` is then
   `c · Σ coef_i · residual_value_i`, which is 0 for an honest quorum;
   verification uses `verify_zero_opening` (which also appends
   `relation = zero-opening:v2` to the transcript). `verify_threshold_range`
   rejects `z_value != 0`.
4. `quote_proof.rs`: `verify_zero_opening` on `shift(C_winner, v)`; prover side
   `prove_zero_opening`.
5. `rule_audit.rs` `Step::Equality`: zero-opening.
6. Regenerate the zkPI wire vectors (`qomm-zkpi-verify --vectors`) because the
   linkage transcript changes; note it in `ZKPI_WIRE.md` as a format change.
7. Apply to all three copies (`zkpi/rust`, `defmi/rust`, `qomm/rust`) and to the
   codex PQC branches, which carry these crates.
8. Add the two tests below (they must then pass) and a threshold variant.

## Tests (failing at discovery, passing after the fix)

`qomm-defmi/tests/reconcile_forgery.rs`:

```rust
//! A prover who knows the openings can make the reconciliation proof accept a
//! total the balances do not sum to, because the check is a general opening
//! proof of the residual rather than a proof that its value part is zero.

use curve25519_dalek::scalar::Scalar;
use qomm_defmi::reconcile::*;
use qomm_zk::pedersen::{asset_tag, Pedersen};
use qomm_zk::sigma::prove_opening;
use merlin::Transcript;
use rand::rngs::OsRng;

#[test]
fn a_dishonest_total_is_refused() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1").with_value_generator(asset_tag(7));
    let values = [1_000u64, 2_000, 3_000];
    let blindings: Vec<Scalar> = (0..3).map(|_| Scalar::random(&mut rng)).collect();
    let commitments: Vec<_> = values.iter().zip(&blindings).map(|(v, r)| key.commit_u64(*v, r)).collect();
    let true_total: u64 = values.iter().sum();
    let claimed = true_total + 500; // the register says 6,500; the ledger holds 6,000
    let attestation = Attestation { register: "reg".into(), account: "acct".into(), asset: "7".into(), as_of: "2026-09-07".into(), total: claimed, signature: None };
    // honest path refuses
    let honest = prove(&key, &commitments, &blindings, &attestation, &mut rng).unwrap();
    assert!(check(&key, &commitments, &honest, None).is_err(), "honest prover with wrong total must fail");
    // dishonest path: open the residual with value (true - claimed) instead of zero
    let residual = aggregate(&commitments) - key.g * Scalar::from(claimed);
    let delta = Scalar::from(true_total) - Scalar::from(claimed);
    let combined: Scalar = blindings.iter().sum();
    let mut t = Transcript::new(b"qomm:defmi:reconcile");
    t.append_message(b"attestation", &attestation.body());
    let forged = prove_opening(&key, &mut t, &residual, &delta, &combined, &mut rng);
    let rec = Reconciliation { attestation: attestation.clone(), positions: commitments.len(), proof: forged };
    assert!(check(&key, &commitments, &rec, None).is_err(), "FORGERY ACCEPTED: total {} accepted for balances summing to {}", claimed, true_total);
}
```

`qomm-zk/tests/bitrange_forgery.rs`:

```rust
//! The linkage of a bit-decomposition range proof must pin the residual's
//! value part to zero; otherwise bits for a small honest value can be linked
//! to a commitment of a value outside the range.

use curve25519_dalek::scalar::Scalar;
use qomm_zk::bitrange::*;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::prove_opening;
use rand::rngs::OsRng;

#[test]
fn bits_of_another_value_do_not_link() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:zk:test");
    let bits = 8usize;
    let ctx: &[u8] = b"ctx";
    // the commitment under test is to 300, outside [0, 256)
    let r = Scalar::random(&mut rng);
    let big = key.commit_u64(300, &r);
    // honest bit commitments for 44 under fresh blindings
    let small = key.commit_u64(44, &r);
    let mut proof = prove_range(&key, &small, 44, &r, bits, ctx, &mut rng).expect("honest proof");
    // re-prove only the linkage against `big`: residual = big - sum 2^j C_j has
    // value part 300 - 44 = 256 and blinding part r - sum 2^j r_j. The prover
    // cannot know sum 2^j r_j from the proof alone, so recompute it the way a
    // dishonest prover who made the bits would: prove afresh with known blindings.
    // Simplest faithful route: build bits ourselves.
    let bit_blindings: Vec<Scalar> = (0..bits).map(|_| Scalar::random(&mut rng)).collect();
    let mut aggregate_blinding = Scalar::ZERO;
    let mut weight = Scalar::ONE;
    let value_bits: Vec<u64> = (0..bits).map(|j| (44u64 >> j) & 1).collect();
    let mut bit_commitments = Vec::new();
    let mut bit_proofs = Vec::new();
    for (j, (b, rb)) in value_bits.iter().zip(&bit_blindings).enumerate() {
        let c = key.commit_u64(*b, rb);
        let mut t = component_transcript(&bit_context(ctx, j).unwrap());
        bit_proofs.push(qomm_zk::sigma::prove_bit(&key, &mut t, &c, *b == 1, rb, &mut rng));
        bit_commitments.push(c);
        aggregate_blinding += rb * weight;
        weight += weight;
    }
    let aggregate: curve25519_dalek::ristretto::RistrettoPoint = bit_commitments.iter().zip(std::iter::successors(Some(Scalar::ONE), |w| Some(w + w))).map(|(c, w)| c * w).sum();
    let residual = big - aggregate;
    let mut t = component_transcript(&suffixed_context(ctx, b":link"));
    let linkage = prove_opening(&key, &mut t, &residual, &Scalar::from(256u64), &(r - aggregate_blinding), &mut rng);
    proof.bit_commitments = bit_commitments;
    proof.bit_proofs = bit_proofs;
    proof.linkage = linkage;
    assert!(!verify_range(&key, &big, &proof, ctx), "FORGERY ACCEPTED: 300 passed an 8-bit range proof");
}
```

Output on 2026-09-07:

```
test a_dishonest_total_is_refused ... FAILED
FORGERY ACCEPTED: total 6500 accepted for balances summing to 6000
test bits_of_another_value_do_not_link ... FAILED
FORGERY ACCEPTED: 300 passed an 8-bit range proof
```
