//! Shared netting-cycle measurement used by the DeFMI and DeCCP harnesses.

use crate::HarnessResult;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use qomm_defmi::assets::AssetRegistry;
use qomm_defmi::netting::{
    prove_cash_reference, BatchAttestation, Cycle, Mode, Order, PositionBook,
};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::{deal_quorum, frost, Bounds, Instruction, Issuer, Openings, Venue};
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::time::Instant;

const ACCOUNT_BITS: usize = 64;

struct Committee {
    issuer: Issuer,
    shares: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: frost::keys::PublicKeyPackage,
}

impl Committee {
    fn new(key: Pedersen, rng: &mut OsRng) -> HarnessResult<Self> {
        let bounds = Bounds::default();
        let (secret, public) = deal_quorum(7, 3, rng)?;
        let shares = secret
            .into_iter()
            .map(|(id, share)| {
                frost::keys::KeyPackage::try_from(share)
                    .map(|package| (id, package))
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<_, _>>()
            .map_err(|error: String| -> Box<dyn std::error::Error> { error.into() })?;
        Ok(Self {
            issuer: Issuer::new(key, bounds),
            shares,
            public,
        })
    }

    fn venue(&self, key: Pedersen) -> Venue {
        Venue::new(key, &Bounds::default(), self.public.clone())
    }

    #[allow(clippy::too_many_arguments)]
    fn issue(
        &self,
        quantity: u64,
        price: u64,
        asset: u32,
        payer: RistrettoPoint,
        payee: RistrettoPoint,
        nonce: u64,
        rng: &mut OsRng,
    ) -> HarnessResult<(Instruction, Openings)> {
        let mut nonce_bytes = [0u8; 32];
        nonce_bytes[24..].copy_from_slice(&nonce.to_be_bytes());
        let (digest, openings, partial) = self.issuer.build(
            quantity,
            price,
            asset,
            payer,
            payee,
            1_500,
            nonce_bytes,
            1_599_845,
            rng,
        )?;
        let chosen = self.shares.keys().take(3).cloned().collect::<Vec<_>>();
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for id in &chosen {
            let (nonce, commitment) = frost::round1::commit(self.shares[id].signing_share(), rng);
            nonces.insert(*id, nonce);
            commitments.insert(*id, commitment);
        }
        let signing = frost::SigningPackage::new(commitments, &digest);
        let mut signatures = BTreeMap::new();
        for id in &chosen {
            signatures.insert(
                *id,
                frost::round2::sign(&signing, &nonces[id], &self.shares[id])?,
            );
        }
        let signature = frost::aggregate(&signing, &signatures, &self.public)?;
        Ok((partial.sealed(signature), openings))
    }
}

struct NetHolder {
    securities: (i64, Scalar),
    cash: (i64, Scalar),
}

fn signed_scalar(value: i64) -> Scalar {
    if value >= 0 {
        Scalar::from(value as u64)
    } else {
        -Scalar::from(value.unsigned_abs())
    }
}

/// Execute the same real DeFMI netting cycle used by `run_defmi`.
pub fn one_cycle(
    mode: Mode,
    trades: usize,
    participants: usize,
    attest: bool,
    seed: u64,
    rng: &mut OsRng,
) -> HarnessResult<serde_json::Value> {
    if participants < 2 {
        return Err("a cycle needs at least two participants".into());
    }
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key.clone(), 16);
    let (sec_tag, _) = registry.blind(3, false, rng)?;
    let (cash_tag, _) = registry.blind(0, false, rng)?;
    let mut sec_book = PositionBook::new(
        key.clone(),
        sec_tag,
        mode.securities_net(),
        "securities",
        ACCOUNT_BITS,
    );
    let mut cash_book =
        PositionBook::new(key.clone(), cash_tag, mode.cash_net(), "cash", ACCOUNT_BITS);
    let mut holders = BTreeMap::new();
    for index in 0..participants {
        let handle = format!("p{index}").into_bytes();
        let holder = NetHolder {
            securities: (10_000_000, Scalar::random(&mut *rng)),
            cash: (
                (100_000_000_000u64 % (1u64 << 40)) as i64,
                Scalar::random(&mut *rng),
            ),
        };
        sec_book.open(
            &handle,
            sec_book
                .tagged()
                .commit(&signed_scalar(holder.securities.0), &holder.securities.1),
        )?;
        cash_book.open(
            &handle,
            cash_book
                .tagged()
                .commit(&signed_scalar(holder.cash.0), &holder.cash.1),
        )?;
        holders.insert(handle, holder);
    }
    let committee = Committee::new(key.clone(), rng)?;
    let batch_key = SigningKey::from_bytes(&[7u8; 32]);
    let mut cycle = Cycle::new(
        key.clone(),
        format!("harness-{seed}").into_bytes(),
        mode,
        sec_book,
        cash_book,
        committee.venue(key.clone()),
        attest,
        attest.then_some(batch_key.verifying_key()),
    )?;
    let handles = holders.keys().cloned().collect::<Vec<_>>();
    let mut state = seed.wrapping_add(1);
    let mut build_total = 0.0;
    let mut verify_total = 0.0;
    let mut admitted = 0usize;
    let mut refused = 0usize;
    for order_index in 0..trades {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let seller_index = (state as usize) % participants;
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let buyer_index = (seller_index + 1 + (state as usize % (participants - 1))) % participants;
        let seller = &handles[seller_index];
        let buyer = &handles[buyer_index];
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let quantity = 10 + state % 50;
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let price = 90_000 + state % 20_000;
        let trade_value = quantity * price;
        let payer = RistrettoPoint::mul_base(&Scalar::from(buyer_index as u64 + 101));
        let payee = RistrettoPoint::mul_base(&Scalar::from(seller_index as u64 + 201));
        let (instruction, openings) =
            committee.issue(quantity, price, 3, payer, payee, order_index as u64, rng)?;

        let started = Instant::now();
        let cash_blinding = Scalar::random(&mut *rng);
        let cash_reference = key.commit_u64(trade_value, &cash_blinding);
        let value_proof = prove_cash_reference(
            &key,
            &instruction.price_commitment,
            price,
            &openings.price,
            quantity,
            &openings.amount,
            &cash_blinding,
            rng,
        );
        let sold = holders[seller].securities;
        let bought = holders[buyer].cash;
        let sec_delta = Scalar::random(&mut *rng);
        let cash_delta = Scalar::random(&mut *rng);
        let sec_leg = match cycle.securities.build_leg(
            seller,
            buyer,
            quantity,
            &sec_delta,
            sold.0,
            &sold.1,
            &instruction.amount_commitment,
            &openings.amount,
            0,
            &Scalar::ZERO,
            rng,
        ) {
            Ok(leg) => leg,
            Err(_) => {
                refused += 1;
                continue;
            }
        };
        let cash_leg = match cycle.cash.build_leg(
            buyer,
            seller,
            trade_value,
            &cash_delta,
            bought.0,
            &bought.1,
            &cash_reference,
            &cash_blinding,
            0,
            &Scalar::ZERO,
            rng,
        ) {
            Ok(leg) => leg,
            Err(_) => {
                refused += 1;
                continue;
            }
        };
        build_total += started.elapsed().as_secs_f64() * 1e3;
        let order = Order {
            instruction,
            securities: sec_leg,
            cash: cash_leg,
            cash_reference,
            value_proof,
        };
        let started = Instant::now();
        let accepted = cycle.admit(&order, 1_000, rng).is_ok();
        verify_total += started.elapsed().as_secs_f64() * 1e3;
        if !accepted {
            refused += 1;
            continue;
        }
        admitted += 1;
        {
            let sold = holders.get_mut(seller).expect("holder exists");
            sold.securities.0 -= quantity as i64;
            sold.securities.1 -= sec_delta;
            sold.cash.0 += trade_value as i64;
            sold.cash.1 += cash_delta;
        }
        {
            let bought = holders.get_mut(buyer).expect("holder exists");
            bought.securities.0 += quantity as i64;
            bought.securities.1 += sec_delta;
            bought.cash.0 -= trade_value as i64;
            bought.cash.1 -= cash_delta;
        }
    }

    let started = Instant::now();
    let mut securities_coverage = Vec::new();
    let mut cash_coverage = Vec::new();
    if cycle.securities.net {
        for (handle, holder) in &holders {
            securities_coverage.push(cycle.securities.build_coverage(
                handle,
                holder.securities.0,
                &holder.securities.1,
                0,
                &Scalar::ZERO,
            )?);
        }
    }
    if cycle.cash.net {
        for (handle, holder) in &holders {
            cash_coverage.push(cycle.cash.build_coverage(
                handle,
                holder.cash.0,
                &holder.cash.1,
                0,
                &Scalar::ZERO,
            )?);
        }
    }
    let close_build = started.elapsed().as_secs_f64() * 1e3;
    let attestation = attest.then(|| BatchAttestation::sign(&batch_key, cycle.batch_digest()));
    let started = Instant::now();
    cycle.close(&securities_coverage, &cash_coverage, attestation.as_ref())?;
    let close_verify = started.elapsed().as_secs_f64() * 1e3;
    Ok(serde_json::json!({
        "mode": format!("{}{}", mode.label(), if attest { "+attested" } else { "" }),
        "trades": trades,
        "participants": participants,
        "admitted": admitted,
        "refused": refused,
        "verify_per_order_ms": verify_total / admitted.max(1) as f64,
        "verify_orders_ms": verify_total,
        "verify_close_ms": close_verify,
        "verify_total_ms": verify_total + close_verify,
        "build_orders_ms": build_total,
        "build_close_ms": close_build,
    }))
}
