//! Two DeFMI deployments on one chain: one transaction, or two and an adaptor.
//!
//! Across two chains there is no choice --- nothing can span them, so the
//! adaptor and its deadline window are the only way. On one chain there is a
//! choice, and it is not the obvious one.
//!
//! A single transaction calling both venues gets atomicity from the chain for
//! nothing: both apply or the transaction reverts, and the exposure window is
//! zero. But that transaction *is* the link. Two transactions with an adaptor
//! keep the two legs cryptographically unrelated and pay a window of at least
//! one block. Both cannot be had, because being one transaction is what makes
//! it atomic and what makes it linkable.
//!
//! So three things are worth a number, and the third is the one that decides:
//!
//!   1. what each arm costs the chain in state --- exact, not timed
//!   2. what each arm costs in verification --- timed
//!   3. **what an observer reading the chain can still join**
//!
//! The prediction for the third, written before running it: the adaptor makes
//! the two *claims* unrelated, and does nothing about the two *prepares*, which
//! name account handles. An observer who joins "Alice pays on venue A" to
//! "Alice is paid on venue B" needs no cryptanalysis at all. If that is right,
//! the adaptor buys nothing on account rails and the whole choice above is a
//! false one until the rails are note rails.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_defmi::chain::{Call, ChainState, Delta, Observable};
use qomm_defmi::ledger::{Ledger, Transfer};
use qomm_defmi::pvp::Swap;
use qomm_measure::{hosts, Summary};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::handles::Identity;
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::time::Instant;

const BITS: usize = 32;
const AMOUNT: u64 = 1_000;
const BALANCE: u64 = 1_000_000;

fn shell(cmd: &str, args: &[&str]) -> String {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// One venue: a DeFMI deployment, its off-chain ledger and the chain state it
/// keeps. Two of these are two contract addresses on one chain.
struct Venue {
    name: String,
    ledger: Ledger,
    chain: ChainState,
    /// What each handle holds and the blinding that opens it. Tracked because
    /// a party that swaps twice pays from a moved balance the second time, and
    /// building the second transfer against the first one's opening is how a
    /// benchmark quietly stops measuring anything.
    holdings: BTreeMap<Vec<u8>, (u64, Scalar)>,
}

impl Venue {
    /// Every party is banked on every venue. A cross-currency swap needs that:
    /// whoever pays yen here is paid dollars there, so both need a handle on
    /// both. Modelling one venue per party would make the observer's job look
    /// harder than it is.
    fn new(name: &str, handles: &[Vec<u8>], rng: &mut OsRng) -> Venue {
        let key = Pedersen::new(name.as_bytes());
        let mut ledger = Ledger::new(key.clone(), BITS);
        let mut chain = ChainState::new();
        let mut holdings = BTreeMap::new();
        for handle in handles {
            let b = Scalar::random(rng);
            let commitment = key.commit_u64(BALANCE, &b);
            ledger.open(handle, commitment);
            chain.open(handle, commitment);
            holdings.insert(handle.clone(), (BALANCE, b));
        }
        Venue {
            name: name.to_string(),
            ledger,
            chain,
            holdings,
        }
    }

    /// Build a transfer and move this venue's own bookkeeping with it, so a
    /// second transfer from the same handle is built against the balance the
    /// first one left.
    fn transfer(&mut self, payer: &[u8], payee: &[u8], rng: &mut OsRng) -> Transfer {
        let (balance, blinding) = self.holdings[payer];
        let (transfer, secrets) = self
            .ledger
            .build_transfer(
                balance,
                &blinding,
                AMOUNT,
                b"same-chain",
                None,
                &Scalar::ZERO,
                false,
                rng,
            )
            .unwrap();
        self.holdings.insert(
            payer.to_vec(),
            (balance - AMOUNT, secrets.remainder_blinding),
        );
        let (had, opening) = self.holdings[payee];
        self.holdings.insert(
            payee.to_vec(),
            (had + AMOUNT, opening + secrets.payee_delta),
        );
        transfer
    }
}

/// One party pair doing one swap, with a handle at each venue.
struct Pair {
    a_jpy: Vec<u8>,
    a_usd: Vec<u8>,
    b_jpy: Vec<u8>,
    b_usd: Vec<u8>,
    index: usize,
}

/// How a firm is named at a venue --- the choice this whole measurement turns
/// out to be about.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Naming {
    /// One identifier everywhere. What a caller reaches for when the library
    /// offers nothing else, and what the first version of this benchmark did.
    Shared,
    /// `qomm_zkpi::handles`: one seed, an unrelated point per venue. What the
    /// design says, now that it is code.
    PerVenue,
}

fn pairs(count: usize, distinct: bool, naming: Naming) -> Vec<Pair> {
    (0..count)
        .map(|i| {
            // `distinct` decides whether these are k swaps between k different
            // pairs of parties or k swaps between the same two. The first is what a
            // venue with more than two users looks like.
            let who = if distinct { i } else { 0 };
            match naming {
                Naming::Shared => {
                    let (a, b) = (
                        format!("party-a-{who}").into_bytes(),
                        format!("party-b-{who}").into_bytes(),
                    );
                    Pair {
                        a_jpy: a.clone(),
                        a_usd: a,
                        b_jpy: b.clone(),
                        b_usd: b,
                        index: i,
                    }
                }
                Naming::PerVenue => {
                    let mut seed_a = [0u8; 32];
                    let mut seed_b = [0u8; 32];
                    seed_a[..8].copy_from_slice(&(who as u64).to_be_bytes());
                    seed_b[..8].copy_from_slice(&((who as u64 + 1) << 32).to_be_bytes());
                    let (fa, fb) = (Identity::from_seed(seed_a), Identity::from_seed(seed_b));
                    Pair {
                        a_jpy: fa.handle(b"jpy").account(),
                        a_usd: fa.handle(b"usd").account(),
                        b_jpy: fb.handle(b"jpy").account(),
                        b_usd: fb.handle(b"usd").account(),
                        index: i,
                    }
                }
            }
        })
        .collect()
}

fn banked(count: usize, distinct: bool, naming: Naming, venue: &str) -> Vec<Vec<u8>> {
    let mut all = Vec::new();
    for p in pairs(count, distinct, naming) {
        let two = if venue == "jpy" {
            [p.a_jpy, p.b_jpy]
        } else {
            [p.a_usd, p.b_usd]
        };
        for h in two {
            if !all.contains(&h) {
                all.push(h);
            }
        }
    }
    all
}

struct ArmResult {
    calls: usize,
    delta: Delta,
    verify_ms: f64,
    log: Vec<Observable>,
}

fn merge(into: &mut Delta, d: Delta) {
    into.merge(&d);
}

/// Both legs in one call to one transaction that touches both venues.
fn one_transaction(count: usize, distinct: bool, naming: Naming, rng: &mut OsRng) -> ArmResult {
    let mut yen = Venue::new("jpy", &banked(count, distinct, naming, "jpy"), rng);
    let mut usd = Venue::new("usd", &banked(count, distinct, naming, "usd"), rng);
    let mut delta = Delta::default();
    let mut log = Vec::new();
    let mut calls = 0;

    let start = Instant::now();
    for p in pairs(count, distinct, naming) {
        let ta = yen.transfer(&p.a_jpy, &p.b_jpy, rng);
        let tb = usd.transfer(&p.b_usd, &p.a_usd, rng);
        yen.ledger
            .settle_transfer(&p.a_jpy, &p.b_jpy, &ta, b"same-chain", false)
            .unwrap();
        usd.ledger
            .settle_transfer(&p.b_usd, &p.a_usd, &tb, b"same-chain", false)
            .unwrap();

        let mut nullifier = [0u8; 32];
        nullifier[..8].copy_from_slice(&(p.index as u64).to_be_bytes());
        merge(
            &mut delta,
            yen.chain
                .settle(
                    nullifier,
                    1_000,
                    1,
                    &[
                        (&p.a_jpy, ta.remainder_commitment),
                        (&p.b_jpy, ta.amount_commitment),
                    ],
                )
                .unwrap(),
        );
        merge(
            &mut delta,
            usd.chain
                .settle(
                    nullifier,
                    1_000,
                    1,
                    &[
                        (&p.b_usd, tb.remainder_commitment),
                        (&p.a_usd, tb.amount_commitment),
                    ],
                )
                .unwrap(),
        );
        calls += 1;

        // One transaction, both venues. That is the record an observer reads.
        log.push(Observable {
            block: 0,
            venue: format!("{}+{}", yen.name, usd.name),
            call: Call::Settle,
            handles: vec![
                p.a_jpy.clone(),
                p.b_jpy.clone(),
                p.a_usd.clone(),
                p.b_usd.clone(),
            ],
            leg: None,
        });
    }
    ArmResult {
        calls,
        delta,
        verify_ms: start.elapsed().as_secs_f64() * 1e3,
        log,
    }
}

/// Two transactions per leg, joined by an adaptor signature.
fn with_adaptor(count: usize, distinct: bool, naming: Naming, rng: &mut OsRng) -> ArmResult {
    let mut yen = Venue::new("jpy", &banked(count, distinct, naming, "jpy"), rng);
    let mut usd = Venue::new("usd", &banked(count, distinct, naming, "usd"), rng);
    let mut delta = Delta::default();
    let mut log = Vec::new();
    let mut calls = 0;

    let start = Instant::now();
    for p in pairs(count, distinct, naming) {
        let (bob, _) = Swap::proposer(rng);
        let mut alice = Swap::responder(bob.adaptor_point);
        let (leg_a, leg_b) = (
            format!("A{}", p.index).into_bytes(),
            format!("B{}", p.index).into_bytes(),
        );

        let ta = yen.transfer(&p.a_jpy, &p.b_jpy, rng);
        let tb = usd.transfer(&p.b_usd, &p.a_usd, rng);
        let la = alice
            .prepare(
                &mut yen.ledger,
                &leg_a,
                &p.a_jpy,
                &p.b_jpy,
                &Scalar::random(rng),
                &ta,
                b"same-chain",
                false,
                100,
                rng,
            )
            .unwrap();
        let lb = bob
            .prepare(
                &mut usd.ledger,
                &leg_b,
                &p.b_usd,
                &p.a_usd,
                &Scalar::random(rng),
                &tb,
                b"same-chain",
                false,
                160,
                rng,
            )
            .unwrap();
        merge(
            &mut delta,
            yen.chain
                .prepare(
                    &leg_a,
                    &p.a_jpy,
                    &p.b_jpy,
                    ta.remainder_commitment,
                    ta.amount_commitment,
                    100,
                )
                .unwrap(),
        );
        merge(
            &mut delta,
            usd.chain
                .prepare(
                    &leg_b,
                    &p.b_usd,
                    &p.a_usd,
                    tb.remainder_commitment,
                    tb.amount_commitment,
                    160,
                )
                .unwrap(),
        );

        // A prepare names both parties: it is a transfer, and a transfer says
        // who is paying whom. Nothing about the adaptor changes that.
        log.push(Observable {
            block: 0,
            venue: yen.name.clone(),
            call: Call::Prepare,
            handles: vec![p.a_jpy.clone(), p.b_jpy.clone()],
            leg: Some(leg_a.clone()),
        });
        log.push(Observable {
            block: 0,
            venue: usd.name.clone(),
            call: Call::Prepare,
            handles: vec![p.b_usd.clone(), p.a_usd.clone()],
            leg: Some(leg_b.clone()),
        });

        let published = bob.claim(&mut yen.ledger, &la, 90).unwrap();
        let secret = alice.learn(&la, &published);
        alice
            .claim_with(&mut usd.ledger, &lb, &secret, 120)
            .unwrap();
        merge(
            &mut delta,
            yen.chain
                .claim(&leg_a, RistrettoPoint::default(), 90)
                .unwrap(),
        );
        merge(
            &mut delta,
            usd.chain
                .claim(&leg_b, RistrettoPoint::default(), 120)
                .unwrap(),
        );
        calls += 4;

        // A claim names only the escrow and a signature. This is the part the
        // adaptor makes unrelated across the two venues.
        log.push(Observable {
            block: 1,
            venue: yen.name.clone(),
            call: Call::Claim,
            handles: vec![],
            leg: Some(leg_a),
        });
        log.push(Observable {
            block: 2,
            venue: usd.name.clone(),
            call: Call::Claim,
            handles: vec![],
            leg: Some(leg_b),
        });
    }
    ArmResult {
        calls,
        delta,
        verify_ms: start.elapsed().as_secs_f64() * 1e3,
        log,
    }
}

/// What a reader of the chain can still join, using only what the log exposes.
///
/// One stated strategy, run over the real records rather than reasoned about:
/// take every call on the first venue, find the calls on the second venue that
/// name the same handles, and guess uniformly among them. **When no handle
/// matches, the observer does not give up --- it guesses uniformly among every
/// call of the same kind on the other venue.** An earlier version scored that
/// case as zero, which reads as "never succeeds" and is wrong: an observer
/// always has a guess, and the floor is chance, not nothing.
fn observer_success(log: &[Observable]) -> f64 {
    let mut total = 0.0;
    let mut scored = 0usize;
    for (i, entry) in log.iter().enumerate() {
        if entry.call == Call::Settle {
            // One call carries both legs: there is nothing to join, it is
            // already joined.
            total += 1.0;
            scored += 1;
            continue;
        }
        if entry.venue != "jpy" || entry.call != Call::Prepare {
            continue;
        }
        let across: Vec<usize> = log
            .iter()
            .enumerate()
            .filter(|(j, o)| *j != i && o.venue == "usd" && o.call == entry.call)
            .map(|(j, _)| j)
            .collect();
        if across.is_empty() {
            continue;
        }
        let by_handle: Vec<usize> = across
            .iter()
            .copied()
            .filter(|j| {
                let o = &log[*j];
                !entry.handles.is_empty()
                    && o.handles.len() == entry.handles.len()
                    && entry.handles.iter().all(|h| o.handles.contains(h))
            })
            .collect();
        let candidates = if by_handle.is_empty() {
            across
        } else {
            by_handle
        };
        total += 1.0 / candidates.len() as f64;
        scored += 1;
    }
    if scored == 0 {
        0.0
    } else {
        total / scored as f64
    }
}

fn main() {
    let mut rng = OsRng;
    let counts = [1usize, 2, 4, 8, 16];
    let repeats: usize = std::env::var("QOMM_BENCH_REPEATS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);

    println!("two DeFMI deployments on one chain, {BITS}-bit rails\n");
    println!(
        "{:<16} {:<19} {:<9} {:>3} {:>6} {:>7} {:>22} {:>9}",
        "arm", "naming", "parties", "k", "calls", "slots", "verify ms", "observer"
    );
    let mut rows = Vec::new();

    type Arm = fn(usize, bool, Naming, &mut OsRng) -> ArmResult;
    for (naming, naming_name) in [
        (Naming::Shared, "one name everywhere"),
        (Naming::PerVenue, "a handle per venue"),
    ] {
        for distinct in [true, false] {
            for count in counts {
                for (name, run) in [
                    ("one transaction", one_transaction as Arm),
                    ("adaptor", with_adaptor),
                ] {
                    let mut times = Vec::new();
                    let mut last: Option<ArmResult> = None;
                    for _ in 0..repeats {
                        let r = run(count, distinct, naming, &mut rng);
                        times.push(r.verify_ms);
                        last = Some(r);
                    }
                    let r = last.unwrap();
                    let t = Summary::of(&times).unwrap();
                    let success = observer_success(&r.log);
                    println!(
                        "{:<16} {:<19} {:<9} {:>3} {:>6} {:>7} {:>22} {:>9.3}",
                        name,
                        naming_name,
                        if distinct { "distinct" } else { "one pair" },
                        count,
                        r.calls,
                        r.delta.slots_written,
                        format!("{t}"),
                        success
                    );
                    rows.push(format!(
                        "    {{\"arm\": \"{}\", \"naming\": \"{}\", \"swaps\": {}, \
                     \"parties\": \"{}\", \
                     \"calls\": {}, \"slots_written\": {}, \"bytes_written\": {}, \
                     \"verify_ms\": {{\"n\": {}, \"mean\": {:.4}, \"sd\": {}, \
                     \"median\": {:.4}}}, \"observer_success\": {:.4}, \
                     \"chance\": {:.4}}}",
                        name,
                        naming_name,
                        count,
                        if distinct { "distinct" } else { "one pair" },
                        r.calls,
                        r.delta.slots_written,
                        r.delta.bytes_written,
                        t.n,
                        t.mean,
                        t.sd.map_or("null".into(), |v| format!("{v:.4}")),
                        t.median,
                        success,
                        1.0 / count as f64
                    ));
                }
            }
            println!();
        }
    }

    println!("`observer` is the chance a reader of the chain names the partner leg,");
    println!("using only what the calls expose. 1.000 means the two legs are joined");
    println!("without any cryptanalysis at all.");

    let Ok(path) = std::env::var("QOMM_BENCH_JSON") else {
        return;
    };
    let json = format!(
        "{{\n  \"host\": \"{}\",\n  \"rustc\": \"{}\",\n  \"rail_bits\": {BITS},\n  \
         \"amount\": {AMOUNT},\n  \"repeats\": {repeats},\n  \
         \"observer\": \"joins two calls that name the same handles; guesses \
uniformly among the candidates\",\n  \"rows\": [\n{}\n  ]\n}}\n",
        std::env::var("QOMM_HOST_LABEL").unwrap_or_else(|_| hosts::this_host()),
        shell("rustc", &["--version"]),
        rows.join(",\n")
    );
    std::fs::write(&path, json).expect("could not write the benchmark JSON");
    println!("\nwrote {path}");
}
