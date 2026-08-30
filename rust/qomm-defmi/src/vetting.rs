//! Vetted handles, as a list whose crowd anyone can count.
//!
//! A taker or a maker makes its own handle. Nobody's permission is needed for
//! that: a handle is `A = a·G` and anyone can pick `a`. What needs permission is
//! being *vetted*, and this is where that is recorded.
//!
//! **The list holds sealed envelopes, not handles.** An envelope is
//! `C = a·G + r·h`, so `C − A = r·h` and the envelope is the handle plus a
//! blinding nobody else knows. Adding one to the list therefore reveals a
//! uniformly random point. An observer who knows the operator vetted a
//! particular firm on a particular day learns that the firm is somewhere in the
//! list, and learns nothing about which entry is theirs --- so the firm's later
//! settlements cannot be traced to it. Putting the handle itself in the list
//! would have leaked exactly that trace, because the handle is what appears on
//! chain when the account moves.
//!
//! **Membership is proved one-out-of-many over a group.** Subtract the handle
//! from every envelope in its group; exactly one difference is then a
//! commitment to zero, and `qomm_zk::oneofmany` proves that without saying
//! which. Two properties follow, and the second is the reason the design looks
//! the way it does.
//!
//! **The group is fixed for the life of the handle.** Drawing a fresh ring per
//! proof would look more private and be less: rings that overlap differently
//! each time let an observer intersect them and narrow the real member down.
//! A handle that always proves inside the same group gives an observer the same
//! candidates every time, and intersecting a set with itself yields nothing.
//!
//! **The group is bounded by verification, which costs less than expected.**
//! It was chosen at sixteen on the belief that checking a one-out-of-many proof
//! is linear in the group. Measured, it is not: doubling the crowd costs about
//! 1.4x, because the check is one multi-exponentiation and the batched
//! algorithm underneath it is sublinear in its terms. 1.31 ms at sixteen,
//! 3.80 ms at a hundred and twenty-eight --- against the 51.9 ms a note
//! settlement already costs, so a crowd of a hundred and twenty-eight is
//! affordable where a crowd of sixteen was thought to be the ceiling. The wire
//! barely notices either: every doubling of the crowd adds exactly 224 bytes.
//! `artifacts/vetting.json`.
//!
//! What stays out of reach is hiding in thousands. That needs a Merkle tree
//! checked inside a circuit, which is a different proof system from the one
//! this stack is built on.
//!
//! **Whose privacy this is.** The seal hides the entry from *observers*, not
//! from the operator: `vouch` takes the handle's secret, picks the blinding and
//! picks the slot, so the operator knows the whole relation. Enrolment in which
//! it does not --- the party proving knowledge of its secret and receiving a
//! jointly chosen blinding --- is not built here. What the seal establishes is
//! that dating an onboarding tells a third party nothing about which entry it
//! is, which is the linkage that would otherwise expose a firm's settlements.
//!
//! **What is deliberately public: how big the crowd is.** `Roll::vetted` counts
//! the real envelopes and `Roll::crowd` gives the group size, so anyone can
//! check the claim "one of this many" rather than take it. It counts calls to
//! `vouch`, not distinct legal entities --- nothing here deduplicates one, and
//! the per-entity cap lives at the operator. That is the trade this design makes
//! on purpose. Hiding the fact that a vetting happened would mean
//! padding the roll with entries nobody can distinguish from real ones --- and
//! then nobody could count the real ones either, including a regulator asking
//! how large the anonymity set actually is. The two are the same information.
//! One or the other, not both.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_zk::oneofmany::{self, GkProof};
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::TranscriptExt;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

/// How big a crowd a handle hides in, unless a deployment says otherwise.
///
/// It was sixteen, chosen on the belief that verifying a one-out-of-many proof
/// is linear in the group. The measurement says it is not --- doubling the
/// crowd costs about 1.4x --- so the number that fits the same budget is eight
/// times larger. 3.80 ms to verify and 1,676 bytes on the wire, against the
/// 51.9 ms a note settlement already costs. `artifacts/vetting.json`.
pub const CROWD: usize = 128;

/// The handle a secret controls. Bare `a·G`, which is what `control` pins.
pub fn handle_of(secret: &Scalar) -> RistrettoPoint {
    G * secret
}

/// A place in a group that no one can prove membership from.
///
/// Derived by hashing rather than drawn at random, so that not even the
/// operator knows an opening for it. That is what makes `filled` an honest
/// count: a decoy cannot be used, by anybody, so the firms hiding in a group
/// really are the ones the roll says are there.
fn decoy(cohort: &[u8], group: usize, index: usize) -> RistrettoPoint {
    let mut bytes = Vec::with_capacity(cohort.len() + 16);
    bytes.extend_from_slice(b"qomm:defmi:vetting:decoy:v1");
    bytes.extend_from_slice(&(cohort.len() as u64).to_be_bytes());
    bytes.extend_from_slice(cohort);
    bytes.extend_from_slice(&(group as u64).to_be_bytes());
    bytes.extend_from_slice(&(index as u64).to_be_bytes());
    RistrettoPoint::hash_from_bytes::<Sha512>(&bytes)
}

/// One group of the roll: the crowd a handle inside it hides in.
///
/// Readable and not constructible from outside this crate. Every field being
/// public made a `Roll` something a caller could build: push a group holding an
/// envelope of your own, cut a `Seal` by hand, and `check_membership` succeeds
/// against it without `Operator::vouch` ever running. The check is a statement
/// about the roll it is handed, so what a verifier must not be able to do is
/// build the roll.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Group {
    /// Which attribute cohort this group belongs to --- jurisdiction, entity
    /// type, collateral tier. Proving membership here proves the attribute,
    /// because the operator only puts a firm in a cohort it qualifies for.
    pub cohort: Vec<u8>,
    /// Bumped whenever an envelope replaces a decoy, so a proof names the
    /// version of the group it was made against and a stale one is refused
    /// rather than silently checked against different contents.
    pub epoch: u64,
    pub envelopes: Vec<RistrettoPoint>,
    /// How many of `envelopes` are real. The rest are decoys, and this number
    /// is the honest size of the crowd.
    pub filled: usize,
}

/// What the chain holds.
#[derive(Clone, Debug)]
pub struct Roll {
    groups: Vec<Group>,
    crowd: usize,
}

impl Roll {
    /// `crowd` is the group size, and must be a power of two of at least two
    /// because that is what the one-out-of-many proof accepts. [`CROWD`] is the
    /// size a deployment should use unless it has a reason; halving it halves
    /// the crowd and saves rather little, because the cost does not scale the
    /// way the crowd does.
    pub fn new(crowd: usize) -> Result<Self, &'static str> {
        if !crowd.is_power_of_two() || crowd < 2 {
            return Err("a group is a power of two, at least two");
        }
        Ok(Roll {
            groups: Vec::new(),
            crowd,
        })
    }

    /// The size of the crowd one handle hides in.
    pub fn crowd(&self) -> usize {
        self.crowd
    }

    /// How many firms are actually vetted. Public on purpose --- see the module
    /// note on why this and hiding the vetting event are the same information.
    pub fn vetted(&self) -> usize {
        self.groups.iter().map(|g| g.filled).sum()
    }

    pub fn group(&self, index: usize) -> Option<&Group> {
        self.groups.get(index)
    }

    pub fn groups(&self) -> &[Group] {
        &self.groups
    }

    /// What the chain publishes, and what a verifier compares against it.
    ///
    /// `check_membership` proves a handle is in the roll it is given. Which
    /// roll that is, is the caller's to establish, and this is how: the digest
    /// covers the crowd size and every group's cohort, epoch, fill and
    /// envelopes, so two rolls that agree here are the same roll.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha512::new();
        hasher.update(b"qomm:defmi:vetting:roll:v1");
        hasher.update((self.crowd as u64).to_be_bytes());
        hasher.update((self.groups.len() as u64).to_be_bytes());
        for group in &self.groups {
            hasher.update((group.cohort.len() as u64).to_be_bytes());
            hasher.update(&group.cohort);
            hasher.update(group.epoch.to_be_bytes());
            hasher.update((group.filled as u64).to_be_bytes());
            for envelope in &group.envelopes {
                hasher.update(envelope.compress().as_bytes());
            }
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize()[..32]);
        out
    }
}

/// What the vetted party keeps. Losing it costs the ability to prove
/// membership, and nothing else --- it is not a spending key.
#[derive(Clone, Debug)]
pub struct Seal {
    pub group: usize,
    pub index: usize,
    pub blinding: Scalar,
    /// The version this seal was cut against, so a holder can tell that the
    /// group moved under it.
    pub epoch: u64,
}

/// The operator's side: it has done the KYB and now records it.
pub struct Operator {
    pub key: Pedersen,
}

impl Operator {
    pub fn new(key: Pedersen) -> Self {
        Operator { key }
    }

    /// Seal a handle into a group of its cohort, opening a new group if the
    /// cohort's groups are full.
    ///
    /// Takes the handle's *secret*, because the envelope is a commitment to it
    /// and the blinding has to be handed back. In a deployment the party sends
    /// the secret under a channel the operator already has for the KYB
    /// paperwork, or --- better, and not built here --- proves knowledge of it
    /// and receives a blinding chosen jointly, so the operator never holds a
    /// secret it does not need.
    pub fn vouch<R: RngCore + CryptoRng>(
        &self,
        roll: &mut Roll,
        cohort: &[u8],
        secret: &Scalar,
        rng: &mut R,
    ) -> Seal {
        let crowd = roll.crowd;
        let slot = roll
            .groups
            .iter()
            .position(|g| g.cohort == cohort && g.filled < crowd);
        let group = match slot {
            Some(index) => index,
            None => {
                let index = roll.groups.len();
                let envelopes = (0..crowd).map(|i| decoy(cohort, index, i)).collect();
                roll.groups.push(Group {
                    cohort: cohort.to_vec(),
                    epoch: 0,
                    envelopes,
                    filled: 0,
                });
                index
            }
        };
        let blinding = Pedersen::random_blinding(rng);
        let envelope = self.key.commit(secret, &blinding);
        // Filling in order would say, from the position alone, how many firms
        // were vetted before this one. The position is drawn from the free
        // slots instead, so it says nothing beyond the group.
        let free: Vec<usize> = {
            let g = &roll.groups[group];
            (0..crowd)
                .filter(|i| g.envelopes[*i] == decoy(cohort, group, *i))
                .collect()
        };
        let pick = free[(u64::from_le_bytes({
            let mut b = [0u8; 8];
            rng.fill_bytes(&mut b);
            b
        }) % free.len() as u64) as usize];
        let g = &mut roll.groups[group];
        g.envelopes[pick] = envelope;
        g.filled += 1;
        g.epoch += 1;
        Seal {
            group,
            index: pick,
            blinding,
            epoch: g.epoch,
        }
    }
}

/// A Schnorr proof that the handle is a bare power of the base point.
///
/// Without it one envelope yields unboundedly many usable handles: the
/// one-out-of-many proof only says `C_l − A` is a multiple of `h`, and
/// `A + δ·h` satisfies that just as well for any `δ` the holder picks. Pinning
/// `A = a·G` makes the handle the envelope determines and no other, which is
/// what "one vetting, one handle" has to mean if the per-firm caps are to hold.
#[derive(Clone, Debug)]
pub struct ControlProof {
    pub t: RistrettoPoint,
    pub z: Scalar,
}

/// What a party shows. The group index is public --- it is the crowd it is
/// claiming to hide in, and a verifier has to know which sixteen to check
/// against.
#[derive(Clone, Debug)]
pub struct Membership {
    pub group: usize,
    pub epoch: u64,
    pub ring: GkProof,
    pub control: ControlProof,
}

impl Membership {
    pub fn size_bytes(&self) -> usize {
        4 + 8 + self.ring.size_bytes() + 32 + 32
    }
}

fn transcript(group: &Group, index: usize, handle: &RistrettoPoint, context: &[u8]) -> Transcript {
    let mut t = Transcript::new(b"qomm:defmi:vetting:v1");
    t.append_message(b"ctx", context);
    t.append_message(b"cohort", &group.cohort);
    t.append_u64(b"group", index as u64);
    t.append_u64(b"epoch", group.epoch);
    // Every envelope goes in, so a proof made against one version of the group
    // does not verify against another. Naming the epoch alone would leave a
    // roll that rewrote an entry without bumping it looking sound.
    for envelope in &group.envelopes {
        t.append_point(b"C", envelope);
    }
    t.append_point(b"A", handle);
    t
}

/// Prove the handle was vetted, without saying which entry is it.
pub fn prove_membership<R: RngCore + CryptoRng>(
    key: &Pedersen,
    roll: &Roll,
    seal: &Seal,
    secret: &Scalar,
    context: &[u8],
    rng: &mut R,
) -> Result<Membership, &'static str> {
    let group = roll.groups.get(seal.group).ok_or("no such group")?;
    if group.epoch != seal.epoch {
        return Err("the group moved under this seal; get a fresh one");
    }
    let handle = handle_of(secret);
    let shifted: Vec<RistrettoPoint> = group.envelopes.iter().map(|c| c - handle).collect();
    let mut ring_transcript = transcript(group, seal.group, &handle, context);
    let ring = oneofmany::prove(
        key,
        &mut ring_transcript,
        &shifted,
        seal.index,
        &seal.blinding,
        rng,
    )?;

    let witness = Scalar::random(rng);
    let t = G * witness;
    let mut control_transcript = transcript(group, seal.group, &handle, context);
    control_transcript.append_point(b"T", &t);
    let c = control_transcript.challenge_scalar(b"c");
    Ok(Membership {
        group: seal.group,
        epoch: group.epoch,
        ring,
        control: ControlProof {
            t,
            z: witness + c * secret,
        },
    })
}

/// The verifier's side. Anyone holding the roll can run it.
///
/// It proves the handle is in **the roll it is given**. Establishing that this
/// is the roll the chain published is the caller's, and `Roll::digest` is what
/// to compare against: a proof that arrives with its own roll proves nothing.
pub fn check_membership(
    key: &Pedersen,
    roll: &Roll,
    handle: &RistrettoPoint,
    membership: &Membership,
    context: &[u8],
) -> Result<(), &'static str> {
    let group = roll.groups.get(membership.group).ok_or("no such group")?;
    if group.epoch != membership.epoch {
        return Err("this proof was made against a different version of the group");
    }
    let mut control_transcript = transcript(group, membership.group, handle, context);
    control_transcript.append_point(b"T", &membership.control.t);
    let c = control_transcript.challenge_scalar(b"c");
    if G * membership.control.z != membership.control.t + handle * c {
        return Err("the handle is not a bare power of the base point");
    }
    let shifted: Vec<RistrettoPoint> = group.envelopes.iter().map(|point| point - handle).collect();
    let mut ring_transcript = transcript(group, membership.group, handle, context);
    if !oneofmany::verify(key, &mut ring_transcript, &shifted, &membership.ring) {
        return Err("this handle is not in that group");
    }
    Ok(())
}

/// Which cohort a group speaks for, so an attribute gate reads it without
/// having to trust the presenter about it.
pub fn cohort_of(roll: &Roll, membership: &Membership) -> Option<Vec<u8>> {
    roll.groups.get(membership.group).map(|g| g.cohort.clone())
}
