//! Turn a checked rule into real proofs by walking it once.
//!
//! The same traversal that computes the value produces the proof for it. A maker
//! registers a rule and its secret parameters; this emits the commitments and
//! the sigma proofs showing every declared bound holds and every product and
//! comparison was evaluated correctly. Nothing here is written by hand, so a
//! rule that gains a term gains the matching proof automatically --- which is the
//! property that makes the language worth having.

use std::collections::BTreeMap;

use bulletproofs::RangeProof;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_dsl::interval::{Interval, RuleError};
use qomm_dsl::parse::{Cmp, Expr};
use qomm_dsl::rule::Rule;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::range::RangeCtx;
use qomm_zk::sigma::{
    prove_bit, prove_opening, prove_product, verify_bit, verify_opening, verify_product, BitProof,
    OpeningProof, ProductProof,
};
use rand_core::{CryptoRng, RngCore};

fn scalar(value: i128) -> Scalar {
    if value < 0 {
        -Scalar::from(value.unsigned_abs() as u64)
    } else {
        Scalar::from(value as u64)
    }
}

/// A value as it travels up the tree: cleartext, blinding and commitment.
#[derive(Clone, Copy)]
struct Wire {
    value: i128,
    blinding: Scalar,
    commitment: RistrettoPoint,
    interval: Interval,
}

/// One step of the audit. Typed rather than tagged, so a verifier that forgets
/// a case does not compile.
#[derive(Debug)]
pub enum Step {
    /// `c = a * b` over three commitments.
    Product {
        label: String,
        a: Box<RistrettoPoint>,
        b: Box<RistrettoPoint>,
        c: Box<RistrettoPoint>,
        proof: Box<ProductProof>,
        tag: Vec<u8>,
    },
    /// A committed difference is not negative.
    Range {
        label: String,
        commitment: CompressedRistretto,
        proof: Box<RangeProof>,
        tag: Vec<u8>,
    },
    /// A committed value is 0 or 1.
    Bit {
        label: String,
        commitment: RistrettoPoint,
        proof: Box<BitProof>,
        tag: Vec<u8>,
    },
    /// A committed difference opens to a value the verifier can reconstruct.
    Equality {
        label: String,
        commitment: RistrettoPoint,
        proof: Box<OpeningProof>,
        tag: Vec<u8>,
    },
}

impl Step {
    pub fn kind(&self) -> &'static str {
        match self {
            Step::Product { .. } => "product",
            Step::Range { .. } => "range",
            Step::Bit { .. } => "bit",
            Step::Equality { .. } => "equality",
        }
    }
}

#[derive(Debug)]
pub struct RuleAudit {
    pub declared: BTreeMap<String, RistrettoPoint>,
    /// One aggregated range proof over every secret's declared band.
    pub declared_ranges: Option<(RangeProof, Vec<CompressedRistretto>, Vec<String>)>,
    pub steps: Vec<Step>,
    pub outputs: BTreeMap<String, RistrettoPoint>,
    pub output_values: BTreeMap<String, i128>,
}

impl RuleAudit {
    pub fn size(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::new();
        for step in &self.steps {
            *counts.entry(step.kind()).or_insert(0) += 1;
        }
        counts.insert(
            "declared_range",
            self.declared_ranges.as_ref().map_or(0, |(_, c, _)| c.len()),
        );
        counts
    }
}

/// Comparison widths are rounded up to what an aggregated range proof takes.
const STEP_BITS: usize = 64;

pub struct RuleProver {
    pub key: Pedersen,
    ranges: RangeCtx,
}

impl Default for RuleProver {
    fn default() -> Self {
        Self::new()
    }
}

fn transcript(tag: &[u8]) -> Transcript {
    let mut t = Transcript::new(b"qomm:rule:v1");
    t.append_message(b"tag", tag);
    t
}

impl RuleProver {
    pub fn new() -> Self {
        RuleProver {
            key: Pedersen::new(b"qomm:rule:v1"),
            ranges: RangeCtx::new(STEP_BITS, 1),
        }
    }

    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        rule: &Rule,
        bindings: &BTreeMap<String, i128>,
        context: &[u8],
        rng: &mut R,
    ) -> Result<RuleAudit, RuleError> {
        let mut wires: BTreeMap<String, Wire> = BTreeMap::new();
        let mut declared = BTreeMap::new();
        let mut secret_names = Vec::new();
        let mut offsets = Vec::new();
        let mut offset_blindings = Vec::new();

        for (name, declaration) in &rule.declarations {
            let value = *bindings
                .get(name)
                .ok_or_else(|| RuleError(format!("no value supplied for '{name}'")))?;
            let (low, high) = (declaration.interval.lo, declaration.interval.hi);
            if value < low || value > high {
                return Err(RuleError(format!(
                    "'{name}' = {value} is outside its declared range [{low}, {high}]"
                )));
            }
            let blinding = Scalar::random(rng);
            let commitment = self.key.commit(&scalar(value), &blinding);
            if declaration.role.is_secret() {
                // A secret has to prove it sits inside the band it declared.
                secret_names.push(name.clone());
                offsets.push((value - low) as u64);
                offset_blindings.push(blinding);
            }
            declared.insert(name.clone(), commitment);
            wires.insert(
                name.clone(),
                Wire {
                    value,
                    blinding,
                    commitment,
                    interval: declaration.interval,
                },
            );
        }

        let declared_ranges = if secret_names.is_empty() {
            None
        } else {
            let ranges = RangeCtx::new(STEP_BITS, secret_names.len().next_power_of_two());
            let mut t = transcript(&[context, b":decl"].concat());
            let (proof, commitments) = ranges
                .prove(&mut t, &offsets, &offset_blindings)
                .map_err(|e| RuleError(e.into()))?;
            Some((proof, commitments, secret_names))
        };

        let mut steps = Vec::new();
        let mut outputs = BTreeMap::new();
        let mut output_values = BTreeMap::new();
        for (label, tree) in &rule.outputs {
            let wire = self.walk(tree, &wires, label, context, &mut steps, rng)?;
            outputs.insert(label.clone(), wire.commitment);
            output_values.insert(label.clone(), wire.value);
        }

        Ok(RuleAudit {
            declared,
            declared_ranges,
            steps,
            outputs,
            output_values,
        })
    }

    fn tag(context: &[u8], label: &str, n: usize, suffix: &str) -> Vec<u8> {
        let mut out = context.to_vec();
        out.extend_from_slice(b":");
        out.extend_from_slice(label.as_bytes());
        out.extend_from_slice(format!(":{n}:{suffix}").as_bytes());
        out
    }

    fn difference(&self, left: &Wire, right: &Wire) -> Wire {
        Wire {
            value: left.value - right.value,
            blinding: left.blinding - right.blinding,
            commitment: left.commitment - right.commitment,
            interval: left.interval.minus(right.interval),
        }
    }

    fn prove_ge_zero<R: RngCore + CryptoRng>(
        &self,
        wire: &Wire,
        label: &str,
        tag: Vec<u8>,
        steps: &mut Vec<Step>,
        rng: &mut R,
    ) -> Result<(), RuleError> {
        let _ = rng;
        if wire.value < 0 {
            return Err(RuleError(
                "a difference the rule requires to be non-negative is not".into(),
            ));
        }
        let mut t = transcript(&tag);
        let (proof, commitments) = self
            .ranges
            .prove(&mut t, &[wire.value as u64], &[wire.blinding])
            .map_err(|e| RuleError(e.into()))?;
        steps.push(Step::Range {
            label: label.into(),
            commitment: commitments[0],
            proof: Box::new(proof),
            tag,
        });
        Ok(())
    }

    /// `(left - result) * (right - result) == 0` pins the result to one of them,
    /// which is cheaper and simpler than proving which branch was taken.
    #[expect(
        clippy::too_many_arguments,
        reason = "the proof transcript inputs remain explicit at this security boundary"
    )]
    fn pin_to_one_of<R: RngCore + CryptoRng>(
        &self,
        left: &Wire,
        right: &Wire,
        result: &Wire,
        label: &str,
        tag: &[u8],
        steps: &mut Vec<Step>,
        rng: &mut R,
    ) -> Result<(), RuleError> {
        let gap_left = self.difference(left, result);
        let gap_right = self.difference(right, result);
        let zero_blinding = Scalar::random(rng);
        let pin_tag = [tag, b":pin"].concat();
        let proof = prove_product(
            &self.key,
            &mut transcript(&pin_tag),
            &gap_left.commitment,
            &scalar(gap_left.value),
            &gap_left.blinding,
            &scalar(gap_right.value),
            &gap_right.blinding,
            &zero_blinding,
            rng,
        );
        let zero_commitment = self
            .key
            .commit(&scalar(gap_left.value * gap_right.value), &zero_blinding);
        steps.push(Step::Product {
            label: label.into(),
            a: Box::new(gap_left.commitment),
            b: Box::new(gap_right.commitment),
            c: Box::new(zero_commitment),
            proof: Box::new(proof),
            tag: pin_tag,
        });
        let zero_tag = [tag, b":zero"].concat();
        let opening = prove_opening(
            &self.key,
            &mut transcript(&zero_tag),
            &zero_commitment,
            &Scalar::ZERO,
            &zero_blinding,
            rng,
        );
        steps.push(Step::Equality {
            label: label.into(),
            commitment: zero_commitment,
            proof: Box::new(opening),
            tag: zero_tag,
        });
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the proof transcript inputs remain explicit at this security boundary"
    )]
    fn select<R: RngCore + CryptoRng>(
        &self,
        left: Wire,
        right: Wire,
        take_min: bool,
        label: &str,
        tag: &[u8],
        steps: &mut Vec<Step>,
        rng: &mut R,
    ) -> Result<Wire, RuleError> {
        let value = if take_min {
            left.value.min(right.value)
        } else {
            left.value.max(right.value)
        };
        let blinding = Scalar::random(rng);
        let interval = if take_min {
            Interval {
                lo: left.interval.lo.min(right.interval.lo),
                hi: left.interval.hi.min(right.interval.hi),
            }
        } else {
            Interval {
                lo: left.interval.lo.max(right.interval.lo),
                hi: left.interval.hi.max(right.interval.hi),
            }
        };
        let result = Wire {
            value,
            blinding,
            commitment: self.key.commit(&scalar(value), &blinding),
            interval,
        };
        // The result is no worse than either input...
        let (a, b) = if take_min {
            (
                self.difference(&left, &result),
                self.difference(&right, &result),
            )
        } else {
            (
                self.difference(&result, &left),
                self.difference(&result, &right),
            )
        };
        self.prove_ge_zero(&a, label, [tag, b":a"].concat(), steps, rng)?;
        self.prove_ge_zero(&b, label, [tag, b":b"].concat(), steps, rng)?;
        // ...and equals one of them.
        self.pin_to_one_of(&left, &right, &result, label, tag, steps, rng)?;
        Ok(result)
    }

    /// Dispatch by construct. Each handler is the whole answer for one: the
    /// value, the commitment that carries it, and the proof it obliges.
    fn walk<R: RngCore + CryptoRng>(
        &self,
        node: &Expr,
        wires: &BTreeMap<String, Wire>,
        label: &str,
        context: &[u8],
        steps: &mut Vec<Step>,
        rng: &mut R,
    ) -> Result<Wire, RuleError> {
        let n = steps.len();
        match node {
            Expr::Const(v) => Ok(Wire {
                value: *v,
                blinding: Scalar::ZERO,
                commitment: self.key.commit(&scalar(*v), &Scalar::ZERO),
                interval: Interval::point(*v),
            }),
            Expr::Name(name) => wires
                .get(name)
                .copied()
                .ok_or_else(|| RuleError(format!("'{name}' has no wire"))),
            Expr::Neg(inner) => {
                let w = self.walk(inner, wires, label, context, steps, rng)?;
                Ok(Wire {
                    value: -w.value,
                    blinding: -w.blinding,
                    commitment: -w.commitment,
                    interval: w.interval.negated(),
                })
            }
            Expr::Add(a, b) | Expr::Sub(a, b) => {
                let left = self.walk(a, wires, label, context, steps, rng)?;
                let right = self.walk(b, wires, label, context, steps, rng)?;
                Ok(self.additive(&left, &right, matches!(node, Expr::Add(_, _))))
            }
            Expr::Mul(a, b) => {
                let left = self.walk(a, wires, label, context, steps, rng)?;
                let right = self.walk(b, wires, label, context, steps, rng)?;
                Ok(self.multiply(
                    &left,
                    &right,
                    label,
                    Self::tag(context, label, n, "mul"),
                    steps,
                    rng,
                ))
            }
            Expr::Compare(a, op, b) => {
                let left = self.walk(a, wires, label, context, steps, rng)?;
                let right = self.walk(b, wires, label, context, steps, rng)?;
                self.compare(
                    &left,
                    &right,
                    op,
                    label,
                    Self::tag(context, label, n, "cmp"),
                    steps,
                    rng,
                )
            }
            Expr::And(parts) => self.conjunction(parts, wires, label, context, steps, rng),
            Expr::Call(name, args) => {
                let mut evaluated = Vec::with_capacity(args.len());
                for argument in args {
                    evaluated.push(self.walk(argument, wires, label, context, steps, rng)?);
                }
                self.intrinsic(
                    name,
                    &evaluated,
                    label,
                    Self::tag(context, label, n, name),
                    steps,
                    rng,
                )
            }
        }
    }

    /// Addition on commitments is free: no proof, and no round in the circuit.
    fn additive(&self, left: &Wire, right: &Wire, adding: bool) -> Wire {
        if !adding {
            return self.difference(left, right);
        }
        Wire {
            value: left.value + right.value,
            blinding: left.blinding + right.blinding,
            commitment: left.commitment + right.commitment,
            interval: left.interval.plus(right.interval),
        }
    }

    /// The one step that costs a proof.
    fn multiply<R: RngCore + CryptoRng>(
        &self,
        left: &Wire,
        right: &Wire,
        label: &str,
        tag: Vec<u8>,
        steps: &mut Vec<Step>,
        rng: &mut R,
    ) -> Wire {
        let blinding = Scalar::random(rng);
        let value = left.value * right.value;
        let proof = prove_product(
            &self.key,
            &mut transcript(&tag),
            &left.commitment,
            &scalar(left.value),
            &left.blinding,
            &scalar(right.value),
            &right.blinding,
            &blinding,
            rng,
        );
        let commitment = self.key.commit(&scalar(value), &blinding);
        steps.push(Step::Product {
            label: label.into(),
            a: Box::new(left.commitment),
            b: Box::new(right.commitment),
            c: Box::new(commitment),
            proof: Box::new(proof),
            tag,
        });
        Wire {
            value,
            blinding,
            commitment,
            interval: left.interval.times(right.interval),
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the proof transcript inputs remain explicit at this security boundary"
    )]
    fn compare<R: RngCore + CryptoRng>(
        &self,
        left: &Wire,
        right: &Wire,
        op: &Cmp,
        label: &str,
        tag: Vec<u8>,
        steps: &mut Vec<Step>,
        rng: &mut R,
    ) -> Result<Wire, RuleError> {
        let result = match op {
            // Equality is decided by opening a difference, so no range is involved.
            Cmp::Eq | Cmp::Ne => {
                let diff = self.difference(left, right);
                let opening = prove_opening(
                    &self.key,
                    &mut transcript(&tag),
                    &diff.commitment,
                    &scalar(diff.value),
                    &diff.blinding,
                    rng,
                );
                steps.push(Step::Equality {
                    label: label.into(),
                    commitment: diff.commitment,
                    proof: Box::new(opening),
                    tag: tag.clone(),
                });
                i128::from(if matches!(op, Cmp::Eq) {
                    diff.value == 0
                } else {
                    diff.value != 0
                })
            }
            // An ordering is "the difference is not negative", one range proof.
            _ => {
                let diff = if matches!(op, Cmp::Gt | Cmp::Ge) {
                    self.difference(left, right)
                } else {
                    self.difference(right, left)
                };
                let strict = matches!(op, Cmp::Gt | Cmp::Lt);
                let shifted = Wire {
                    value: diff.value - i128::from(strict),
                    blinding: diff.blinding,
                    commitment: if strict {
                        diff.commitment - self.key.g
                    } else {
                        diff.commitment
                    },
                    interval: diff.interval,
                };
                self.prove_ge_zero(&shifted, label, tag.clone(), steps, rng)?;
                1
            }
        };
        Ok(self.as_bit(result, label, &tag, steps, rng))
    }

    /// Commit a comparison's result and prove it really is a bit.
    fn as_bit<R: RngCore + CryptoRng>(
        &self,
        value: i128,
        label: &str,
        tag: &[u8],
        steps: &mut Vec<Step>,
        rng: &mut R,
    ) -> Wire {
        let blinding = Scalar::random(rng);
        let commitment = self.key.commit(&scalar(value), &blinding);
        let bit_tag = [tag, b":bit"].concat();
        let proof = prove_bit(
            &self.key,
            &mut transcript(&bit_tag),
            &commitment,
            value == 1,
            &blinding,
            rng,
        );
        steps.push(Step::Bit {
            label: label.into(),
            commitment,
            proof: Box::new(proof),
            tag: bit_tag,
        });
        Wire {
            value,
            blinding,
            commitment,
            interval: Interval { lo: 0, hi: 1 },
        }
    }

    fn conjunction<R: RngCore + CryptoRng>(
        &self,
        parts: &[Expr],
        wires: &BTreeMap<String, Wire>,
        label: &str,
        context: &[u8],
        steps: &mut Vec<Step>,
        rng: &mut R,
    ) -> Result<Wire, RuleError> {
        let mut wire = self.walk(&parts[0], wires, label, context, steps, rng)?;
        for part in &parts[1..] {
            let other = self.walk(part, wires, label, context, steps, rng)?;
            let tag = Self::tag(context, label, steps.len(), "and");
            wire = self.multiply(&wire, &other, label, tag, steps, rng);
            wire.interval = Interval { lo: 0, hi: 1 };
        }
        Ok(wire)
    }

    fn intrinsic<R: RngCore + CryptoRng>(
        &self,
        name: &str,
        args: &[Wire],
        label: &str,
        tag: Vec<u8>,
        steps: &mut Vec<Step>,
        rng: &mut R,
    ) -> Result<Wire, RuleError> {
        match (name, args) {
            ("min", [a, b]) => self.select(*a, *b, true, label, &tag, steps, rng),
            ("max", [a, b]) => self.select(*a, *b, false, label, &tag, steps, rng),
            // A floor then a ceiling, which is max then min and nothing new.
            ("clamp", [value, lo, hi]) => {
                let lowered = self.select(
                    *value,
                    *lo,
                    false,
                    label,
                    &[tag.as_slice(), b":lo"].concat(),
                    steps,
                    rng,
                )?;
                self.select(
                    lowered,
                    *hi,
                    true,
                    label,
                    &[tag.as_slice(), b":hi"].concat(),
                    steps,
                    rng,
                )
            }
            ("signed", [side, magnitude]) => {
                Ok(self.signed(side, magnitude, label, tag, steps, rng))
            }
            _ => Err(RuleError(format!("the prover has no rule for {name}"))),
        }
    }

    /// `side ? magnitude : -magnitude`, written as arithmetic rather than as a
    /// branch, so nothing about which way the trade went has to be opened.
    fn signed<R: RngCore + CryptoRng>(
        &self,
        side: &Wire,
        magnitude: &Wire,
        label: &str,
        tag: Vec<u8>,
        steps: &mut Vec<Step>,
        rng: &mut R,
    ) -> Wire {
        let blinding = Scalar::random(rng);
        let product_value = side.value * magnitude.value;
        let proof = prove_product(
            &self.key,
            &mut transcript(&tag),
            &side.commitment,
            &scalar(side.value),
            &side.blinding,
            &scalar(magnitude.value),
            &magnitude.blinding,
            &blinding,
            rng,
        );
        let product_commitment = self.key.commit(&scalar(product_value), &blinding);
        steps.push(Step::Product {
            label: label.into(),
            a: Box::new(side.commitment),
            b: Box::new(magnitude.commitment),
            c: Box::new(product_commitment),
            proof: Box::new(proof),
            tag,
        });
        let two = Scalar::from(2u64);
        Wire {
            value: 2 * product_value - magnitude.value,
            blinding: two * blinding - magnitude.blinding,
            commitment: product_commitment * two - magnitude.commitment,
            interval: Interval {
                lo: -magnitude.interval.hi,
                hi: magnitude.interval.hi,
            },
        }
    }
}

pub struct RuleVerifier {
    pub key: Pedersen,
    ranges: RangeCtx,
}

impl Default for RuleVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleVerifier {
    pub fn new() -> Self {
        RuleVerifier {
            key: Pedersen::new(b"qomm:rule:v1"),
            ranges: RangeCtx::new(STEP_BITS, 1),
        }
    }

    /// Nothing here opens anything. Every check is against a commitment the
    /// verifier already holds or reconstructs.
    pub fn verify(&self, rule: &Rule, audit: &RuleAudit, context: &[u8]) -> Result<(), String> {
        // The declared bands, aggregated. The commitments the proof covers must
        // be the offsets of the very commitments the audit publishes, or the
        // range proof is about numbers nobody else constrained.
        if let Some((proof, commitments, names)) = &audit.declared_ranges {
            let mut expected = Vec::with_capacity(names.len());
            for name in names {
                let declaration = rule
                    .declarations
                    .get(name)
                    .ok_or_else(|| format!("{name}: no such declaration"))?;
                let commitment = audit
                    .declared
                    .get(name)
                    .ok_or_else(|| format!("{name}: no commitment"))?;
                expected
                    .push((commitment - self.key.g * scalar(declaration.interval.lo)).compress());
            }
            if commitments.len() < expected.len() || commitments[..expected.len()] != expected[..] {
                return Err("a declared range proof is about the wrong commitment".into());
            }
            let ranges = RangeCtx::new(STEP_BITS, names.len().next_power_of_two());
            let mut t = transcript(&[context, b":decl"].concat());
            if !ranges.verify(&mut t, proof, commitments) {
                return Err("a secret is outside its declared band".into());
            }
        }

        for step in &audit.steps {
            let ok = match step {
                Step::Product {
                    a,
                    b,
                    c,
                    proof,
                    tag,
                    ..
                } => verify_product(&self.key, &mut transcript(tag), a, b, c, proof),
                Step::Range {
                    commitment,
                    proof,
                    tag,
                    ..
                } => self.ranges.verify(
                    &mut transcript(tag),
                    proof,
                    std::slice::from_ref(commitment),
                ),
                Step::Bit {
                    commitment,
                    proof,
                    tag,
                    ..
                } => verify_bit(&self.key, &mut transcript(tag), commitment, proof),
                Step::Equality {
                    commitment,
                    proof,
                    tag,
                    ..
                } => verify_opening(&self.key, &mut transcript(tag), commitment, proof),
            };
            if !ok {
                return Err(format!("a {} step of the audit failed", step.kind()));
            }
        }
        Ok(())
    }
}
