//! Registered digests, so a substituted rule or circuit is detectable.
//!
//! The design asks that an approved rule form and its circuit digest be
//! registered, with only the secret parameters replaceable afterwards. The
//! language makes that a one-line property: the digest covers the canonical
//! source, the declared bounds and the emitted circuit, but not the values.
//! Swapping a parameter keeps the digest; swapping the rule does not.
//!
//! That covers the rule and stops there, which is the part that was missing.
//! What the computing nodes execute is not a rule --- it is a program emitted
//! from one and then compiled --- so a node holding the approved digest can still
//! compile something else and the registry would never know. A second digest
//! therefore covers the emitted program text, and the two are registered
//! together with the circuit shape they belong to. Approving a rule and running
//! a different circuit now requires the shape or the program to differ, and both
//! are checked before the compiler is invoked rather than after the answers are
//! out.
//!
//! Deliberately not claimed: this binds the program text the nodes were given,
//! not the bytecode their compiler produced.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::emit::to_mpc;
use crate::interval::RuleError;
use crate::rule::{compile_rule, Rule};

const RULE_DOMAIN: &[u8] = b"QOMM:RULE-DIGEST:v1";
const PROGRAM_DOMAIN: &[u8] = b"QOMM:PROGRAM-DIGEST:v1";
pub const POLICY_RULE_DIGEST_MARKER: &str = "# QOMM_POLICY_RULE_DIGEST=";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Everything that must not change: the shape, the bounds, the circuit. Not the
/// values --- that is the whole point.
pub fn canonical(rule: &Rule) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(rule.name.as_bytes());
    out.push(0);
    for (name, declaration) in &rule.declarations {
        out.extend_from_slice(name.as_bytes());
        out.push(b'=');
        out.extend_from_slice(declaration.role.as_str().as_bytes());
        out.extend_from_slice(
            format!(":{}:{}", declaration.interval.lo, declaration.interval.hi).as_bytes(),
        );
        out.push(b';');
    }
    out.push(0);
    for (name, expression) in to_mpc(rule) {
        out.extend_from_slice(name.as_bytes());
        out.push(b'=');
        out.extend_from_slice(expression.as_bytes());
        out.push(b';');
    }
    out.extend_from_slice(
        format!("bits={};degree={}", rule.required_bits(), rule.max_degree()).as_bytes(),
    );
    out
}

pub fn rule_digest(rule: &Rule) -> String {
    let mut h = Sha256::new();
    h.update(RULE_DOMAIN);
    h.update(canonical(rule));
    hex(&h.finalize())
}

/// Digest of the emitted program text.
///
/// Normalised for trailing whitespace and a trailing newline, because those
/// differ between generators and editors without changing an instruction, and a
/// digest that tripped on them would be turned off.
pub fn program_digest(source: &str) -> String {
    let body: Vec<&str> = source.trim().lines().map(|l| l.trim_end()).collect();
    let mut h = Sha256::new();
    h.update(PROGRAM_DOMAIN);
    h.update(body.join("\n").as_bytes());
    hex(&h.finalize())
}

/// Return the single DSL digest embedded by the Rust MPC generator.
///
/// Requiring exactly one marker prevents a source from carrying both the
/// approved rule and a second, ambiguous rule identity.  Product execution
/// additionally rebuilds the whole source from `ProgramConfig` and compares
/// every byte before deriving the executable.
pub fn embedded_policy_rule_digest(source: &str) -> Result<String, String> {
    let values = source
        .lines()
        .filter_map(|line| line.trim().strip_prefix(POLICY_RULE_DIGEST_MARKER))
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return Err("the MPC source must contain exactly one policy-rule digest marker".into());
    }
    let value = values[0];
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("the MPC policy-rule digest marker is not canonical SHA-256".into());
    }
    Ok(value.to_string())
}

#[derive(Clone, Debug)]
pub struct ApprovedRule {
    pub name: String,
    pub digest: String,
    pub required_bits: u32,
    pub source: String,
}

/// The venue's list of approved rule forms.
#[derive(Default)]
pub struct RuleRegistry {
    approved: BTreeMap<String, ApprovedRule>,
}

impl RuleRegistry {
    pub fn approve(&mut self, source: &str, name: &str) -> Result<ApprovedRule, RuleError> {
        let rule = compile_rule(source, name)?;
        let entry = ApprovedRule {
            name: name.to_string(),
            digest: rule_digest(&rule),
            required_bits: rule.required_bits(),
            source: source.to_string(),
        };
        self.approved.insert(entry.digest.clone(), entry.clone());
        Ok(entry)
    }

    /// Reject a rule that is not the approved one, or a mislabelled digest.
    pub fn check(&self, source: &str, name: &str, claimed: &str) -> Result<(), &'static str> {
        if !self.approved.contains_key(claimed) {
            return Err("the claimed digest is not an approved rule form");
        }
        let rule = compile_rule(source, name).map_err(|_| "the rule does not compile")?;
        if rule_digest(&rule) != claimed {
            return Err("the rule does not hash to the digest it claims; \
                        the registered form was substituted");
        }
        Ok(())
    }
}

/// A rule, the program emitted from it, and the shape they were approved for.
///
/// The shape is part of the identity because one rule emits different circuits
/// for different maker counts or bit widths, and a node asked for one shape must
/// not answer with another.
#[derive(Clone, Debug)]
pub struct ApprovedCircuit {
    pub name: String,
    pub rule_digest: String,
    pub program_digest: String,
    pub shape: Vec<u64>,
}

impl ApprovedCircuit {
    pub fn matches(&self, program: &str, shape: &[u64]) -> Result<(), String> {
        if shape != self.shape.as_slice() {
            return Err(format!(
                "circuit shape {shape:?} was never approved for {}; the approved \
                 shape is {:?}",
                self.name, self.shape
            ));
        }
        let actual = program_digest(program);
        if actual != self.program_digest {
            return Err(format!(
                "the program for {} does not match what was approved: {} against {}",
                self.name,
                &actual[..16],
                &self.program_digest[..16]
            ));
        }
        Ok(())
    }
}

/// What each shape is allowed to compile, checked before the compiler runs.
#[derive(Default)]
pub struct CircuitRegistry {
    approved: BTreeMap<Vec<u64>, ApprovedCircuit>,
}

impl CircuitRegistry {
    pub fn approve(
        &mut self,
        name: &str,
        rule_source: &str,
        program_source: &str,
        shape: &[u64],
    ) -> Result<ApprovedCircuit, RuleError> {
        let rule = compile_rule(rule_source, name)?;
        let expected_rule_digest = rule_digest(&rule);
        let embedded = embedded_policy_rule_digest(program_source).map_err(RuleError)?;
        if embedded != expected_rule_digest {
            return Err(RuleError(
                "the MPC source was generated from a different price-rule DSL".into(),
            ));
        }
        let entry = ApprovedCircuit {
            name: rule.name.clone(),
            rule_digest: expected_rule_digest,
            program_digest: program_digest(program_source),
            shape: shape.to_vec(),
        };
        self.approved.insert(shape.to_vec(), entry.clone());
        Ok(entry)
    }

    pub fn check(&self, program: &str, shape: &[u64]) -> Result<(), String> {
        match self.approved.get(shape) {
            None => Err(format!("no circuit is approved for shape {shape:?}")),
            Some(entry) => entry.matches(program, shape),
        }
    }

    pub fn approved_shapes(&self) -> Vec<&Vec<u64>> {
        self.approved.keys().collect()
    }
}
