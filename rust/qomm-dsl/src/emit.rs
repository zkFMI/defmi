//! Emit what a checked rule implies: the circuit, an evaluator, the obligations.
//!
//! They come from one source, so they cannot drift apart. That is the practical
//! reason to have a language here: the audit is a compiler output, and a rule
//! that changes changes its own audit with it.

use std::collections::BTreeMap;

use crate::interval::RuleError;
use crate::parse::{Cmp, Expr};
use crate::rule::Rule;

/// The proof obligations derived from one checked rule, grouped exactly as the
/// registration audit and generated documents consume them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObligationPlan {
    pub counts: BTreeMap<String, usize>,
    pub total: usize,
    pub range_bits: Vec<u32>,
    pub total_bit_proofs: usize,
    pub required_circuit_bits: u32,
    pub output_intervals: BTreeMap<String, (i128, i128)>,
}

/// Group the compiler-derived obligations so an audit can be costed before it
/// is proved. This mirrors `qomm_dsl.emit.obligation_plan`.
pub fn obligation_plan(rule: &Rule) -> ObligationPlan {
    let mut counts = BTreeMap::new();
    let mut range_bits = Vec::new();
    for obligation in &rule.obligations {
        *counts.entry(obligation.kind.clone()).or_insert(0) += 1;
        if obligation.kind == "range" {
            range_bits.push(obligation.bits);
        }
    }
    range_bits.sort_unstable();
    let total_bit_proofs = range_bits.iter().map(|bits| *bits as usize).sum::<usize>()
        + counts.get("bit").copied().unwrap_or(0);
    let output_intervals = rule
        .intervals
        .iter()
        .map(|(name, interval)| (name.clone(), (interval.lo, interval.hi)))
        .collect();
    ObligationPlan {
        counts,
        total: rule.obligations.len(),
        range_bits,
        total_bit_proofs,
        required_circuit_bits: rule.required_bits(),
        output_intervals,
    }
}

/// One MP-SPDZ expression per output, over the declared columns.
///
/// MP-SPDZ works on secret vectors, so every declared name is one column and the
/// whole maker set is priced in a single pass --- which is why widening the maker
/// count costs bandwidth and not rounds.
pub fn to_mpc(rule: &Rule) -> BTreeMap<String, String> {
    rule.outputs
        .iter()
        .map(|(name, tree)| {
            (
                name.clone(),
                mpc(tree, None).expect("a checked rule only contains declared names"),
            )
        })
        .collect()
}

/// Emit the same checked rule into an existing MPC function.
///
/// The ordinary emitter names a declaration `col_<name>`.  The QOMM product
/// circuit already has vector-valued locals such as `qty_v` and
/// `tile_makers(inv_vec)`, so it supplies those exact bindings here.  The
/// expression tree is still emitted from the checked DSL; callers cannot
/// substitute a handwritten price formula after approval.
pub fn to_mpc_with_bindings(
    rule: &Rule,
    bindings: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, RuleError> {
    for name in rule.declarations.keys() {
        if !bindings.contains_key(name) {
            return Err(RuleError(format!(
                "the MPC binding for declared value '{name}' is missing"
            )));
        }
    }
    rule.outputs
        .iter()
        .map(|(name, tree)| Ok((name.clone(), mpc(tree, Some(bindings))?)))
        .collect()
}

fn mpc(node: &Expr, bindings: Option<&BTreeMap<String, String>>) -> Result<String, RuleError> {
    Ok(match node {
        Expr::Const(v) => format!("sint({v})"),
        Expr::Name(n) => match bindings {
            Some(bindings) => bindings
                .get(n)
                .cloned()
                .ok_or_else(|| RuleError(format!("the MPC binding for '{n}' is missing")))?,
            None => format!("col_{n}"),
        },
        Expr::Neg(e) => format!("(-{})", mpc(e, bindings)?),
        Expr::Add(a, b) => format!("({} + {})", mpc(a, bindings)?, mpc(b, bindings)?),
        Expr::Sub(a, b) => format!("({} - {})", mpc(a, bindings)?, mpc(b, bindings)?),
        Expr::Mul(a, b) => format!("({} * {})", mpc(a, bindings)?, mpc(b, bindings)?),
        Expr::Compare(a, op, b) => {
            let (l, r) = (mpc(a, bindings)?, mpc(b, bindings)?);
            match op {
                Cmp::Lt => format!("({l}).__lt__({r})"),
                Cmp::Le => format!("({l}).__le__({r})"),
                Cmp::Gt => format!("({l}).__gt__({r})"),
                Cmp::Ge => format!("({l}).__ge__({r})"),
                Cmp::Eq => format!("({l}).__eq__({r})"),
                Cmp::Ne => format!("(1 - ({l}).__eq__({r}))"),
            }
        }
        // A conjunction is a product of bits, which is one multiplication each
        // and so one round layer --- the reason 'or' is not in the language.
        Expr::And(parts) => {
            let joined: Vec<String> = parts
                .iter()
                .map(|part| mpc(part, bindings))
                .collect::<Result<_, _>>()?;
            format!("({})", joined.join(" * "))
        }
        Expr::Call(name, args) => {
            let rendered: Vec<String> = args
                .iter()
                .map(|argument| mpc(argument, bindings))
                .collect::<Result<_, _>>()?;
            match (name.as_str(), rendered.as_slice()) {
                ("min", [a, b]) => format!("(({a}).__lt__({b}).if_else({a}, {b}))"),
                ("max", [a, b]) => format!("(({a}).__lt__({b}).if_else({b}, {a}))"),
                ("clamp", [v, lo, hi]) => format!(
                    "((({v}).__lt__({lo})).if_else({lo}, (({hi}).__lt__({v})).if_else({hi}, {v})))"
                ),
                ("signed", [side, magnitude]) => {
                    format!("(({side}).if_else({magnitude}, -({magnitude})))")
                }
                _ => format!("/* unreachable: {name} */"),
            }
        }
    })
}

/// Evaluate the rule in the clear. Every circuit run is checked against this,
/// which is what makes a disagreement a bug report rather than a mystery.
pub fn evaluate(
    rule: &Rule,
    bindings: &BTreeMap<String, i128>,
) -> Result<BTreeMap<String, i128>, RuleError> {
    rule.outputs
        .iter()
        .map(|(name, tree)| Ok((name.clone(), eval(tree, bindings)?)))
        .collect()
}

fn eval(node: &Expr, b: &BTreeMap<String, i128>) -> Result<i128, RuleError> {
    Ok(match node {
        Expr::Const(v) => *v,
        Expr::Name(n) => *b
            .get(n)
            .ok_or_else(|| RuleError(format!("'{n}' has no value")))?,
        Expr::Neg(e) => -eval(e, b)?,
        Expr::Add(x, y) => eval(x, b)? + eval(y, b)?,
        Expr::Sub(x, y) => eval(x, b)? - eval(y, b)?,
        Expr::Mul(x, y) => eval(x, b)? * eval(y, b)?,
        Expr::Compare(x, op, y) => {
            let (l, r) = (eval(x, b)?, eval(y, b)?);
            i128::from(match op {
                Cmp::Lt => l < r,
                Cmp::Le => l <= r,
                Cmp::Gt => l > r,
                Cmp::Ge => l >= r,
                Cmp::Eq => l == r,
                Cmp::Ne => l != r,
            })
        }
        Expr::And(parts) => {
            let mut all = 1;
            for part in parts {
                all &= eval(part, b)?;
            }
            all
        }
        Expr::Call(name, args) => {
            let v: Vec<i128> = args.iter().map(|a| eval(a, b)).collect::<Result<_, _>>()?;
            match (name.as_str(), v.as_slice()) {
                ("min", [a, c]) => *a.min(c),
                ("max", [a, c]) => *a.max(c),
                ("clamp", [value, lo, hi]) => (*value).clamp(*lo, *hi),
                ("signed", [side, magnitude]) => {
                    if *side == 1 {
                        *magnitude
                    } else {
                        -*magnitude
                    }
                }
                _ => return Err(RuleError(format!("cannot evaluate {name}"))),
            }
        }
    })
}
