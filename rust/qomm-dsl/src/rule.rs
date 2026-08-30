//! Declarations, the checked rule, and everything the checker derives from it.

use std::collections::{BTreeMap, BTreeSet};

use crate::interval::{Interval, RuleError};
use crate::parse::{parse_expression, Cmp, Expr, FORBIDDEN, INTRINSICS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Param,
    State,
    Input,
}

impl Role {
    /// A parameter or a state is secret and so contributes degree; an input is
    /// the request, which is secret from the makers but public to the circuit's
    /// degree accounting.
    pub fn is_secret(&self) -> bool {
        matches!(self, Role::Param | Role::State)
    }

    fn parse(word: &str) -> Option<Role> {
        match word {
            "param" => Some(Role::Param),
            "state" => Some(Role::State),
            "input" => Some(Role::Input),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Param => "param",
            Role::State => "state",
            Role::Input => "input",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Declaration {
    pub name: String,
    pub interval: Interval,
    pub role: Role,
}

/// One zero-knowledge proof the audit has to carry, derived from the source
/// rather than written down beside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Obligation {
    /// product | range | bit | equality
    pub kind: String,
    pub target: String,
    pub detail: String,
    pub bits: u32,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub name: String,
    pub declarations: BTreeMap<String, Declaration>,
    pub outputs: Vec<(String, Expr)>,
    pub source: String,
    pub intervals: BTreeMap<String, Interval>,
    pub degrees: BTreeMap<String, u32>,
    pub obligations: Vec<Obligation>,
}

impl Rule {
    pub fn secrets(&self) -> Vec<&str> {
        self.declarations
            .values()
            .filter(|d| d.role.is_secret())
            .map(|d| d.name.as_str())
            .collect()
    }

    pub fn inputs(&self) -> Vec<&str> {
        self.declarations
            .values()
            .filter(|d| d.role == Role::Input)
            .map(|d| d.name.as_str())
            .collect()
    }

    pub fn output_interval(&self) -> Interval {
        let mut combined: Option<Interval> = None;
        for (name, _) in &self.outputs {
            let interval = self.intervals[name];
            combined = Some(match combined {
                None => interval,
                Some(c) => c.union(interval),
            });
        }
        combined.expect("a checked rule has at least one output")
    }

    /// The width the circuit has to carry, which is a compiler output rather
    /// than a number someone chose.
    pub fn required_bits(&self) -> u32 {
        self.output_interval().width_bits()
    }

    pub fn max_degree(&self) -> u32 {
        self.degrees.values().copied().max().unwrap_or(0)
    }
}

pub fn compile_rule(source: &str, name: &str) -> Result<Rule, RuleError> {
    check(parse(source, name)?)
}

pub fn parse(source: &str, name: &str) -> Result<Rule, RuleError> {
    let mut declarations: BTreeMap<String, Declaration> = BTreeMap::new();
    let mut outputs: Vec<(String, Expr)> = Vec::new();

    for (index, raw) in source.lines().enumerate() {
        let lineno = index + 1;
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (head, rest) = line.split_once(' ').unwrap_or((line, ""));
        if let Some(role) = Role::parse(head) {
            for declaration in parse_declarations(role, rest, lineno)? {
                declarations.insert(declaration.name.clone(), declaration);
            }
            continue;
        }
        let (target, expression) = line.split_once('=').ok_or_else(|| {
            RuleError(format!(
                "line {lineno}: expected a declaration or an assignment"
            ))
        })?;
        let target = target.trim();
        if target.is_empty() || !is_identifier(target) {
            return Err(RuleError(format!(
                "line {lineno}: '{target}' is not a valid output name"
            )));
        }
        if declarations.contains_key(target) {
            return Err(RuleError(format!(
                "line {lineno}: '{target}' is already declared"
            )));
        }
        outputs.push((
            target.to_string(),
            parse_expression(expression.trim(), lineno)?,
        ));
    }

    if declarations.is_empty() {
        return Err(RuleError(
            "a rule must declare at least one parameter".into(),
        ));
    }
    if outputs.is_empty() {
        return Err(RuleError("a rule must produce at least one output".into()));
    }
    Ok(Rule {
        name: name.to_string(),
        declarations,
        outputs,
        source: source.to_string(),
        intervals: BTreeMap::new(),
        degrees: BTreeMap::new(),
        obligations: Vec::new(),
    })
}

fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    matches!(chars.next(), Some(c) if c.is_alphabetic() || c == '_')
        && chars.all(|c| c.is_alphanumeric() || c == '_')
}

/// `spread[2,400] slope[0,16]` — a name is only accepted with a range, so a rule
/// cannot declare something whose width the checker would have to guess.
fn parse_declarations(
    role: Role,
    rest: &str,
    lineno: usize,
) -> Result<Vec<Declaration>, RuleError> {
    let mut out = Vec::new();
    let mut chars = rest.char_indices().peekable();
    let text: Vec<char> = rest.chars().collect();
    let mut consumed = vec![false; text.len()];

    while let Some((start, c)) = chars.next() {
        if !(c.is_alphabetic() || c == '_') {
            continue;
        }
        let mut end = start + c.len_utf8();
        while let Some((i, c)) = chars.peek().copied() {
            if c.is_alphanumeric() || c == '_' {
                end = i + c.len_utf8();
                chars.next();
            } else {
                break;
            }
        }
        let name = &rest[start..end];
        let remainder = rest[end..].trim_start();
        if !remainder.starts_with('[') {
            return Err(RuleError(format!(
                "line {lineno}: '{name}' needs a range, e.g. spread[2,400]"
            )));
        }
        let close = remainder
            .find(']')
            .ok_or_else(|| RuleError(format!("line {lineno}: '{name}' has no closing bracket")))?;
        let bounds = &remainder[1..close];
        let (lo, hi) = bounds.split_once(',').ok_or_else(|| {
            RuleError(format!(
                "line {lineno}: bad range on '{name}': expected two bounds"
            ))
        })?;
        let parse_bound = |t: &str| {
            t.trim().parse::<i128>().map_err(|_| {
                RuleError(format!(
                    "line {lineno}: bad range on '{name}': '{}' is not an integer",
                    t.trim()
                ))
            })
        };
        let interval = Interval::new(parse_bound(lo)?, parse_bound(hi)?)
            .map_err(|e| RuleError(format!("line {lineno}: bad range on '{name}': {e}")))?;

        if FORBIDDEN.contains(&name) {
            return Err(RuleError(format!(
                "line {lineno}: '{name}' may not be a pricing input; a quote must not \
                 depend on who is asking"
            )));
        }
        out.push(Declaration {
            name: name.to_string(),
            interval,
            role,
        });

        // Everything up to the closing bracket belongs to this declaration.
        let absolute = rest[..end].chars().count()
            + rest[end..]
                .chars()
                .take_while(|c| c.is_whitespace())
                .count();
        for slot in consumed
            .iter_mut()
            .take(absolute + close + 1)
            .skip(rest[..start].chars().count())
        {
            *slot = true;
        }
        // Resume tokenising after the bracket.
        let skip_to =
            end + (remainder.as_ptr() as usize - rest[end..].as_ptr() as usize) + close + 1;
        while let Some((i, _)) = chars.peek().copied() {
            if i < skip_to {
                chars.next();
            } else {
                break;
            }
        }
    }

    if out.is_empty() {
        return Err(RuleError(format!("line {lineno}: no declarations found")));
    }
    Ok(out)
}

/// Interval arithmetic, degree tracking and obligation extraction in one pass.
struct Analyser<'a> {
    rule: &'a Rule,
    obligations: Vec<Obligation>,
    label: String,
}

impl<'a> Analyser<'a> {
    fn note(&mut self, kind: &str, detail: String, bits: u32) {
        self.obligations.push(Obligation {
            kind: kind.into(),
            target: self.label.clone(),
            detail,
            bits,
        });
    }

    /// Dispatch by construct rather than by one long match arm apiece.
    ///
    /// Each handler below is the whole answer for one construct: what interval
    /// it produces, what degree it costs, and what it obliges the audit to
    /// prove. Keeping those three together per construct is the point --- they
    /// are what a reader changing the language has to keep consistent.
    fn visit(&mut self, node: &Expr) -> Result<(Interval, u32), RuleError> {
        match node {
            Expr::Const(v) => Ok((Interval::point(*v), 0)),
            Expr::Name(name) => self.name(name),
            Expr::Neg(inner) => {
                let (interval, degree) = self.visit(inner)?;
                Ok((interval.negated(), degree))
            }
            Expr::Add(a, b) => self.additive(a, b, true),
            Expr::Sub(a, b) => self.additive(a, b, false),
            Expr::Mul(a, b) => self.product(a, b),
            Expr::Compare(a, op, b) => self.comparison(node, a, op, b),
            Expr::And(parts) => self.conjunction(parts),
            Expr::Call(name, args) => self.call(name, args),
        }
    }

    fn name(&mut self, name: &str) -> Result<(Interval, u32), RuleError> {
        if FORBIDDEN.contains(&name) {
            return Err(RuleError(format!(
                "'{name}' may not be used in a price rule"
            )));
        }
        let declaration = self.rule.declarations.get(name).ok_or_else(|| {
            RuleError(format!(
                "'{name}' is not declared; a rule may only read its own \
                     declared parameters, state and inputs"
            ))
        })?;
        // Inputs are committed with fresh blindings too, so they contribute
        // degree exactly like parameters and state. Treating them as public to
        // the proof cost model drops every input-times-secret obligation.
        Ok((declaration.interval, 1))
    }

    /// Addition and subtraction are free: no proof, and no round in the circuit.
    fn additive(&mut self, a: &Expr, b: &Expr, adding: bool) -> Result<(Interval, u32), RuleError> {
        let ((ia, da), (ib, db)) = (self.visit(a)?, self.visit(b)?);
        Ok((if adding { ia.plus(ib) } else { ia.minus(ib) }, da.max(db)))
    }

    /// A secret times a secret is the one construct that costs a proof.
    fn product(&mut self, a: &Expr, b: &Expr) -> Result<(Interval, u32), RuleError> {
        let ((ia, da), (ib, db)) = (self.visit(a)?, self.visit(b)?);
        let degree = da + db;
        if degree > 2 {
            return Err(RuleError(
                "a price rule may not exceed degree two in its secrets; higher \
                 degree would need a proof per intermediate product"
                    .into(),
            ));
        }
        if degree == 2 {
            self.note("product", format!("{} * {}", a.render(), b.render()), 0);
        }
        Ok((ia.times(ib), degree))
    }

    /// A total comparison costs a bit, a product and a range proof. Equality is
    /// a zero test: one product sends the difference to zero and another proves
    /// it invertible when the result bit is zero.
    fn comparison(
        &mut self,
        node: &Expr,
        a: &Expr,
        op: &Cmp,
        b: &Expr,
    ) -> Result<(Interval, u32), RuleError> {
        let ((ia, _), (ib, _)) = (self.visit(a)?, self.visit(b)?);
        self.note("bit", format!("result of {}", node.render()), 0);
        if matches!(op, Cmp::Eq | Cmp::Ne) {
            self.note(
                "product",
                format!("{}: the bit sends the difference to zero", node.render()),
                0,
            );
            self.note(
                "product",
                format!(
                    "{}: the difference is invertible when the bit is 0",
                    node.render()
                ),
                0,
            );
        } else {
            let difference = if matches!(op, Cmp::Gt | Cmp::Ge) {
                ia.minus(ib)
            } else {
                ib.minus(ia)
            };
            self.note(
                "product",
                format!("{}: the bit against the difference", node.render()),
                0,
            );
            self.note(
                "range",
                node.render(),
                difference.minus(Interval::point(1)).width_bits() + 1,
            );
        }
        Ok((Interval::new(0, 1)?, 0))
    }

    /// A conjunction is a product of bits: one multiplication each, which is
    /// also why `or` is not in the language.
    fn conjunction(&mut self, parts: &[Expr]) -> Result<(Interval, u32), RuleError> {
        for part in parts {
            let (interval, _) = self.visit(part)?;
            if !interval.is_condition() {
                return Err(RuleError("'and' may only combine conditions".into()));
            }
        }
        for _ in 1..parts.len() {
            self.note("product", "conjunction of two conditions".into(), 0);
        }
        Ok((Interval::new(0, 1)?, 0))
    }

    fn call(&mut self, name: &str, args: &[Expr]) -> Result<(Interval, u32), RuleError> {
        if !INTRINSICS.contains(&name) {
            return Err(RuleError(format!("only {INTRINSICS:?} may be called")));
        }
        let parts: Vec<(Interval, u32)> = args
            .iter()
            .map(|a| self.visit(a))
            .collect::<Result<_, _>>()?;
        match name {
            "min" | "max" => {
                if parts.len() != 2 {
                    return Err(RuleError(format!("{name} takes exactly two arguments")));
                }
                let ((a, da), (b, db)) = (parts[0], parts[1]);
                self.note(
                    "range",
                    format!("{name} comparison"),
                    a.minus(b).width_bits(),
                );
                self.note("product", format!("{name} selection"), 0);
                let merged = if name == "min" {
                    Interval {
                        lo: a.lo.min(b.lo),
                        hi: a.hi.min(b.hi),
                    }
                } else {
                    Interval {
                        lo: a.lo.max(b.lo),
                        hi: a.hi.max(b.hi),
                    }
                };
                Ok((merged, da.max(db)))
            }
            "clamp" => {
                if parts.len() != 3 {
                    return Err(RuleError("clamp takes a value and two bounds".into()));
                }
                let ((value, degree), (lo, _), (hi, _)) = (parts[0], parts[1], parts[2]);
                if lo.lo != lo.hi || hi.lo != hi.hi {
                    return Err(RuleError(
                        "clamp bounds must be constants so the range is static".into(),
                    ));
                }
                self.note(
                    "range",
                    "clamp lower bound".into(),
                    value.minus(lo).width_bits(),
                );
                self.note(
                    "range",
                    "clamp upper bound".into(),
                    hi.minus(value).width_bits(),
                );
                self.note("product", "clamp selection".into(), 0);
                Ok((Interval::new(lo.lo, hi.hi)?, degree))
            }
            "signed" => {
                if parts.len() != 2 {
                    return Err(RuleError("signed takes a side bit and a magnitude".into()));
                }
                let ((side, _), (magnitude, degree)) = (parts[0], parts[1]);
                if !side.is_condition() {
                    return Err(RuleError(
                        "the first argument of signed must be a condition".into(),
                    ));
                }
                self.note("product", "signed selection".into(), 0);
                Ok((Interval::new(-magnitude.hi, magnitude.hi)?, degree))
            }
            _ => Err(RuleError(format!("unknown intrinsic {name}"))),
        }
    }
}

/// Run every static check and fill in the derived facts.
pub fn check(mut rule: Rule) -> Result<Rule, RuleError> {
    let mut intervals = BTreeMap::new();
    let mut degrees = BTreeMap::new();
    let mut obligations = {
        let mut analyser = Analyser {
            rule: &rule,
            obligations: Vec::new(),
            label: String::new(),
        };
        for (label, tree) in &rule.outputs {
            analyser.label = label.clone();
            let (interval, degree) = analyser.visit(tree)?;
            intervals.insert(label.clone(), interval);
            degrees.insert(label.clone(), degree);
        }
        std::mem::take(&mut analyser.obligations)
    };

    // The declared bounds are themselves obligations at registration time.
    let mut declared: Vec<Obligation> = rule
        .declarations
        .values()
        .filter(|d| d.role.is_secret())
        .map(|d| Obligation {
            kind: "range".into(),
            target: d.name.clone(),
            detail: format!("{} in {}", d.name, d.interval),
            bits: {
                let span = (d.interval.hi - d.interval.lo).unsigned_abs();
                (128 - span.leading_zeros()).max(1)
            },
        })
        .collect();
    declared.append(&mut obligations);

    // A parameter declared and never read is either dead weight or a channel for
    // something the rule is not supposed to carry. Either way the registry
    // should not be asked to hold it.
    let read: BTreeSet<&str> = rule.outputs.iter().flat_map(|(_, e)| e.names()).collect();
    let unused: Vec<&str> = rule
        .declarations
        .keys()
        .map(String::as_str)
        .filter(|n| !read.contains(n))
        .collect();
    if !unused.is_empty() {
        return Err(RuleError(format!(
            "declared but never used: {unused:?}; a rule may not register values \
             it does not price with"
        )));
    }

    rule.intervals = intervals;
    rule.degrees = degrees;
    rule.obligations = declared;
    Ok(rule)
}
