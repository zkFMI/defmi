//! Tokenise and parse the expression subset.
//!
//! tree against an allow-list, which is convenient and gets the allow-list
//! backwards: everything is permitted until named otherwise, and the language
//! grows whenever the host's does. Here the grammar is written out, so the
//! subset is what the parser can express and nothing else. There are no loops,
//! no indexing, no attributes, no division, no floating point, and the only
//! calls are four named intrinsics.

use crate::interval::RuleError;

/// Identifiers a price rule may never read. Reading any of these would let the
/// quote depend on who is asking, which is the one thing the design forbids.
pub const FORBIDDEN: [&str; 12] = [
    "wallet",
    "address",
    "entity",
    "entity_id",
    "user",
    "user_id",
    "client",
    "counterparty",
    "name",
    "kyc_id",
    "nullifier",
    "ip",
];

pub const INTRINSICS: [&str; 4] = ["min", "max", "clamp", "signed"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cmp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

impl Cmp {
    pub fn as_str(&self) -> &'static str {
        match self {
            Cmp::Lt => "<",
            Cmp::Le => "<=",
            Cmp::Gt => ">",
            Cmp::Ge => ">=",
            Cmp::Eq => "==",
            Cmp::Ne => "!=",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    Const(i128),
    Name(String),
    Neg(Box<Expr>),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    Compare(Box<Expr>, Cmp, Box<Expr>),
    /// `and` only. `or` would need a disjunction proof.
    And(Vec<Expr>),
    Call(String, Vec<Expr>),
}

impl Expr {
    /// Source-like rendering, used in obligation text so an audit line points at
    /// something the author will recognise.
    pub fn render(&self) -> String {
        match self {
            Expr::Const(v) => v.to_string(),
            Expr::Name(n) => n.clone(),
            Expr::Neg(e) => format!("-{}", e.render()),
            Expr::Add(a, b) => format!("{} + {}", a.render(), b.render()),
            Expr::Sub(a, b) => format!("{} - {}", a.render(), b.render()),
            Expr::Mul(a, b) => format!("{} * {}", a.render(), b.render()),
            Expr::Compare(a, op, b) => format!("{} {} {}", a.render(), op.as_str(), b.render()),
            Expr::And(parts) => parts
                .iter()
                .map(Expr::render)
                .collect::<Vec<_>>()
                .join(" and "),
            Expr::Call(name, args) => format!(
                "{}({})",
                name,
                args.iter().map(Expr::render).collect::<Vec<_>>().join(", ")
            ),
        }
    }

    pub fn names(&self) -> Vec<&str> {
        let mut out = Vec::new();
        self.walk_names(&mut out);
        out
    }

    fn walk_names<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Expr::Const(_) => {}
            Expr::Name(n) => out.push(n),
            Expr::Neg(e) => e.walk_names(out),
            Expr::Add(a, b) | Expr::Sub(a, b) | Expr::Mul(a, b) => {
                a.walk_names(out);
                b.walk_names(out);
            }
            Expr::Compare(a, _, b) => {
                a.walk_names(out);
                b.walk_names(out);
            }
            Expr::And(parts) => {
                for p in parts {
                    p.walk_names(out)
                }
            }
            Expr::Call(_, args) => {
                for a in args {
                    a.walk_names(out)
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Int(i128),
    Ident(String),
    Plus,
    Minus,
    Star,
    LParen,
    RParen,
    Comma,
    Cmp(Cmp),
    And,
}

fn tokenize(text: &str, lineno: usize) -> Result<Vec<Token>, RuleError> {
    let bytes: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let text: String = bytes[start..i].iter().collect();
            out.push(Token::Int(text.parse().map_err(|_| {
                RuleError(format!("line {lineno}: integer '{text}' does not fit"))
            })?));
            continue;
        }
        if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_alphanumeric() || bytes[i] == '_') {
                i += 1;
            }
            let word: String = bytes[start..i].iter().collect();
            out.push(if word == "and" {
                Token::And
            } else {
                Token::Ident(word)
            });
            continue;
        }
        let two: String = bytes[i..(i + 2).min(bytes.len())].iter().collect();
        let token = match two.as_str() {
            "<=" => Some(Token::Cmp(Cmp::Le)),
            ">=" => Some(Token::Cmp(Cmp::Ge)),
            "==" => Some(Token::Cmp(Cmp::Eq)),
            "!=" => Some(Token::Cmp(Cmp::Ne)),
            _ => None,
        };
        if let Some(t) = token {
            out.push(t);
            i += 2;
            continue;
        }
        out.push(match c {
            '+' => Token::Plus,
            '-' => Token::Minus,
            '*' => Token::Star,
            '(' => Token::LParen,
            ')' => Token::RParen,
            ',' => Token::Comma,
            '<' => Token::Cmp(Cmp::Lt),
            '>' => Token::Cmp(Cmp::Gt),
            '/' => {
                return Err(RuleError(format!(
                    "line {lineno}: there is no division in this language"
                )))
            }
            other => {
                return Err(RuleError(format!(
                    "line {lineno}: '{other}' is not part of this language"
                )))
            }
        });
        i += 1;
    }
    Ok(out)
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
    lineno: usize,
}

pub fn parse_expression(text: &str, lineno: usize) -> Result<Expr, RuleError> {
    let tokens = tokenize(text, lineno)?;
    if tokens.is_empty() {
        return Err(RuleError(format!("line {lineno}: empty expression")));
    }
    let mut parser = Parser {
        tokens,
        at: 0,
        lineno,
    };
    let expr = parser.conjunction()?;
    if parser.at != parser.tokens.len() {
        return Err(RuleError(format!(
            "line {lineno}: trailing input after the expression"
        )));
    }
    Ok(expr)
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }
    fn eat(&mut self, token: &Token) -> bool {
        if self.peek() == Some(token) {
            self.at += 1;
            true
        } else {
            false
        }
    }
    fn err<T>(&self, what: &str) -> Result<T, RuleError> {
        Err(RuleError(format!("line {}: expected {what}", self.lineno)))
    }

    fn conjunction(&mut self) -> Result<Expr, RuleError> {
        let first = self.comparison()?;
        if self.peek() != Some(&Token::And) {
            return Ok(first);
        }
        let mut parts = vec![first];
        while self.eat(&Token::And) {
            parts.push(self.comparison()?);
        }
        Ok(Expr::And(parts))
    }

    fn comparison(&mut self) -> Result<Expr, RuleError> {
        let left = self.sum()?;
        let op = match self.peek() {
            Some(Token::Cmp(op)) => op.clone(),
            _ => return Ok(left),
        };
        self.at += 1;
        let right = self.sum()?;
        // Chained comparisons would need two proofs and mean two things; the
        if matches!(self.peek(), Some(Token::Cmp(_))) {
            return Err(RuleError(format!(
                "line {}: chained comparisons are not allowed",
                self.lineno
            )));
        }
        Ok(Expr::Compare(Box::new(left), op, Box::new(right)))
    }

    fn sum(&mut self) -> Result<Expr, RuleError> {
        let mut left = self.product()?;
        loop {
            if self.eat(&Token::Plus) {
                left = Expr::Add(Box::new(left), Box::new(self.product()?));
            } else if self.eat(&Token::Minus) {
                left = Expr::Sub(Box::new(left), Box::new(self.product()?));
            } else {
                return Ok(left);
            }
        }
    }

    fn product(&mut self) -> Result<Expr, RuleError> {
        let mut left = self.unary()?;
        while self.eat(&Token::Star) {
            left = Expr::Mul(Box::new(left), Box::new(self.unary()?));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, RuleError> {
        if self.eat(&Token::Minus) {
            return Ok(Expr::Neg(Box::new(self.unary()?)));
        }
        if self.eat(&Token::Plus) {
            return self.unary();
        }
        self.atom()
    }

    fn atom(&mut self) -> Result<Expr, RuleError> {
        match self.peek().cloned() {
            Some(Token::Int(v)) => {
                self.at += 1;
                Ok(Expr::Const(v))
            }
            Some(Token::LParen) => {
                self.at += 1;
                let inner = self.conjunction()?;
                if !self.eat(&Token::RParen) {
                    return self.err("a closing parenthesis");
                }
                Ok(inner)
            }
            Some(Token::Ident(name)) => {
                self.at += 1;
                if !self.eat(&Token::LParen) {
                    return Ok(Expr::Name(name));
                }
                if !INTRINSICS.contains(&name.as_str()) {
                    return Err(RuleError(format!(
                        "line {}: only {:?} may be called",
                        self.lineno, INTRINSICS
                    )));
                }
                let mut args = Vec::new();
                if !self.eat(&Token::RParen) {
                    loop {
                        args.push(self.conjunction()?);
                        if self.eat(&Token::RParen) {
                            break;
                        }
                        if !self.eat(&Token::Comma) {
                            return self.err("',' or ')'");
                        }
                    }
                }
                Ok(Expr::Call(name, args))
            }
            _ => self.err("a value"),
        }
    }
}
