//! Rust port of `evm/ed_reference.py`.
//!
//! This is deliberately a small RFC 8032 reference implementation over
//! unbounded integers, not a call to dalek: the Solidity vectors need an
//! implementation independent of the curve library used elsewhere in Rust.

use num_bigint::BigUint;
use num_traits::{One, Zero};
use qomm_harness::HarnessResult;
use sha2::{Digest, Sha512};
use std::path::PathBuf;
use std::sync::OnceLock;

const RFC8032_SECRET_1: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const RFC8032_PUBLIC_1: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

const TEMPLATE: &str = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console2 as console} from "forge-std/Test.sol";
import {Ed25519} from "../src/Ed25519.sol";

/// The instrument is checked before it is read.
///
/// The vectors below are the output of an RFC 8032 reference implementation
/// (`rust/qomm-harness/src/bin/ed_reference.rs`), which is itself checked against
/// the public key in the RFC's own first test vector. Two independent
/// implementations agreeing on six points is what makes the gas number beside
/// them worth quoting.
contract Ed25519Test is Test {
    Ed25519 ed;

    function setUp() public { ed = new Ed25519(); }

    function check(uint256 s, uint256 x, uint256 y) internal view {
        (uint256 gx, uint256 gy) = ed.mulBase(s);
        assertEq(gx, x, "x");
        assertEq(gy, y, "y");
    }

    function test_matches_the_reference() public view {
__CHECKS__
    }

    /// What one scalar multiplication costs, and what that makes a settlement
    /// cost when it is composed with the number of them a verification does.
    function test_gas() public {
        uint256 s = __GAS_SCALAR__;
        uint256 before = gasleft();
        ed.mulBase(s);
        uint256 used = before - gasleft();

        // popcount of the scalar: how many of the 256 iterations took the
        // add branch. Reported so the number can be scaled to another scalar.
        uint256 bits = 0;
        for (uint256 t = s; t != 0; t >>= 1) { bits += t & 1; }

        string memory json = string.concat(
            '{\n  "curve": "ed25519",\n  "operation": "base-point scalar multiplication",\n',
            '  "implementation": "extended coordinates, double-and-add, no windowing",\n',
            '  "solc": "0.8.28",\n  "optimizer_runs": 200,\n',
            '  "scalar_bits_set": ', vm.toString(bits), ',\n',
            '  "gas": ', vm.toString(used), '\n}\n'
        );
        vm.writeFile("../artifacts/evm_gas.json", json);
        console.log("gas per scalar multiplication:", used);
    }
}
"#;

#[derive(Clone, Debug)]
struct Point {
    x: BigUint,
    y: BigUint,
    z: BigUint,
    t: BigUint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Vector {
    scalar: BigUint,
    x: BigUint,
    y: BigUint,
}

fn main() {
    if let Err(error) = run_main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run_main() -> HarnessResult<()> {
    let out = parse_args()?;
    validate_rfc8032_vector_1()?;
    println!("reference validated against RFC 8032 test vector 1");
    let vectors = vectors();
    for vector in vectors.iter().take(5) {
        println!(
            "    s=0x{:0>64}\n      x=0x{:0>64}\n      y=0x{:0>64}",
            vector.scalar.to_str_radix(16),
            vector.x.to_str_radix(16),
            vector.y.to_str_radix(16),
        );
    }
    write_test(&out, &vectors)?;
    println!("regenerated {}", out.display());
    Ok(())
}

fn parse_args() -> HarnessResult<PathBuf> {
    let mut out = PathBuf::from("test/Ed25519.t.sol");
    let mut args = std::env::args_os().skip(1);
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--out") => {
                out = PathBuf::from(args.next().ok_or("--out expects one path")?);
            }
            Some("-h" | "--help") => {
                println!("usage: ed_reference [--out PATH]");
                std::process::exit(0);
            }
            Some(value) => return Err(format!("unrecognised argument {value}").into()),
            None => return Err("argument is not valid UTF-8".into()),
        }
    }
    Ok(out)
}

fn prime() -> &'static BigUint {
    static VALUE: OnceLock<BigUint> = OnceLock::new();
    VALUE.get_or_init(|| (BigUint::one() << 255usize) - BigUint::from(19u8))
}

fn order() -> &'static BigUint {
    static VALUE: OnceLock<BigUint> = OnceLock::new();
    VALUE.get_or_init(|| {
        (BigUint::one() << 252usize)
            + BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10)
                .expect("the Ed25519 subgroup order is valid")
    })
}

fn curve_d() -> &'static BigUint {
    static VALUE: OnceLock<BigUint> = OnceLock::new();
    VALUE.get_or_init(|| {
        let quotient = BigUint::from(121_665u32) * inverse(&BigUint::from(121_666u32));
        mod_sub(&BigUint::zero(), &(quotient % prime()))
    })
}

fn inverse(value: &BigUint) -> BigUint {
    value.modpow(&(prime() - BigUint::from(2u8)), prime())
}

fn mod_sub(left: &BigUint, right: &BigUint) -> BigUint {
    if left >= right {
        (left - right) % prime()
    } else {
        (prime() - ((right - left) % prime())) % prime()
    }
}

fn recover_x(y: &BigUint, sign: bool) -> Option<BigUint> {
    if y >= prime() {
        return None;
    }
    let y_squared = (y * y) % prime();
    let numerator = mod_sub(&y_squared, &BigUint::one());
    let denominator = (curve_d() * &y_squared + BigUint::one()) % prime();
    let x_squared = numerator * inverse(&denominator) % prime();
    if x_squared.is_zero() {
        return (!sign).then(BigUint::zero);
    }
    let mut x = x_squared.modpow(&((prime() + BigUint::from(3u8)) >> 3usize), prime());
    if (&x * &x + prime() - &x_squared) % prime() != BigUint::zero() {
        x = x * BigUint::from(2u8).modpow(&((prime() - BigUint::one()) >> 2usize), prime())
            % prime();
    }
    if (&x * &x + prime() - &x_squared) % prime() != BigUint::zero() {
        return None;
    }
    if x.bit(0) != sign {
        x = prime() - x;
    }
    Some(x)
}

fn generator() -> Point {
    let y = BigUint::from(4u8) * inverse(&BigUint::from(5u8)) % prime();
    let x = recover_x(&y, false).expect("the RFC base point is valid");
    Point {
        x: x.clone(),
        y: y.clone(),
        z: BigUint::one(),
        t: x * y % prime(),
    }
}

fn point_add(left: &Point, right: &Point) -> Point {
    let a = mod_sub(&left.y, &left.x) * mod_sub(&right.y, &right.x) % prime();
    let b = (&left.y + &left.x) * (&right.y + &right.x) % prime();
    let c = BigUint::from(2u8) * &left.t * &right.t * curve_d() % prime();
    let d = BigUint::from(2u8) * &left.z * &right.z % prime();
    let e = mod_sub(&b, &a);
    let f = mod_sub(&d, &c);
    let g = (&d + &c) % prime();
    let h = (&b + &a) % prime();
    Point {
        x: &e * &f % prime(),
        y: &g * &h % prime(),
        z: &f * &g % prime(),
        t: &e * &h % prime(),
    }
}

fn point_mul(scalar: &BigUint, point: &Point) -> Point {
    let mut scalar = scalar.clone();
    let mut addend = point.clone();
    let mut result = Point {
        x: BigUint::zero(),
        y: BigUint::one(),
        z: BigUint::one(),
        t: BigUint::zero(),
    };
    while !scalar.is_zero() {
        if scalar.bit(0) {
            result = point_add(&result, &addend);
        }
        addend = point_add(&addend, &addend);
        scalar >>= 1usize;
    }
    result
}

fn affine(point: &Point) -> (BigUint, BigUint) {
    let z = inverse(&point.z);
    (&point.x * &z % prime(), &point.y * z % prime())
}

fn compress(point: &Point) -> [u8; 32] {
    let (x, y) = affine(point);
    let mut encoded = y;
    if x.bit(0) {
        encoded |= BigUint::one() << 255usize;
    }
    let bytes = encoded.to_bytes_le();
    let mut output = [0u8; 32];
    output[..bytes.len()].copy_from_slice(&bytes);
    output
}

fn secret_expand(secret: &[u8]) -> BigUint {
    let digest = Sha512::digest(secret);
    let mut scalar = BigUint::from_bytes_le(&digest[..32]);
    scalar &= (BigUint::one() << 254usize) - BigUint::from(8u8);
    scalar |= BigUint::one() << 254usize;
    scalar
}

fn validate_rfc8032_vector_1() -> HarnessResult<()> {
    let secret = hex::decode(RFC8032_SECRET_1)?;
    let got = hex::encode(compress(&point_mul(&secret_expand(&secret), &generator())));
    if got != RFC8032_PUBLIC_1 {
        return Err(format!("reference is wrong: {got} != {RFC8032_PUBLIC_1}").into());
    }
    Ok(())
}

fn vector_scalars() -> Vec<BigUint> {
    let large = BigUint::parse_bytes(
        b"1f3c9a5b2e8d7460f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708",
        16,
    )
    .expect("the vector scalar is valid")
        % order();
    vec![
        BigUint::one(),
        BigUint::from(2u8),
        BigUint::from(3u8),
        BigUint::from(0xdead_beefu32),
        large,
        order() - BigUint::one(),
    ]
}

fn vectors() -> Vec<Vector> {
    let generator = generator();
    vector_scalars()
        .into_iter()
        .map(|scalar| {
            let (x, y) = affine(&point_mul(&scalar, &generator));
            Vector { scalar, x, y }
        })
        .collect()
}

fn write_test(path: &PathBuf, vectors: &[Vector]) -> HarnessResult<()> {
    let checks = vectors
        .iter()
        .map(|vector| {
            format!(
                "        check({}, {}, {});",
                vector.scalar, vector.x, vector.y
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let gas_scalar = &vectors.get(4).ok_or("the gas vector is missing")?.scalar;
    let rendered = TEMPLATE
        .replace("__CHECKS__", &checks)
        .replace("__GAS_SCALAR__", &gas_scalar.to_string());
    std::fs::write(path, rendered)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8032_vector_one_validates_before_generation() {
        validate_rfc8032_vector_1().unwrap();
    }

    #[test]
    fn six_solidity_vectors_are_stable() {
        let vectors = vectors();
        assert_eq!(vectors.len(), 6);
        assert_eq!(vectors[0].scalar, BigUint::one());
        assert_eq!(
            vectors[0].x.to_string(),
            "15112221349535400772501151409588531511454012693041857206046113283949847762202"
        );
        assert_eq!(
            vectors[5].scalar.to_string(),
            "7237005577332262213973186563042994240857116359379907606001950938285454250988"
        );
    }
}
