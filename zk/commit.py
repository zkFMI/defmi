"""Pedersen commitments and the proofs the market-maker policy audit needs.

Three primitives, all sigma protocols over the same pluggable group:

    opening       I know (v, r) with C = g^v h^r
    bit           C commits to 0 or 1                (a 1-of-2 OR of openings)
    range         C commits to a value in [0, 2^k)   (bit decomposition + linkage)
    linear        a public linear relation holds between committed values

Bulletproofs would give O(log k) proof size instead of O(k), but the prover cost
stays O(k) either way, and the market-maker audit is prover-bound rather than
bandwidth-bound. The simpler construction is used here and the trade-off is
recorded in SURVEY.md rather than hidden.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Sequence

from .groups import DOMAIN, Group


class Pedersen:
    """Commitment key: two generators whose relative discrete log is unknown."""

    def __init__(self, group: Group, label: bytes = b"qomm:pedersen:v1",
                 value_generator=None):
        self.group = group
        self.g = group.base_pow(1) if value_generator is None else value_generator
        self.h = group.hash_to_point(label)
        self._base_valued = value_generator is None

    def with_value_generator(self, generator) -> "Pedersen":
        """The same key with the value carried by a different generator.

        Used for asset tags: a balance of q units of asset a is committed as
        A^q h^r, so commitments of different assets simply do not add up, and
        conservation holds per asset without the ledger learning which asset it
        is holding. The blinding generator stays put, so proofs that only speak
        about h --- openings, the linkage inside a range proof --- are unchanged.
        """
        clone = Pedersen.__new__(Pedersen)
        clone.group = self.group
        clone.g = generator
        clone.h = self.h
        clone._base_valued = False
        return clone

    def commit(self, value: int, blinding: int):
        group = self.group
        if self._base_valued:
            return group.mul(group.base_pow(value % group.order),
                             group.point_pow(self.h, blinding % group.order))
        return group.mul(group.point_pow(self.g, value % group.order),
                         group.point_pow(self.h, blinding % group.order))

    def random_blinding(self) -> int:
        return self.group.random_scalar()

    def _challenge(self, *parts: Any) -> int:
        digest = hashlib.sha512(DOMAIN + b":ped:")
        for part in parts:
            encoded = part if isinstance(part, bytes) else self.group.encode(part)
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
        return int.from_bytes(digest.digest(), "big") % self.group.order


@dataclass(frozen=True)
class OpeningProof:
    commitment_t: Any
    z_value: int
    z_blinding: int


def prove_opening(key: Pedersen, commitment, value: int, blinding: int,
                  context: bytes = b"") -> OpeningProof:
    """Schnorr proof of knowledge of (v, r) with C = g^v h^r."""
    group = key.group
    k_value = group.random_scalar()
    k_blinding = group.random_scalar()
    t = key.commit(k_value, k_blinding)
    c = key._challenge(b"open", context, commitment, t)
    return OpeningProof(t,
                        (k_value + c * value) % group.order,
                        (k_blinding + c * blinding) % group.order)


def verify_opening(key: Pedersen, commitment, proof: OpeningProof,
                   context: bytes = b"") -> bool:
    group = key.group
    if not group.is_valid(proof.commitment_t):
        return False
    if not (0 <= proof.z_value < group.order and 0 <= proof.z_blinding < group.order):
        return False
    c = key._challenge(b"open", context, commitment, proof.commitment_t)
    left = key.commit(proof.z_value, proof.z_blinding)
    right = group.mul(proof.commitment_t, group.point_pow(commitment, c))
    return group.encode(left) == group.encode(right)


@dataclass(frozen=True)
class BitProof:
    """1-of-2 OR proof that a commitment opens to 0 or to 1."""

    t0: Any
    t1: Any
    c0: int
    c1: int
    z0: int
    z1: int


def prove_bit(key: Pedersen, commitment, bit: int, blinding: int,
              context: bytes = b"") -> BitProof:
    """Prove C = h^r (bit 0) or C = g h^r (bit 1) without revealing which."""
    group = key.group
    order = group.order
    # C - bit*g is a pure power of h in the honest branch
    shifted = {0: commitment,
               1: group.mul(commitment, group.neg(key.g))}

    real, fake = bit, 1 - bit
    k = group.random_scalar()
    t_real = group.point_pow(key.h, k)
    c_fake = group.random_scalar()
    z_fake = group.random_scalar()
    # simulate the other branch: t = h^z * (C - fake*g)^-c
    t_fake = group.mul(group.point_pow(key.h, z_fake),
                       group.neg(group.point_pow(shifted[fake], c_fake)))

    t0, t1 = (t_real, t_fake) if bit == 0 else (t_fake, t_real)
    total = key._challenge(b"bit", context, commitment, t0, t1)
    c_real = (total - c_fake) % order
    z_real = (k + c_real * blinding) % order

    if bit == 0:
        return BitProof(t0, t1, c_real, c_fake, z_real, z_fake)
    return BitProof(t0, t1, c_fake, c_real, z_fake, z_real)


def verify_bit(key: Pedersen, commitment, proof: BitProof, context: bytes = b"") -> bool:
    group = key.group
    order = group.order
    if not isinstance(proof, BitProof):
        return False
    if not (group.is_valid(proof.t0) and group.is_valid(proof.t1)):
        return False
    if any(not 0 <= v < order for v in (proof.c0, proof.c1, proof.z0, proof.z1)):
        return False
    total = key._challenge(b"bit", context, commitment, proof.t0, proof.t1)
    if (proof.c0 + proof.c1) % order != total:
        return False
    shifted = {0: commitment,
               1: group.mul(commitment, group.neg(key.g))}
    for branch, challenge, response, t in ((0, proof.c0, proof.z0, proof.t0),
                                           (1, proof.c1, proof.z1, proof.t1)):
        left = group.point_pow(key.h, response)
        right = group.mul(t, group.point_pow(shifted[branch], challenge))
        if group.encode(left) != group.encode(right):
            return False
    return True


@dataclass(frozen=True)
class RangeProof:
    """Value lies in [0, 2^bits): bit commitments plus a linkage proof."""

    bit_commitments: tuple
    bit_proofs: tuple
    linkage: OpeningProof
    bits: int


def prove_range(key: Pedersen, commitment, value: int, blinding: int, bits: int,
                context: bytes = b"") -> RangeProof:
    group = key.group
    order = group.order
    if not 0 <= value < (1 << bits):
        raise ValueError(f"value {value} outside [0, 2^{bits})")
    bit_blindings = [group.random_scalar() for _ in range(bits)]
    bit_values = [(value >> j) & 1 for j in range(bits)]
    commitments = [key.commit(bit_values[j], bit_blindings[j]) for j in range(bits)]
    proofs = [prove_bit(key, commitments[j], bit_values[j], bit_blindings[j],
                        context + b":bit:" + j.to_bytes(2, "big"))
              for j in range(bits)]
    # C / prod C_j^(2^j) must be h^(r - sum 2^j r_j); prove knowledge of that exponent
    combined_blinding = sum((1 << j) * bit_blindings[j] for j in range(bits)) % order
    residual_blinding = (blinding - combined_blinding) % order
    aggregate = group.identity()
    for j in range(bits):
        aggregate = group.mul(aggregate, group.point_pow(commitments[j], 1 << j))
    residual = group.mul(commitment, group.neg(aggregate))
    linkage = prove_opening(key, residual, 0, residual_blinding, context + b":link")
    return RangeProof(tuple(commitments), tuple(proofs), linkage, bits)


def verify_range(key: Pedersen, commitment, proof: RangeProof,
                 context: bytes = b"") -> bool:
    group = key.group
    if not isinstance(proof, RangeProof):
        return False
    if len(proof.bit_commitments) != proof.bits or len(proof.bit_proofs) != proof.bits:
        return False
    for j, (bit_commitment, bit_proof) in enumerate(zip(proof.bit_commitments, proof.bit_proofs)):
        if not group.is_valid(bit_commitment):
            return False
        if not verify_bit(key, bit_commitment, bit_proof,
                          context + b":bit:" + j.to_bytes(2, "big")):
            return False
    aggregate = group.identity()
    for j, bit_commitment in enumerate(proof.bit_commitments):
        aggregate = group.mul(aggregate, group.point_pow(bit_commitment, 1 << j))
    residual = group.mul(commitment, group.neg(aggregate))
    return verify_opening(key, residual, proof.linkage, context + b":link")


def prove_bounded(key: Pedersen, value: int, blinding: int, low: int, high: int,
                  context: bytes = b"") -> tuple[Any, "BoundedProof", int]:
    """Prove low <= value <= high, on both sides.

    One shifted range proof is not enough and used not to be recognised as such.
    A range proof over `bits` establishes `0 <= value - low < 2^bits`, and
    `bits` is the width of the span, so unless the span is one less than a power
    of two the interval actually enforced is *wider than the one published*: a
    band of `[1, 200]` was accepting 201 through 256, because 199 needs eight
    bits and eight bits reach 255. That does not leak the value --- the hiding
    is untouched --- but the venue's published statement that every field is
    inside its band was false for values in the gap, by up to a factor of two
    per field.

    Both sides are therefore proved: `value - low` and `high - value` are each
    in `[0, 2^bits)`, and their sum is fixed at `span`, so together they pin the
    interval exactly. It costs a second range proof, which against a sixty-second
    disclosure interval is not a cost worth a wrong bound.
    """
    span = high - low
    if span < 0:
        raise ValueError("empty interval")
    bits = max(1, span.bit_length())
    if not low <= value <= high:
        raise ValueError(f"value {value} outside [{low}, {high}]")
    commitment = key.commit(value, blinding)
    above = prove_range(key, shift_commitment(key, commitment, low),
                        value - low, blinding, bits, context + b"|above")
    # `high - value` commits under the negated blinding, since
    # C_high / C = g^(high-value) h^(-r)
    ceiling = key.commit(high, 0)
    below_commitment = key.group.mul(
        ceiling, key.group.point_pow(commitment, key.group.order - 1))
    below = prove_range(key, below_commitment, high - value,
                        (-blinding) % key.group.order, bits, context + b"|below")
    return commitment, BoundedProof(above=above, below=below, bits=bits), bits


@dataclass(frozen=True)
class BoundedProof:
    """Two range proofs that together pin an interval that is not a power of two."""

    above: RangeProof
    below: RangeProof
    bits: int


def shift_commitment(key: Pedersen, commitment, low: int):
    """C for value v becomes the commitment for v - low, with the same blinding."""
    group = key.group
    return group.mul(commitment,
                     group.neg(group.point_pow(key.g, low % group.order)))


def verify_bounded(key: Pedersen, commitment, proof: "BoundedProof", low: int,
                   high: int, context: bytes = b"") -> bool:
    span = high - low
    bits = max(1, span.bit_length())
    if span < 0 or proof.bits != bits:
        return False
    if not key.group.is_valid(commitment):
        return False
    if not verify_range(key, shift_commitment(key, commitment, low),
                        proof.above, context + b"|above"):
        return False
    ceiling = key.commit(high, 0)
    below_commitment = key.group.mul(
        ceiling, key.group.point_pow(commitment, key.group.order - 1))
    return verify_range(key, below_commitment, proof.below, context + b"|below")


def _combine(group, commitments: Sequence, coefficients: Sequence[int]):
    """`prod C_i^{a_i}`, without paying a scalar multiplication for a 1.

    The all-ones case is not a corner: it is what reconciling a ledger against
    a book of record is, and there `point_pow(C, 1)` was costing a full scalar
    multiplication per position. Measured on 4,096 positions before and after:
    175 ms and 33 ms.
    """
    order = group.order
    aggregate = group.identity()
    for commitment, coefficient in zip(commitments, coefficients):
        coefficient %= order
        if coefficient == 1:
            aggregate = group.mul(aggregate, commitment)
        elif coefficient == order - 1:
            aggregate = group.mul(aggregate, group.neg(commitment))
        elif coefficient:
            aggregate = group.mul(aggregate, group.point_pow(commitment, coefficient))
    return aggregate


def verify_linear(key: Pedersen, commitments: Sequence, coefficients: Sequence[int],
                  constant: int, proof: OpeningProof, context: bytes = b"") -> bool:
    """Check sum(coeff_i * v_i) == constant across committed values.

    The relation holds exactly when the combined commitment, with the constant
    divided out, is a pure power of h, which is what the opening proof shows.
    """
    group = key.group
    aggregate = _combine(group, commitments, coefficients)
    # `key.commit(constant, 0)` rather than `group.base_pow(constant)`: they are
    # the same point for a base-valued key and they are not for one carrying an
    # asset tag, where the constant has to be divided out under the tag. The
    # difference is invisible until somebody reconciles a tagged ledger, and
    # then it is a wrong answer rather than an error.
    residual = group.mul(aggregate, group.neg(key.commit(constant % group.order, 0)))
    return verify_opening(key, residual, proof, context)


def prove_linear(key: Pedersen, blindings: Sequence[int], coefficients: Sequence[int],
                 context: bytes = b"", commitments: Sequence | None = None,
                 constant: int = 0) -> OpeningProof:
    group = key.group
    combined = sum(c * r for c, r in zip(coefficients, blindings)) % group.order
    aggregate = _combine(group, commitments or (), coefficients)
    residual = group.mul(aggregate, group.neg(key.commit(constant % group.order, 0)))
    return prove_opening(key, residual, 0, combined, context)


@dataclass(frozen=True)
class ProductProof:
    """c = a * b, on three Pedersen commitments, revealing none of them."""

    t_factor: Any
    t_product: Any
    z_b: int
    z_rb: int
    z_s: int


def prove_product(key: Pedersen, c_a, a: int, r_a: int, b: int, r_b: int,
                  r_c: int, context: bytes = b"") -> ProductProof:
    """Prove the committed product without opening any factor.

    The identity used is C_a^b = g^{ab} h^{r_a b}, so C_c / C_a^b is a pure power
    of h. Proving knowledge of one exponent b that opens C_b *and* relates C_c to
    C_a therefore pins the product.
    """
    group = key.group
    order = group.order
    c_b = key.commit(b, r_b)
    c_c = key.commit(a * b, r_c)
    s = (r_c - r_a * b) % order
    k_b, k_rb, k_s = (group.random_scalar() for _ in range(3))
    t_factor = key.commit(k_b, k_rb)
    t_product = group.mul(group.point_pow(c_a, k_b), group.point_pow(key.h, k_s))
    challenge = key._challenge(b"product", context, c_a, c_b, c_c, t_factor, t_product)
    return ProductProof(t_factor, t_product,
                        (k_b + challenge * b) % order,
                        (k_rb + challenge * r_b) % order,
                        (k_s + challenge * s) % order)


def verify_product(key: Pedersen, c_a, c_b, c_c, proof: ProductProof,
                   context: bytes = b"") -> bool:
    group = key.group
    # A proof of the wrong shape is a refusal and not an exception. The two
    # verifier flavours accept different leaf objects, and a caller handed the
    # other one has to be told "no" rather than have the process die --- the
    # difference matters because one of those is a denial of service.
    if not isinstance(proof, ProductProof):
        return False
    if not (group.is_valid(proof.t_factor) and group.is_valid(proof.t_product)):
        return False
    if any(not 0 <= v < group.order for v in (proof.z_b, proof.z_rb, proof.z_s)):
        return False
    challenge = key._challenge(b"product", context, c_a, c_b, c_c,
                               proof.t_factor, proof.t_product)
    left = key.commit(proof.z_b, proof.z_rb)
    right = group.mul(proof.t_factor, group.point_pow(c_b, challenge))
    if group.encode(left) != group.encode(right):
        return False
    left = group.mul(group.point_pow(c_a, proof.z_b), group.point_pow(key.h, proof.z_s))
    right = group.mul(proof.t_product, group.point_pow(c_c, challenge))
    return group.encode(left) == group.encode(right)


@dataclass(frozen=True)
class CrossGeneratorProof:
    """Two commitments under different value generators hide the same number."""

    t_first: Any
    t_second: Any
    z_value: int
    z_first: int
    z_second: int


def prove_same_value(key: Pedersen, first_generator, second_generator,
                     first_commitment, second_commitment, value: int,
                     first_blinding: int, second_blinding: int,
                     context: bytes = b"") -> CrossGeneratorProof:
    """Bridge a commitment under an asset tag to one under the base generator.

    Needed because the quorum issues an instruction before anyone has chosen a
    settlement tag, so the quantity is committed twice under generators that
    were picked independently. One shared response for the value ties them.
    """
    group = key.group
    order = group.order
    k_value = group.random_scalar()
    k_first = group.random_scalar()
    k_second = group.random_scalar()
    t_first = group.mul(group.point_pow(first_generator, k_value),
                        group.point_pow(key.h, k_first))
    t_second = group.mul(group.point_pow(second_generator, k_value),
                         group.point_pow(key.h, k_second))
    challenge = key._challenge(b"xgen", context, first_generator, second_generator,
                               first_commitment, second_commitment, t_first, t_second)
    return CrossGeneratorProof(
        t_first, t_second,
        (k_value + challenge * value) % order,
        (k_first + challenge * first_blinding) % order,
        (k_second + challenge * second_blinding) % order)


def verify_same_value(key: Pedersen, first_generator, second_generator,
                      first_commitment, second_commitment,
                      proof: CrossGeneratorProof, context: bytes = b"") -> bool:
    group = key.group
    order = group.order
    if not (group.is_valid(proof.t_first) and group.is_valid(proof.t_second)):
        return False
    if any(not 0 <= v < order
           for v in (proof.z_value, proof.z_first, proof.z_second)):
        return False
    challenge = key._challenge(b"xgen", context, first_generator, second_generator,
                               first_commitment, second_commitment,
                               proof.t_first, proof.t_second)
    for generator, commitment, z_blinding, t in (
            (first_generator, first_commitment, proof.z_first, proof.t_first),
            (second_generator, second_commitment, proof.z_second, proof.t_second)):
        left = group.mul(group.point_pow(generator, proof.z_value),
                         group.point_pow(key.h, z_blinding))
        right = group.mul(t, group.point_pow(commitment, challenge))
        if group.encode(left) != group.encode(right):
            return False
    return True
