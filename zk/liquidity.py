"""Joint ZK proof that at least ``k`` registered makers are eligible.

The exact count stays committed.  The proof establishes that every eligibility
wire is a bit, their committed sum is the count, and ``count - k`` lies in a
bounded non-negative range.  Verification also receives the eligibility
commitments from the quote proof, so a prover cannot count a different set of
makers.  Assembly uses only Shamir shares held by a quorum.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from .commit import Pedersen
from .threshold_gadgets import Shared, joint_prove_bit, verify_square_bit
from .threshold_range import (ValueShares, bits_for, joint_prove_range,
                              verify_threshold_range)

DOMAIN = b"QOMM:LIQUIDITY:v1"


def _share(group, value: int, parties: Sequence[int], threshold: int) -> dict[int, int]:
    coefficients = [value % group.order]
    coefficients += [group.random_scalar() for _ in range(threshold)]
    return {
        party: sum(coefficient * pow(party, power, group.order)
                   for power, coefficient in enumerate(coefficients)) % group.order
        for party in parties
    }


@dataclass(frozen=True)
class LiquidityShares:
    eligibility: tuple[Shared, ...]
    bit_crosses: tuple[Mapping[int, int], ...]
    excess: ValueShares
    threshold: int


@dataclass(frozen=True)
class LiquidityProof:
    n_slots: int
    minimum: int
    quote_statement_digest: bytes
    eligibility_commitments: tuple
    bit_proofs: tuple
    count_commitment: object
    excess_range: object
    range_bits: int


def deal_liquidity_shares(key: Pedersen, eligible: Sequence[int], *, minimum: int,
                          parties: Sequence[int], threshold: int) -> LiquidityShares:
    """Reference handover model; the live MPC emits these shared wires."""

    if not eligible or any(bit not in (0, 1) for bit in eligible):
        raise ValueError("eligibility must be a non-empty bit vector")
    if not 0 <= minimum <= len(eligible):
        raise ValueError("liquidity threshold is outside the maker population")
    group = key.group
    wires, crosses = [], []
    count_blinding = 0
    for bit in eligible:
        blinding = group.random_scalar()
        wires.append(Shared(
            key.commit(bit, blinding),
            _share(group, bit, parties, threshold),
            _share(group, blinding, parties, threshold)))
        crosses.append(_share(group, blinding * (1 - bit), parties, threshold))
        count_blinding = (count_blinding + blinding) % group.order
    count = sum(eligible)
    excess_value = count - minimum
    if excess_value < 0:
        # A false statement cannot be represented as an unsigned range proof.
        raise ValueError("fewer makers are eligible than the claimed threshold")
    count_commitment = group.identity()
    count_value_shares = {party: 0 for party in parties}
    count_blinding_shares = {party: 0 for party in parties}
    for wire in wires:
        count_commitment = group.mul(count_commitment, wire.commitment)
        for party in parties:
            count_value_shares[party] = (
                count_value_shares[party] + wire.value[party]) % group.order
            count_blinding_shares[party] = (
                count_blinding_shares[party] + wire.blinding[party]) % group.order
    excess_commitment = group.mul(count_commitment,
                                  group.point_pow(key.g, -minimum % group.order))
    excess_shared = Shared(
        excess_commitment,
        {party: (share - minimum) % group.order
         for party, share in count_value_shares.items()},
        count_blinding_shares)
    width = max(1, (len(eligible) - minimum).bit_length())
    excess = bits_for(key, excess_shared, excess_value, width, parties, threshold)
    return LiquidityShares(tuple(wires), tuple(crosses), excess, threshold)


def _context(quote_digest: bytes, n_slots: int, minimum: int) -> bytes:
    if len(quote_digest) != 32:
        raise ValueError("quote statement digest must be 32 bytes")
    return (DOMAIN + quote_digest + n_slots.to_bytes(4, "big")
            + minimum.to_bytes(4, "big"))


def joint_prove_liquidity(key: Pedersen, shares: LiquidityShares,
                          quorum: Sequence[int], *, minimum: int,
                          quote_statement_digest: bytes) -> LiquidityProof:
    n_slots = len(shares.eligibility)
    if not 0 <= minimum <= n_slots:
        raise ValueError("liquidity threshold is outside the maker population")
    context = _context(quote_statement_digest, n_slots, minimum)
    bit_proofs = tuple(
        joint_prove_bit(key, wire, cross, quorum, shares.threshold,
                        context + b":bit:" + index.to_bytes(4, "big"))
        for index, (wire, cross) in enumerate(
            zip(shares.eligibility, shares.bit_crosses, strict=True)))
    range_proof, _ = joint_prove_range(
        key, shares.excess, quorum, context + b":excess")
    count_commitment = key.group.identity()
    for wire in shares.eligibility:
        count_commitment = key.group.mul(count_commitment, wire.commitment)
    return LiquidityProof(
        n_slots, minimum, quote_statement_digest,
        tuple(wire.commitment for wire in shares.eligibility),
        bit_proofs, count_commitment, range_proof, shares.excess.width)


def verify_liquidity(key: Pedersen, proof: LiquidityProof, *,
                     expected_eligibility_commitments: Sequence,
                     quote_statement_digest: bytes) -> bool:
    try:
        context = _context(quote_statement_digest, proof.n_slots, proof.minimum)
    except ValueError:
        return False
    if proof.quote_statement_digest != quote_statement_digest:
        return False
    if not 0 <= proof.minimum <= proof.n_slots:
        return False
    if len(expected_eligibility_commitments) != proof.n_slots:
        return False
    if tuple(expected_eligibility_commitments) != proof.eligibility_commitments:
        return False
    if len(proof.bit_proofs) != proof.n_slots:
        return False
    for index, (commitment, bit_proof) in enumerate(
            zip(proof.eligibility_commitments, proof.bit_proofs, strict=True)):
        if not verify_square_bit(
                key, commitment, bit_proof,
                context + b":bit:" + index.to_bytes(4, "big")):
            return False
    aggregate = key.group.identity()
    for commitment in proof.eligibility_commitments:
        aggregate = key.group.mul(aggregate, commitment)
    if key.group.encode(aggregate) != key.group.encode(proof.count_commitment):
        return False
    excess_commitment = key.group.mul(
        proof.count_commitment,
        key.group.point_pow(key.g, -proof.minimum % key.group.order))
    if proof.range_bits != max(1, (proof.n_slots - proof.minimum).bit_length()):
        return False
    return verify_threshold_range(
        key, excess_commitment, proof.excess_range, context + b":excess")
