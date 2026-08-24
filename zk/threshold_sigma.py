"""Sigma proofs produced jointly by the computing nodes, with no node holding the witness.

This is why sigma protocols rather than a general SNARK are the right tool for
the MPC nodes to prove their own computation. A sigma response is *linear* in the
witness:

    t = g^k h^rho          each node publishes t_i = g^{k_i} h^{rho_i}
    z = k + c * w          each node computes z_i = k_i + c * w_i

Both combine across nodes by Lagrange interpolation -- the first in the exponent,
the second in the scalar field -- so a quorum can assemble a proof that an
ordinary verifier accepts, while every individual node only ever touches shares.
A general-purpose SNARK has no such structure, which is exactly why collaborative
SNARK constructions need a full MPC over the proving algorithm.

The threshold is the one the rest of the design already assumes: any T+1 nodes
can assemble a proof, and any T+1 colluding nodes could reconstruct the witness.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .commit import OpeningProof, Pedersen
from .groups import DOMAIN, Group


def lagrange_at_zero(parties: Sequence[int], order: int) -> dict[int, int]:
    """Coefficients that reconstruct f(0) from f(parties)."""
    coefficients = {}
    for i in parties:
        numerator = 1
        denominator = 1
        for j in parties:
            if i == j:
                continue
            numerator = (numerator * (-j)) % order
            denominator = (denominator * (i - j)) % order
        coefficients[i] = (numerator * pow(denominator, -1, order)) % order
    return coefficients


@dataclass(frozen=True)
class ShareSet:
    """One secret, shared with its blinding, plus what is public about it.

    `coefficient_commitments` is the Pedersen VSS ladder: a commitment to each
    coefficient of both polynomials. It leaks nothing --- the constant term is
    the commitment that was already public --- and it is what makes every share
    publicly checkable, which is what attribution needs.
    """

    commitment: Any
    value_shares: Mapping[int, int]
    blinding_shares: Mapping[int, int]
    threshold: int
    coefficient_commitments: tuple = ()


def deal(key: Pedersen, value: int, blinding: int, parties: Sequence[int],
         threshold: int) -> ShareSet:
    group = key.group
    order = group.order
    value_poly = [value % order] + [group.random_scalar() for _ in range(threshold)]
    blind_poly = [blinding % order] + [group.random_scalar() for _ in range(threshold)]

    def evaluate(poly, x):
        return sum(c * pow(x, k, order) for k, c in enumerate(poly)) % order

    return ShareSet(
        commitment=key.commit(value, blinding),
        value_shares={p: evaluate(value_poly, p) for p in parties},
        blinding_shares={p: evaluate(blind_poly, p) for p in parties},
        threshold=threshold,
        coefficient_commitments=tuple(
            key.commit(value_poly[k], blind_poly[k]) for k in range(threshold + 1)),
    )


def share_commitment(key: Pedersen, coefficient_commitments: Sequence, party: int):
    """The commitment to one node's share, derived from public information only.

    A share is a polynomial evaluated at the party's index, so the commitment to
    it is the same evaluation carried out in the exponent over the published
    coefficient commitments. Nobody needs the share to compute this, which is the
    whole point: attribution that requires the witness can only be performed by
    someone who is not supposed to exist.
    """
    group = key.group
    accumulated = group.identity()
    for k, coefficient in enumerate(coefficient_commitments):
        accumulated = group.mul(
            accumulated, group.point_pow(coefficient, pow(party, k, group.order)))
    return accumulated


def verify_share(key: Pedersen, shares: ShareSet, party: int) -> bool:
    """A node accepts its own share only if it opens against the public ladder."""
    expected = share_commitment(key, shares.coefficient_commitments, party)
    actual = key.commit(shares.value_shares[party], shares.blinding_shares[party])
    return key.group.encode(actual) == key.group.encode(expected)


class JointNonce:
    """Randomness for a proof that no single node knows.

    Each node contributes one random polynomial and the shares are summed.

    **What that does and does not establish.** Summing means no node knows the
    result from its own contribution alone. It does not by itself stop a node
    that contributes *after* seeing the others: knowing their sum `K`, a node
    that wants the nonce to be `t` contributes `t - K`, and then it knows the
    nonce, and a known nonce gives up the witness through `z = k + c*w`. What
    rules that out is that at least one honest contribution is still unknown
    when a node fixes its own --- private dealing, or commit-then-open, or a
    distributed key generation. This class sums locally and models the *output*
    of such a protocol; it is not that protocol.

    An earlier note here said a node could only choose the result if it spoke
    last *and everyone else was corrupt*. The second half is wrong: speaking
    last and being able to see the others is enough, and honest contributions
    that are already public are no protection.
    """

    def __init__(self, key: Pedersen, parties: Sequence[int], threshold: int):
        group = key.group
        order = group.order
        self.parties = list(parties)
        self.k_shares = {p: 0 for p in parties}
        self.rho_shares = {p: 0 for p in parties}
        for _dealer in parties:
            k_poly = [group.random_scalar() for _ in range(threshold + 1)]
            r_poly = [group.random_scalar() for _ in range(threshold + 1)]
            for p in parties:
                self.k_shares[p] = (self.k_shares[p] + sum(
                    c * pow(p, i, order) for i, c in enumerate(k_poly))) % order
                self.rho_shares[p] = (self.rho_shares[p] + sum(
                    c * pow(p, i, order) for i, c in enumerate(r_poly))) % order


def node_commitment(key: Pedersen, nonce: JointNonce, party: int):
    """t_i = g^{k_i} h^{rho_i}, published by node i."""
    return key.commit(nonce.k_shares[party], nonce.rho_shares[party])


def combine_commitments(key: Pedersen, partials: Mapping[int, Any]) -> Any:
    """t = prod t_i^{lambda_i}: Lagrange interpolation carried out in the exponent."""
    group = key.group
    coefficients = lagrange_at_zero(sorted(partials), group.order)
    combined = group.identity()
    for party, partial in partials.items():
        combined = group.mul(combined, group.point_pow(partial, coefficients[party]))
    return combined


def node_response(shares: ShareSet, nonce: JointNonce, party: int, challenge: int,
                  order: int) -> tuple[int, int]:
    """z_i = k_i + c * w_i, computed by node i on its own shares alone."""
    return ((nonce.k_shares[party] + challenge * shares.value_shares[party]) % order,
            (nonce.rho_shares[party] + challenge * shares.blinding_shares[party]) % order)


def combine_responses(partials: Mapping[int, tuple[int, int]], order: int) -> tuple[int, int]:
    coefficients = lagrange_at_zero(sorted(partials), order)
    z_value = sum(coefficients[p] * partials[p][0] for p in partials) % order
    z_blinding = sum(coefficients[p] * partials[p][1] for p in partials) % order
    return z_value, z_blinding


def audit_partials(key: Pedersen, coefficient_commitments: Sequence,
                   quorum: Sequence[int],
                   partial_commitments: Mapping[int, Any],
                   partial_responses: Mapping[int, tuple[int, int]],
                   challenge: int) -> list[int]:
    """Name the nodes whose contribution does not match their own share.

    A node's response has to satisfy g^{z_i} h^{w_i} = t_i * C_i^c, where C_i is
    the commitment to that node's share. So a bad partial is attributable to one
    node rather than only visible as a proof that fails to verify --- but only if
    C_i is public.

    It used to be taken from the shares themselves, which made attribution an
    operation that required the witness. Nobody holds the witness; that is the
    property the whole construction exists to provide. So the check could not
    actually be run by the venue, by a verifier, or by the honest nodes, and a
    quorum that produced a failing proof could only report that somebody had
    cheated. Deriving C_i from the published coefficient commitments instead
    makes it something any observer can do.
    """
    group = key.group
    culprits = []
    for party in quorum:
        expected = share_commitment(key, coefficient_commitments, party)
        z_value, z_blinding = partial_responses[party]
        left = key.commit(z_value, z_blinding)
        right = group.mul(partial_commitments[party],
                          group.point_pow(expected, challenge))
        if group.encode(left) != group.encode(right):
            culprits.append(party)
    return culprits


def joint_prove_opening(key: Pedersen, shares: ShareSet, quorum: Sequence[int],
                        context: bytes = b"",
                        faulty: Mapping[int, tuple[int, int]] | None = None
                        ) -> tuple[OpeningProof, dict]:
    """Assemble one ordinary opening proof from a quorum of nodes.

    Returns the proof and a transcript recording what each node contributed, so
    a node that sends a malformed partial can be identified afterwards.
    """
    group = key.group
    nonce = JointNonce(key, quorum, shares.threshold)
    partial_commitments = {p: node_commitment(key, nonce, p) for p in quorum}
    commitment_t = combine_commitments(key, partial_commitments)
    challenge = key._challenge(b"open", context, shares.commitment, commitment_t)
    partial_responses = {p: node_response(shares, nonce, p, challenge, group.order)
                         for p in quorum}
    for party, replacement in (faulty or {}).items():
        partial_responses[party] = replacement
    z_value, z_blinding = combine_responses(partial_responses, group.order)
    culprits = audit_partials(key, shares.coefficient_commitments, quorum,
                              partial_commitments, partial_responses, challenge)
    transcript = {
        "quorum": list(quorum),
        "partial_commitments": {p: group.encode(v).hex() for p, v in partial_commitments.items()},
        "partial_responses": {p: list(v) for p, v in partial_responses.items()},
        "challenge": challenge,
        "bad_partials": culprits,
    }
    return OpeningProof(commitment_t, z_value, z_blinding), transcript
