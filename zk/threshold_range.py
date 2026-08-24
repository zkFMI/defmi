"""Range proofs assembled from shares, with no node ever holding the value.

The quote proof is assembled jointly for one Pedersen opening. Its range proofs
are not, and the paper records that as an open problem. This is the construction
that closes it, and the reason it is a separate module rather than a flag on
`prove_range` is that one piece of the ordinary range proof genuinely cannot be
assembled and has to be replaced.

**What blocks the ordinary proof.** `prove_bit` is a Chaum--Pedersen
disjunction: the prover proves the real branch and *simulates* the other one,
and it picks which is which from the bit::

    real, fake = bit, 1 - bit
    t0, t1 = (t_real, t_fake) if bit == 0 else (t_fake, t_real)

A node holding a share of the bit cannot make that choice. No amount of Lagrange
interpolation recovers a branch decision, because the decision is not a field
element --- it is control flow.

**What replaces it.** Over a prime field, `b in {0,1}` is exactly `b^2 = b`, and
that is a multiplication, which `prove_product` already proves with responses
that *are* linear in the witness::

    z_b  = k_b  + c*b        z_rb = k_rb + c*r        z_s = k_s + c*s

Setting all three commitments of the product proof to the same `C_j` proves
`b*b = b` about the value inside it. So every bit proof becomes a product proof,
and the whole range proof becomes assemblable.

The cost of the substitution is that the proof object changes, so this module
carries its own verifier. That verifier is still ordinary --- no setup, no
trusted party, the same group --- but it is not byte-compatible with
`verify_range`, and pretending otherwise would be the useful-looking lie here.

**What the nodes have to hold.** Shares of each bit and its blinding, which is
what an MPC bit decomposition produces, and shares of the cross term
`s_j = r_j * (1 - b_j)`, which is one multiplication. `deal_bits` models what
the MPC would hand over. Nothing in the assembly ever sees a bit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .commit import (OpeningProof, Pedersen, ProductProof, verify_opening,
                     verify_product)
from .threshold_gadgets import (JointScalars, Shared, joint_prove_bit,
                                verify_square_bit)
from .threshold_sigma import (combine_commitments, combine_responses)


# --- what the nodes hold ----------------------------------------------------

@dataclass(frozen=True)
class BitShares:
    """One bit of the value, shared three ways.

    `cross` is `r * (1 - b)`, the exponent the product proof needs and the only
    one that is not already a share the decomposition produced. It is one
    multiplication in MPC, which is where it would come from.
    """

    commitment: Any
    bit: Mapping[int, int]
    blinding: Mapping[int, int]
    cross: Mapping[int, int]


@dataclass(frozen=True)
class ValueShares:
    """The value, its blinding, and its bits --- none of them in the clear."""

    commitment: Any
    value: Mapping[int, int]
    blinding: Mapping[int, int]
    bits: tuple[BitShares, ...]
    threshold: int

    @property
    def width(self) -> int:
        return len(self.bits)


@dataclass(frozen=True)
class ThresholdRangeProof:
    """Same shape as a `RangeProof`, with product proofs where the bit proofs were."""

    bit_commitments: tuple
    bit_proofs: tuple
    linkage: OpeningProof
    bits: int


# --- randomness no single node knows ----------------------------------------

# --- dealing, which is what the MPC would do --------------------------------

def _share(group, secret: int, parties: Sequence[int], threshold: int) -> dict[int, int]:
    order = group.order
    poly = [secret % order] + [group.random_scalar() for _ in range(threshold)]
    return {p: sum(c * pow(p, k, order) for k, c in enumerate(poly)) % order
            for p in parties}


def deal_bits(key: Pedersen, value: int, blinding: int, width: int,
              parties: Sequence[int], threshold: int) -> ValueShares:
    """Model of what an MPC bit decomposition hands the nodes.

    A dealer stands in for the protocol here. What matters for the construction
    is the *shape* of what the nodes end up holding --- degree-`threshold` shares
    of each bit, of its blinding, and of the cross term --- and a multiplication
    protocol emits exactly that, since it re-randomises down to degree `t` after
    the product. The rounds it costs are measured separately and are not modelled
    here; this module is about whether the proof can be assembled at all.
    """
    group = key.group
    if not 0 <= value < (1 << width):
        raise ValueError(f"value {value} outside [0, 2^{width})")
    order = group.order
    bit_blindings = [group.random_scalar() for _ in range(width)]
    bit_values = [(value >> j) & 1 for j in range(width)]
    bits = []
    for j in range(width):
        b, r = bit_values[j], bit_blindings[j]
        bits.append(BitShares(
            commitment=key.commit(b, r),
            bit=_share(group, b, parties, threshold),
            blinding=_share(group, r, parties, threshold),
            cross=_share(group, (r * (1 - b)) % order, parties, threshold),
        ))
    return ValueShares(
        commitment=key.commit(value, blinding),
        value=_share(group, value, parties, threshold),
        blinding=_share(group, blinding, parties, threshold),
        bits=tuple(bits), threshold=threshold)


# --- one bit, assembled -----------------------------------------------------

def _joint_bit(key: Pedersen, share: BitShares, quorum: Sequence[int],
               threshold: int, context: bytes) -> ProductProof:
    """`b * b = b` about `share.commitment`, from a quorum that never sees `b`."""
    return joint_prove_bit(
        key, Shared(share.commitment, share.bit, share.blinding),
        share.cross, quorum, threshold, context)


def bits_for(key: Pedersen, shared: Shared, value: int, width: int,
             parties: Sequence[int], threshold: int) -> "ValueShares":
    """Bit shares for a wire that is already shared.

    `deal_bits` starts from a cleartext value and shares everything. Inside a
    larger proof the value is already a `Shared` --- it came out of the circuit
    --- so only the bits are new, and the value and blinding shares have to be
    the ones the rest of the proof is using or the linkage will not close.

    `value` is what the wire actually holds. The dealer needs it to compute the
    bits; the assembly never does.
    """
    group = key.group
    if not 0 <= value < (1 << width):
        raise ValueError(f"value {value} outside [0, 2^{width})")
    order = group.order
    bits = []
    for j in range(width):
        b = (value >> j) & 1
        r = group.random_scalar()
        bits.append(BitShares(
            commitment=key.commit(b, r),
            bit=_share(group, b, parties, threshold),
            blinding=_share(group, r, parties, threshold),
            cross=_share(group, (r * (1 - b)) % order, parties, threshold),
        ))
    return ValueShares(commitment=shared.commitment, value=dict(shared.value),
                       blinding=dict(shared.blinding), bits=tuple(bits),
                       threshold=threshold)


# --- the whole proof --------------------------------------------------------

def joint_prove_range(key: Pedersen, shares: ValueShares, quorum: Sequence[int],
                      context: bytes = b"") -> tuple[ThresholdRangeProof, dict]:
    """Assemble a range proof from a quorum. No node holds the value or a bit."""
    group = key.group
    order = group.order
    width = shares.width

    bit_proofs = tuple(
        _joint_bit(key, shares.bits[j], quorum, shares.threshold,
                   context + b":bit:" + j.to_bytes(2, "big"))
        for j in range(width))
    bit_commitments = tuple(b.commitment for b in shares.bits)

    # The linkage is an opening of C / prod C_j^{2^j} to zero. Its value shares
    # are the value's minus the weighted bits' --- zero by construction, and zero
    # without anybody computing the value to check. Its blinding shares are the
    # same combination, which is linear, so `joint_prove_opening` takes it as is.
    aggregate = group.identity()
    for j, commitment in enumerate(bit_commitments):
        aggregate = group.mul(aggregate, group.point_pow(commitment, 1 << j))
    residual = group.mul(shares.commitment, group.neg(aggregate))

    residual_value = {p: (shares.value[p]
                          - sum((1 << j) * shares.bits[j].bit[p]
                                for j in range(width))) % order
                      for p in quorum}
    residual_blinding = {p: (shares.blinding[p]
                             - sum((1 << j) * shares.bits[j].blinding[p]
                                   for j in range(width))) % order
                         for p in quorum}

    from .threshold_sigma import JointNonce, node_commitment
    nonce = JointNonce(key, quorum, shares.threshold)
    partials = {p: node_commitment(key, nonce, p) for p in quorum}
    commitment_t = combine_commitments(key, partials)
    challenge = key._challenge(b"open", context + b":link", residual, commitment_t)
    answers = {p: ((nonce.k_shares[p] + challenge * residual_value[p]) % order,
                   (nonce.rho_shares[p] + challenge * residual_blinding[p]) % order)
               for p in quorum}
    z_value, z_blinding = combine_responses(answers, order)
    linkage = OpeningProof(commitment_t, z_value, z_blinding)

    proof = ThresholdRangeProof(bit_commitments, bit_proofs, linkage, width)
    transcript = {
        "quorum": list(quorum),
        "width": width,
        "no_node_holds_the_value": True,
        "bit_proof_kind": "square (b*b = b), because the disjunction cannot be shared",
    }
    return proof, transcript


def verify_threshold_range(key: Pedersen, commitment,
                           proof: ThresholdRangeProof, context: bytes = b"") -> bool:
    """Ordinary verification: no setup, no shares, no knowledge of the quorum."""
    group = key.group
    if not isinstance(proof, ThresholdRangeProof):
        return False
    if len(proof.bit_commitments) != proof.bits:
        return False
    if len(proof.bit_proofs) != proof.bits:
        return False
    for j, (bit_commitment, bit_proof) in enumerate(
            zip(proof.bit_commitments, proof.bit_proofs)):
        if not group.is_valid(bit_commitment):
            return False
        # b*b = b over a prime field is exactly b in {0,1}
        if not verify_square_bit(key, bit_commitment, bit_proof,
                                 context + b":bit:" + j.to_bytes(2, "big")):
            return False
    aggregate = group.identity()
    for j, bit_commitment in enumerate(proof.bit_commitments):
        aggregate = group.mul(aggregate, group.point_pow(bit_commitment, 1 << j))
    residual = group.mul(commitment, group.neg(aggregate))
    return verify_opening(key, residual, proof.linkage, context + b":link")
