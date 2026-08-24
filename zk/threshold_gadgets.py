"""Scalars that exist only as shares, and the sigma proofs that go with them.

`threshold_sigma` assembles one opening proof and `threshold_range` assembles a
range proof. What the quote proof needs beyond those is products --- most of its
steps are `a * b = c` on committed values --- and a way to carry the linear
combinations between them without any node ever holding a wire.

The `Shared` type is that carrier. A Pedersen commitment is linear in both
exponents, and Shamir shares add, subtract and scale, so every step the quote
proof calls "linear, free" stays free here: the shares move and the commitment
moves with them, and nothing is opened. Adding a public constant works because
the Lagrange coefficients at zero sum to one, so adding it to every share adds
it once to the secret.

Products are the exception and cannot be done this way --- a product of two
degree-`t` sharings has degree `2t` and needs re-randomising back down. That is
a multiplication protocol, and it is what the MPC already runs. `Shared`
therefore takes products as given: the dealer in `threshold_quote` models what
the protocol emits, and the proof machinery here only has to prove that what it
emitted is right.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .commit import Pedersen, ProductProof
from .threshold_sigma import combine_commitments, lagrange_at_zero


@dataclass(frozen=True)
class Shared:
    """One scalar: its public commitment and the shares that open it.

    Nobody holds the scalar. `value` and `blinding` are per-party shares of a
    degree-`t` polynomial, and the commitment is the one that was published for
    it --- not derived from the shares, because deriving it would need them all
    in one place, which is the thing being avoided.
    """

    commitment: Any
    value: Mapping[int, int]
    blinding: Mapping[int, int]

    @property
    def parties(self) -> list[int]:
        return sorted(self.value)


def add(key: Pedersen, a: Shared, b: Shared) -> Shared:
    order = key.group.order
    return Shared(key.group.mul(a.commitment, b.commitment),
                  {p: (a.value[p] + b.value[p]) % order for p in a.value},
                  {p: (a.blinding[p] + b.blinding[p]) % order for p in a.blinding})


def sub(key: Pedersen, a: Shared, b: Shared) -> Shared:
    order = key.group.order
    return Shared(key.group.mul(a.commitment, key.group.neg(b.commitment)),
                  {p: (a.value[p] - b.value[p]) % order for p in a.value},
                  {p: (a.blinding[p] - b.blinding[p]) % order for p in a.blinding})


def scale(key: Pedersen, a: Shared, factor: int) -> Shared:
    order = key.group.order
    factor %= order
    return Shared(key.group.point_pow(a.commitment, factor),
                  {p: (a.value[p] * factor) % order for p in a.value},
                  {p: (a.blinding[p] * factor) % order for p in a.blinding})


def shift(key: Pedersen, a: Shared, constant: int) -> Shared:
    """Add a public constant. Every share moves by it, and so does the secret,
    because the Lagrange coefficients at zero sum to one."""
    order = key.group.order
    return Shared(key.group.mul(a.commitment, key.commit(constant % order, 0)),
                  {p: (a.value[p] + constant) % order for p in a.value},
                  dict(a.blinding))


def negate(key: Pedersen, a: Shared) -> Shared:
    return scale(key, a, key.group.order - 1)


def commitment_from_shares(key: Pedersen, value: Mapping[int, int],
                           blinding: Mapping[int, int],
                           quorum: Sequence[int]) -> Any:
    """`C = g^v h^r` computed by a quorum that holds only shares of `v` and `r`.

    Each node publishes `g^{v_i} h^{r_i}` and the combination is Lagrange in the
    exponent, so the commitment to a wire is available without the wire. This is
    what lets a derived wire --- a product the circuit computed, a key packed
    from one --- carry a commitment at all: reconstructing the value to commit to
    it would undo the whole arrangement.
    """
    partials = {p: key.commit(value[p], blinding[p]) for p in quorum}
    return combine_commitments(key, partials)


class JointScalars:
    """Shares of `count` random scalars, one polynomial per node.

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

    def __init__(self, key: Pedersen, parties: Sequence[int], threshold: int,
                 count: int):
        group = key.group
        order = group.order
        self.parties = list(parties)
        self.shares: list[dict[int, int]] = [{p: 0 for p in parties}
                                             for _ in range(count)]
        for _dealer in parties:
            for slot in range(count):
                poly = [group.random_scalar() for _ in range(threshold + 1)]
                for p in parties:
                    self.shares[slot][p] = (self.shares[slot][p] + sum(
                        c * pow(p, i, order) for i, c in enumerate(poly))) % order


class CommittedContributions:
    """Contributions fixed before any of them is seen.

    `JointScalars` sums one polynomial per node, which gives a nonce no node
    knows *from its own contribution* --- and leaves a node that contributes
    after seeing the others able to choose the result outright: knowing their
    sum `K`, contribute `t - K` and the nonce is `t`, and a known nonce hands
    over the witness through `z = k + c*w`.

    This is the protocol that rules it out. Every node publishes a hiding
    commitment to its contribution first; only when all of them are in does
    anyone open. A node that waits has nothing to wait for, because what it
    would need to see is still sealed, and a node that opens to something other
    than what it committed is named by `opened_by`.

    It is deliberately the plainest construction that works. The commitment is
    the same Pedersen already in use, so there is nothing new to trust.
    """

    def __init__(self, key: Pedersen, parties: Sequence[int], threshold: int,
                 count: int):
        group = key.group
        order = group.order
        self.key = key
        self.parties = list(parties)
        self.threshold = threshold
        self.count = count
        self._polynomials: dict[int, list[list[int]]] = {}
        self._masks: dict[int, list[int]] = {}
        self.sealed: dict[int, list] = {}
        for dealer in self.parties:
            polys = [[group.random_scalar() for _ in range(threshold + 1)]
                     for _ in range(count)]
            masks = [group.random_scalar() for _ in range(count)]
            self._polynomials[dealer] = polys
            self._masks[dealer] = masks
            # the constant terms are what a late node would want; seal those
            self.sealed[dealer] = [key.commit(polys[slot][0], masks[slot])
                                   for slot in range(count)]

    def open(self) -> list[dict[int, int]]:
        """Everyone opens, and the shares are the sum. Sealed first, always."""
        order = self.key.group.order
        shares = [{p: 0 for p in self.parties} for _ in range(self.count)]
        for dealer in self.parties:
            for slot in range(self.count):
                poly = self._polynomials[dealer][slot]
                for p in self.parties:
                    shares[slot][p] = (shares[slot][p] + sum(
                        c * pow(p, i, order) for i, c in enumerate(poly))) % order
        return shares

    def opened_by(self, dealer: int) -> list[tuple[int, int]]:
        """What `dealer` has to reveal for its seal to be checkable."""
        return [(self._polynomials[dealer][slot][0], self._masks[dealer][slot])
                for slot in range(self.count)]

    def check_opening(self, dealer: int,
                      revealed: Sequence[tuple[int, int]]) -> bool:
        """Whether a node opened to what it sealed."""
        group = self.key.group
        if len(revealed) != self.count:
            return False
        return all(
            group.encode(self.key.commit(value, mask))
            == group.encode(self.sealed[dealer][slot])
            for slot, (value, mask) in enumerate(revealed))


def joint_prove_product(key: Pedersen, c_a: Any, b: Shared, product: Shared,
                        cross: Mapping[int, int], quorum: Sequence[int],
                        threshold: int, context: bytes = b"",
                        transcript: list | None = None) -> ProductProof:
    """`product = a * b`, assembled by a quorum that holds only shares.

    `c_a` is the first factor's commitment and is public; the prover proves
    knowledge of the *second* factor and of the cross term, which is what pins
    the product. So only `b` needs to be shared here, and `a` never appears --- a
    node proving this does not need a share of it.

    Mirrors `prove_product`, whose three responses are each `nonce + c * witness`
    and therefore interpolate. The two first-move points are a node's own share
    in an exponent over a public base, so they interpolate in the exponent.

    `cross` is shares of `s = r_product - r_a * b`, the one witness that is a
    product of secrets rather than a share the protocol already holds. It is one
    multiplication, which is where it comes from.
    """
    group = key.group
    order = group.order
    nonce = JointScalars(key, quorum, threshold, 3)
    k_b, k_rb, k_s = nonce.shares

    factor_parts = {p: key.commit(k_b[p], k_rb[p]) for p in quorum}
    product_parts = {p: group.mul(group.point_pow(c_a, k_b[p]),
                                  group.point_pow(key.h, k_s[p])) for p in quorum}
    t_factor = combine_commitments(key, factor_parts)
    t_product = combine_commitments(key, product_parts)

    challenge = key._challenge(b"product", context, c_a, b.commitment,
                               product.commitment, t_factor, t_product)

    answers = {p: ((k_b[p] + challenge * b.value[p]) % order,
                   (k_rb[p] + challenge * b.blinding[p]) % order,
                   (k_s[p] + challenge * cross[p]) % order)
               for p in quorum}
    coefficients = lagrange_at_zero(sorted(answers), order)
    z_b, z_rb, z_s = (
        sum(coefficients[p] * answers[p][slot] for p in answers) % order
        for slot in range(3))
    if transcript is not None:
        # Kept so a node that sends a partial not matching its own share can be
        # named, rather than only showing up as a proof that does not verify.
        # `audit_product_partials` is the check; this is what it needs.
        transcript.append({
            "context": context,
            "c_a": c_a,
            "quorum": list(quorum),
            "challenge": challenge,
            "factor_parts": dict(factor_parts),
            "product_parts": dict(product_parts),
            "answers": {p: tuple(v) for p, v in answers.items()},
        })
    return ProductProof(t_factor, t_product, z_b, z_rb, z_s)


def joint_prove_bit(key: Pedersen, bit: Shared, cross: Mapping[int, int],
                    quorum: Sequence[int], threshold: int,
                    context: bytes = b"",
                    transcript: list | None = None) -> ProductProof:
    """`b * b = b`, which over a prime field is exactly `b in {0, 1}`.

    The disjunction `prove_bit` uses cannot be assembled --- it picks which
    branch to simulate *from* the bit, and that is control flow, not a field
    element. The square is the same statement and is a multiplication, so it
    assembles. `cross` is shares of `r * (1 - b)`.
    """
    return joint_prove_product(key, bit.commitment, bit, bit, cross,
                               quorum, threshold, context, transcript)


def verify_square_bit(key: Pedersen, commitment: Any, proof: ProductProof,
                      context: bytes = b"") -> bool:
    """The check that replaces `verify_bit` on an assembled proof."""
    from .commit import verify_product
    return verify_product(key, commitment, commitment, commitment, proof, context)


def audit_product_partials(key: Pedersen, entry: Mapping[str, Any],
                           share_commitments: Mapping[int, Any],
                           cross_commitments: Mapping[int, Any]) -> list[int]:
    """Name the nodes whose partial does not match the shares they published.

    `threshold_sigma.audit_partials` does this for the opening assembly and the
    product assembly had no equivalent, so a bad partial broke the proof and
    could not be pinned on anyone. Everything needed is already published: a
    node's contribution has to satisfy

        Com(z_b_i, z_rb_i) = t_factor_i * C_i^c
        c_a^{z_b_i} h^{z_s_i} = t_product_i * D_i^c

    where `C_i` is the commitment to that node's share of the second factor and
    `D_i` the commitment to its share of the cross term --- both derivable from
    the published coefficient ladders, so a verifier runs this without holding a
    single share.
    """
    group = key.group
    challenge = entry["challenge"]
    c_a = entry.get("c_a")
    culprits = []
    for party in entry["quorum"]:
        z_b, z_rb, z_s = entry["answers"][party]
        left = key.commit(z_b, z_rb)
        right = group.mul(entry["factor_parts"][party],
                          group.point_pow(share_commitments[party], challenge))
        if group.encode(left) != group.encode(right):
            culprits.append(party)
            continue
        if c_a is None:
            continue
        left = group.mul(group.point_pow(c_a, z_b),
                         group.point_pow(key.h, z_s))
        right = group.mul(entry["product_parts"][party],
                          group.point_pow(cross_commitments[party], challenge))
        if group.encode(left) != group.encode(right):
            culprits.append(party)
    return culprits
