"""The values the circuit consumed are the values that were committed.

`policy_audit` proves the shares the nodes hold open to the committed policy,
and says plainly what it does not reach: those are not the shares MP-SPDZ
consumes, because MP-SPDZ works over its own prime field. It names two ways to
close that --- run the computation over the commitment field, or link the two
with a commit-and-prove argument. This is the second one.

Running over the commitment field costs 2.0 to 2.5 times the wall clock and
seven to fourteen times the traffic, on every quote, forever
(`artifacts/matched_field.json`). This costs one opening.

The check is one random linear combination. The dealer has already published a
commitment per input. **The coefficients are derived from a challenge drawn
after the circuit has read its inputs**, not from the commitments alone --- the
first version derived them from the commitments, which are published at dealing
time, so a node saw them before it fed the engine and could pick an error in
their null space: feed `x_1 + c_2 k` and `x_2 - c_1 k` and the combination
vanishes identically. That is `artifacts/coefficient_timing_flaw.json`, and it
was found by writing the proof rather than by any of the tests, all of which
substituted a single input --- where the equation does force `e = 0`.

With the challenge drawn afterwards, the circuit computes

    s = sum_j c_j v_j + r

for a mask r the dealer also committed to, and opens s. Pedersen commitments are
additively homomorphic, so the same coefficients combine the commitments into one
that s must open. A node that feeds the circuit v_j + e_j instead of v_j shifts s by
sum_j c_j e_j, and for that to vanish the node would have to have chosen e
knowing coefficients that did not exist yet --- so it passes with probability
about 2^-CHALLENGE_BITS.

Two things this rests on, both checked rather than assumed.

**The fields must not both reduce.** The whole argument is that the same integer
appears on both sides, so the opened value has to stay below both the MPC prime
and the group order.

**The mask is not optional.** Without it each quote opens one linear equation in
the policy, and enough quotes with fresh coefficients solve for it.

**And those two together are what this costs, which is more than it first
looks.** The opening at 31-bit values, 40-bit coefficients and 166 inputs is 120
bits, which fits a 127-bit prime with seven bits to spare --- but the *mask* is
119 bits of that, and the mask is an input like any other, so it has to be dealt
to the nodes the way `qomm_transport.roles.split` deals everything: additively
over the integers, with `SLACK_BITS` of statistical room per share. That spends
the forty bits twice, once to hide the combination and once to hide each share,
and seven shares of a 119-bit value need **164 bits of field**. The 127-bit
prime does not hold it at any coefficient width --- not even at three bits, where
the check would be worthless anyway.

So the check does not run in the field it was proposed to save. It needs about
164 bits, against 253 for the group order, and at 253 the same widening also
makes `threshold_sigma` assemble correctly. **Whether it is worth widening to 164
rather than 253 is a real question and not an obvious one**, which is why
`check_width` takes the sharing into account and refuses rather than letting a
configuration through that would wrap.

What this does *not* do: it says the inputs were the committed ones, not that the
computation on them was right. That is what the malicious protocol is for, and
the two are complementary rather than alternatives.
"""

from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass
from typing import Any, Sequence

from .commit import Pedersen
from .groups import DOMAIN, Group
from .scheme import CommitmentScheme, PedersenScheme

CHALLENGE_BITS = 40
STATISTICAL_BITS = 40

# What fits a 127-bit prime, which is where the check has to run if the field is
# not being widened for anything else. The budget there is
# `challenge_bits + statistical_bits <= 41`, so soundness is bought back by
# repetition instead of by wider coefficients --- four independent combinations
# at ten bits each are 2^-40, the same figure `roles.SLACK_BITS` uses, and they
# open in one round because they do not depend on each other.
#
# The hiding cannot be bought back the same way, and `narrow_tradeoff` is where
# that is shown rather than asserted. Spending the budget on the gap leaves
# narrower coefficients, narrower coefficients need more repetitions, and
# repetitions dilute the gap again --- so the curve has a peak, at about
# **2^-34** near two to four coefficient bits. The stack's usual 2^-40 is not
# reachable at 127 bits at any point on it. That is the honest cost of running
# the check in the narrow field.
NARROW_CHALLENGE_BITS = 6
NARROW_STATISTICAL_BITS = 35
NARROW_REPEATS = 7


class WidthError(ValueError):
    """Raised when the opening would reduce in one of the two fields."""


def narrow_tradeoff(n_inputs: int, value_bits: int, field_bits: int = 127,
                    soundness_bits: int = 40, n_nodes: int = 7,
                    share_slack: int = 40) -> list[dict]:
    """Every coefficient width the narrow field allows, and what it costs.

    Soundness per round is at most `1 / (2^c - 1)`, so reaching a target takes
    `ceil(target / log2(2^c - 1))` rounds; repeating also dilutes the hiding by
    the number of rounds. The point of tabulating it is that "2^-40 hiding is
    not reachable at 127 bits" is false --- it is reachable, and what it costs
    is openings.
    """
    out = []
    for challenge_bits in range(2, 41):
        gap = field_bits - 1 - value_bits - max(0, (n_inputs - 1).bit_length()) \
            - share_slack - max(0, (n_nodes - 1).bit_length()) - 2 - challenge_bits
        if gap < 1:
            break
        per_round = math.log2((1 << challenge_bits) - 1)
        repeats = math.ceil(soundness_bits / per_round)
        out.append({"challenge_bits": challenge_bits, "statistical_bits": gap,
                    "repeats": repeats,
                    "soundness_bits": round(repeats * per_round, 1),
                    "hiding_bits": round(gap - math.log2(repeats), 1),
                    "openings": repeats, "masks_dealt": repeats})
    return out


def opening_bits(n_inputs: int, value_bits: int,
                 challenge_bits: int = CHALLENGE_BITS,
                 statistical_bits: int = STATISTICAL_BITS) -> int:
    """How wide the opened value can get, before any modulus is applied."""
    if n_inputs < 1:
        raise ValueError("an input check over no inputs checks nothing")
    combination = value_bits + challenge_bits + max(0, (n_inputs - 1).bit_length())
    return combination + statistical_bits + 1          # mask, and the carry


def mask_bits(n_inputs: int, value_bits: int,
              challenge_bits: int = CHALLENGE_BITS,
              statistical_bits: int = STATISTICAL_BITS) -> int:
    """How wide the mask has to be to hide the combination it is added to."""
    combination = value_bits + challenge_bits + max(0, (n_inputs - 1).bit_length())
    return combination + statistical_bits


def field_bits_needed(n_inputs: int, value_bits: int, n_nodes: int = 7,
                      challenge_bits: int = CHALLENGE_BITS,
                      statistical_bits: int = STATISTICAL_BITS,
                      share_slack: int = 40) -> int:
    """The field the whole check needs, mask and its shares included.

    The opening is the small half. The mask is an input like any other, so it is
    dealt additively over the integers with `share_slack` bits of room per share,
    and that is what sets the floor.
    """
    mask = mask_bits(n_inputs, value_bits, challenge_bits, statistical_bits)
    return mask + share_slack + max(0, (n_nodes - 1).bit_length()) + 2


def check_width(n_inputs: int, value_bits: int, mpc_prime_bits: int,
                group_order_bits: int, challenge_bits: int = CHALLENGE_BITS,
                statistical_bits: int = STATISTICAL_BITS, n_nodes: int = 7,
                share_slack: int = 40) -> int:
    """Refuse a configuration that would wrap in either field.

    Returns the field width the configuration needs, so a caller can record it.
    Counting only the opening --- which the first version of this did --- says a
    127-bit prime is enough, and it is not: the mask has to be shared too.
    """
    opening = opening_bits(n_inputs, value_bits, challenge_bits, statistical_bits)
    needed = field_bits_needed(n_inputs, value_bits, n_nodes, challenge_bits,
                               statistical_bits, share_slack)
    narrower = min(mpc_prime_bits, group_order_bits)
    if needed >= narrower:
        raise WidthError(
            f"{n_inputs} inputs of {value_bits} bits with {challenge_bits}-bit "
            f"coefficients open to {opening} bits, which fits --- but the "
            f"{mask_bits(n_inputs, value_bits, challenge_bits, statistical_bits)}"
            f"-bit mask has to be dealt to {n_nodes} nodes with {share_slack} "
            f"bits of slack per share, and that needs {needed} bits against the "
            f"narrower of the MPC prime ({mpc_prime_bits}) and the group order "
            f"({group_order_bits}). The forty bits are spent twice, once on the "
            f"combination and once on each share. Widen the field, or say in the "
            f"artifact which of the two hidings was given up.")
    return needed


def as_scheme(key) -> CommitmentScheme:
    """Accept either a commitment scheme or the Pedersen key this used to take."""
    return key if isinstance(key, CommitmentScheme) else PedersenScheme(key)


def coefficients(scheme, commitments: Sequence[Any], mask_commitment: Any,
                 context: bytes, challenge: int | None = None,
                 challenge_bits: int = CHALLENGE_BITS,
                 round_index: int = 0) -> list[int]:
    """Public coefficients, from the commitments AND a post-input challenge.

    `challenge` is a value opened once every input has been read --- in
    deployment, one random opening inside the circuit. Without it the
    coefficients exist before the node fixes its input, and a node that can see
    them chooses an error in their null space. There is no default, because a
    caller that forgets is not slightly weaker; it has no check at all.
    """
    if challenge is None:
        raise ValueError(
            "the coefficients need a challenge drawn AFTER the inputs are "
            "fixed. Deriving them from the commitments alone lets a node that "
            "has seen them feed x_1 + c_2*k and x_2 - c_1*k, which cancels "
            "identically --- see artifacts/coefficient_timing_flaw.json")
    scheme = as_scheme(scheme)
    seed = hashlib.sha512(DOMAIN + b":input-check:v1")
    seed.update(len(context).to_bytes(4, "big"))
    seed.update(context)
    seed.update(len(commitments).to_bytes(4, "big"))
    for commitment in commitments:
        encoded = scheme.encode(commitment)
        seed.update(len(encoded).to_bytes(4, "big"))
        seed.update(encoded)
    encoded = scheme.encode(mask_commitment)
    seed.update(len(encoded).to_bytes(4, "big"))
    seed.update(encoded)
    seed.update(round_index.to_bytes(4, "big"))
    seed.update(int(challenge).to_bytes(32, "big", signed=False))
    root = seed.digest()

    out, span = [], 1 << challenge_bits
    for index in range(len(commitments)):
        digest = hashlib.sha512(root + index.to_bytes(4, "big")).digest()
        # a coefficient of zero would leave that input unchecked
        out.append(1 + int.from_bytes(digest, "big") % (span - 1))
    return out


@dataclass(frozen=True)
class InputCheck:
    """What is published so anyone can check the inputs were the committed ones.

    One entry per repetition. They are independent, so they open together in one
    round, and their soundness multiplies.
    """

    commitments: list
    mask_commitments: list
    openings: list
    opening_blindings: list
    challenge_bits: int = CHALLENGE_BITS

    def soundness_bits(self) -> int:
        return self.challenge_bits * len(self.openings)

    @property
    def repeats(self) -> int:
        return len(self.openings)


def sample_mask(n_inputs: int, value_bits: int,
                challenge_bits: int = CHALLENGE_BITS,
                statistical_bits: int = STATISTICAL_BITS, rng=None) -> int:
    """A mask wide enough that the opening hides the combination."""
    combination = value_bits + challenge_bits + max(0, (n_inputs - 1).bit_length())
    rng = rng or secrets.SystemRandom()
    return rng.randrange(1 << (combination + statistical_bits))


def build(key, values: Sequence[int], blindings: Sequence[int],
          context: bytes, challenge: int | None = None,
          challenge_bits: int = CHALLENGE_BITS,
          statistical_bits: int = STATISTICAL_BITS, repeats: int = 1,
          value_bits: int = 32, masks: Sequence[int] | None = None,
          mask_blindings: Sequence[int] | None = None) -> InputCheck:
    """The dealer's side: commit, derive, combine, open.

    In deployment the circuit computes the combination from shares --- public
    coefficient times secret share is local, so it costs no communication --- and
    the opening is the one round this check adds. Here the values are in hand,
    which is what makes the test able to substitute one.
    """
    scheme = as_scheme(key)
    if len(values) != len(blindings):
        raise ValueError("every value needs its blinding")
    if repeats < 1:
        raise ValueError("a check with no repetitions checks nothing")
    masks = list(masks) if masks is not None else [
        sample_mask(len(values), value_bits, challenge_bits, statistical_bits)
        for _ in range(repeats)]
    mask_blindings = list(mask_blindings) if mask_blindings is not None else [
        scheme.random_blinding() for _ in range(repeats)]

    commitments = [scheme.commit(v, r) for v, r in zip(values, blindings)]
    mask_commitments = [scheme.commit(m, b) for m, b in zip(masks, mask_blindings)]

    openings, opening_blindings = [], []
    for index in range(repeats):
        c = coefficients(scheme, commitments, mask_commitments[index], context,
                         challenge, challenge_bits, round_index=index)
        openings.append(sum(cj * v for cj, v in zip(c, values)) + masks[index])
        opening_blindings.append(
            sum(cj * r for cj, r in zip(c, blindings)) + mask_blindings[index])
    return InputCheck(commitments, mask_commitments, openings, opening_blindings,
                      challenge_bits)


def verify(key, check: InputCheck, context: bytes,
           challenge: int | None = None) -> tuple[bool, str]:
    """Anyone's side: rederive the coefficients and combine the commitments."""
    scheme = as_scheme(key)
    if not check.commitments:
        return False, "the check covers no inputs"
    for index in range(check.repeats):
        c = coefficients(scheme, check.commitments, check.mask_commitments[index],
                         context, challenge, check.challenge_bits,
                         round_index=index)
        combined = check.mask_commitments[index]
        for coefficient, commitment in zip(c, check.commitments):
            combined = scheme.add(combined, scheme.scale(commitment, coefficient))
        if not scheme.equal(scheme.commit(check.openings[index],
                                          check.opening_blindings[index]),
                            combined):
            return False, (f"combination {index} is not what the committed inputs "
                           f"combine to: an input the circuit used was not the "
                           f"one that was committed")
    return True, "ok"


# --- naming the party, not just detecting the substitution -----------------
#
# Everything above proves that *an* input the circuit used was not the one that
# was committed. It does not say which node did it, and
# `ACCOUNTABILITY.md` is about how much difference that makes: detection is the
# first of five rungs and a verdict is the fourth.
#
# The step from one to the other is smaller than it looks, because **the dealer
# already publishes what it needs**. `qomm_transport.roles.Dealing` carries a
# commitment to every share --- that is what makes `check_share` possible for a
# node and `adds_up` possible for anyone --- and those are exactly the
# commitments this combines. The marginal cost is the openings.
#
# Today the circuit opens one combination over the reconstructed values:
#
#     s = sum_j c_j v_j + m          where v_j = sum_p x_{p,j}
#
# Instead open one per party, over that party's own inputs:
#
#     s_p = sum_j c_j x_{p,j} + m_p
#
# and check each against `sum_j c_j C_{p,j} + C_{m_p}`. A party whose check
# fails is named, by anyone, from published data. `sum_p s_p` is the old check
# with the old mask, so this is strictly stronger and not an alternative.
#
# The soundness argument is unchanged and applies per party: the coefficients
# come from the commitments, so a node has to choose its error before it can see
# the coefficient that would cancel it.
#
# **This names. It does not prevent, and it does not repair.** By the time the
# opening is checked the circuit has already computed on the wrong input. That
# is rung four and not rung five.


@dataclass(frozen=True)
class PerPartyCheck:
    """One opening per party, so a failing check has a name attached."""

    share_commitments: list           # [party][value]
    mask_commitments: list            # one per party
    openings: list                    # one per party
    opening_blindings: list
    challenge_bits: int = CHALLENGE_BITS

    @property
    def n_parties(self) -> int:
        return len(self.openings)

    @property
    def n_values(self) -> int:
        return len(self.share_commitments[0]) if self.share_commitments else 0

    def soundness_bits(self) -> int:
        return self.challenge_bits


def per_party_field_bits(n_inputs: int, value_bits: int, n_nodes: int = 7,
                         challenge_bits: int = CHALLENGE_BITS,
                         statistical_bits: int = STATISTICAL_BITS,
                         share_slack: int = 40) -> int:
    """What the per-party check needs from the field.

    Wider than the aggregate check in one place and narrower in another, and the
    second wins. Party `p` combines *shares*, which are `value_bits +
    share_slack` wide rather than `value_bits`, so the combination is wider. But
    the mask is that party's own input and is **not dealt across nodes**, so it
    does not pay the `share_slack + log2(n_nodes)` that the aggregate check's
    mask pays --- and that is the term which forced 164 bits.
    """
    share_bits = value_bits + share_slack
    combination = share_bits + challenge_bits + max(0, (n_inputs - 1).bit_length())
    return combination + statistical_bits + 1


def powers(challenge: int, count: int, modulus: int) -> list[int]:
    """`rho, rho^2, ... rho^count` mod p --- what the circuit multiplies by.

    Powers rather than independent hashes because the circuit has to compute
    them too, and a running product on a public field element is free while a
    hash is not. The bound follows from the shape: `sum_k rho^k e_k + e_m = 0`
    is a polynomial of degree `count` in `rho`, so a fixed non-zero error
    survives with probability at most `count / p` --- about `2^-245` at 166
    values and a 253-bit field, against `2^-42` for the seven narrow
    repetitions the integer version needed.
    """
    if challenge is None:
        raise ValueError(
            "the coefficients need a challenge drawn AFTER the inputs are "
            "fixed --- see artifacts/coefficient_timing_flaw.json")
    out, c = [], 1
    for _ in range(count):
        c = (c * challenge) % modulus
        out.append(c)
    return out


def per_party_coefficients(scheme, share_commitments, mask_commitments,
                           context: bytes, challenge: int | None = None,
                           challenge_bits: int = CHALLENGE_BITS) -> list[int]:
    """Every published commitment, in a fixed order, plus the post-input challenge.

    See `coefficients` for why the challenge is not optional.
    """
    if challenge is None:
        raise ValueError(
            "the coefficients need a challenge drawn AFTER the inputs are "
            "fixed --- see artifacts/coefficient_timing_flaw.json")
    scheme = as_scheme(scheme)
    seed = hashlib.sha512(DOMAIN + b":per-party-check:v1")
    seed.update(len(context).to_bytes(4, "big"))
    seed.update(context)
    seed.update(len(share_commitments).to_bytes(4, "big"))
    for row in share_commitments:
        seed.update(len(row).to_bytes(4, "big"))
        for commitment in row:
            encoded = scheme.encode(commitment)
            seed.update(len(encoded).to_bytes(4, "big"))
            seed.update(encoded)
    for commitment in mask_commitments:
        encoded = scheme.encode(commitment)
        seed.update(len(encoded).to_bytes(4, "big"))
        seed.update(encoded)
    seed.update(int(challenge).to_bytes(32, "big", signed=False))
    root = seed.digest()

    n_values = len(share_commitments[0]) if share_commitments else 0
    out, span = [], 1 << challenge_bits
    for index in range(n_values):
        digest = hashlib.sha512(root + index.to_bytes(4, "big")).digest()
        out.append(1 + int.from_bytes(digest, "big") % (span - 1))
    return out


def build_per_party(key, shares, blindings, context: bytes,
                    challenge: int | None = None,
                    challenge_bits: int = CHALLENGE_BITS,
                    statistical_bits: int = STATISTICAL_BITS,
                    share_bits: int = 71, masks=None,
                    mask_blindings=None) -> PerPartyCheck:
    """The dealer's side. `shares[p][j]` is party `p`'s share of value `j`."""
    scheme = as_scheme(key)
    if not shares:
        raise ValueError("a check over no parties checks nothing")
    n_values = len(shares[0])
    if any(len(row) != n_values for row in shares):
        raise ValueError("every party holds one share of every value")
    if len(blindings) != len(shares) or any(
            len(b) != n_values for b in blindings):
        raise ValueError("every share needs its blinding")

    rng = secrets.SystemRandom()
    width = share_bits + challenge_bits + max(0, (n_values - 1).bit_length())
    masks = list(masks) if masks is not None else [
        rng.randrange(1 << (width + statistical_bits)) for _ in shares]
    mask_blindings = list(mask_blindings) if mask_blindings is not None else [
        scheme.random_blinding() for _ in shares]

    share_commitments = [[scheme.commit(v, r) for v, r in zip(row, brow)]
                         for row, brow in zip(shares, blindings)]
    mask_commitments = [scheme.commit(m, b)
                        for m, b in zip(masks, mask_blindings)]
    coefficients_ = per_party_coefficients(scheme, share_commitments,
                                           mask_commitments, context, challenge,
                                           challenge_bits)
    openings, opening_blindings = [], []
    for party, row in enumerate(shares):
        openings.append(sum(c * v for c, v in zip(coefficients_, row))
                        + masks[party])
        opening_blindings.append(
            sum(c * r for c, r in zip(coefficients_, blindings[party]))
            + mask_blindings[party])
    return PerPartyCheck(share_commitments, mask_commitments, openings,
                         opening_blindings, challenge_bits)


def verify_per_party(key, check: PerPartyCheck, context: bytes,
                     challenge: int | None = None) -> tuple[bool, str, list[int]]:
    """Anyone's side. Returns the parties whose inputs were not the committed ones.

    The third element is the difference from `verify`: a list of indices rather
    than a sentence about somebody.
    """
    scheme = as_scheme(key)
    if not check.share_commitments:
        return False, "the check covers no parties", []
    coefficients_ = per_party_coefficients(scheme, check.share_commitments,
                                           check.mask_commitments, context,
                                           challenge, check.challenge_bits)
    culprits = []
    for party in range(check.n_parties):
        combined = check.mask_commitments[party]
        for coefficient, commitment in zip(coefficients_,
                                           check.share_commitments[party]):
            combined = scheme.add(combined, scheme.scale(commitment, coefficient))
        if not scheme.equal(scheme.commit(check.openings[party],
                                          check.opening_blindings[party]),
                            combined):
            culprits.append(party)
    if not culprits:
        return True, "ok", []
    named = ", ".join(f"node {p}" for p in culprits)
    return False, (f"the inputs {named} fed the circuit were not the ones "
                   f"committed to {'it' if len(culprits) == 1 else 'them'}"), culprits
