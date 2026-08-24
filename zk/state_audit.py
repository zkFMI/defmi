"""Zero-knowledge audit of a market maker's *state update*, not just its policy.

`policy_audit.py` shows the pricing rule is well-formed: every field of the rule
sits inside a band the venue published, and the shares the computing nodes hold
open to the committed rule. That covers the rule. It says nothing about what
happens after a fill, and in a stateful protocol --- RFS carries the winner's
inventory forward from one quote to the next --- the rule is the smaller half.
A maker whose declared rule is impeccable can still carry an inventory that
never moved when it should have, or that quietly grew past the size it promised
to stop at.

Three things are proved here, per fill, without opening anything.

    arithmetic   the new inventory is the old one less what was filled, as a
                 linear relation over three commitments
    containment  the new inventory is inside a limit that is itself committed,
                 so the venue learns the promise was kept without learning
                 either the promise or the position
    continuity   each step names the state it followed, so replaying an old
                 state or running two states in parallel breaks the chain

Containment is the part that needs a committed bound rather than a public one.
A public band would have to be wide enough for the largest maker on the venue,
which makes it vacuous for everyone else; the point of a private limit is that
a maker is held to the promise it actually made. The bound is committed once,
with the policy, and every later step proves against that same commitment ---
so tightening the promise after a breach is not available either.

What is deliberately not claimed: this shows the state the maker *published*
evolved correctly. Binding that state to the inventory the MPC nodes actually
used has the same open edge as `policy_audit.py` --- MP-SPDZ works over its own
field --- and closing it is the same piece of work, not a second one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from .commit import (
    OpeningProof, Pedersen, RangeProof, prove_bounded, prove_linear,
    verify_bounded, verify_linear,
)
from .groups import Group


@dataclass(frozen=True)
class InventoryLimit:
    """The bound a maker commits to once, and is held to at every later step."""

    commitment: Any
    range_proof: RangeProof
    ceiling: int                      # the public ceiling the limit itself sits under

    def encoded(self, group: Group) -> bytes:
        return group.encode(self.commitment)


@dataclass(frozen=True)
class StateStep:
    """One link of the inventory chain: the state left behind by one fill."""

    step: int
    inventory: Any                    # commitment to the inventory after the fill
    fill: Any                         # commitment to the signed size that was filled
    follows: bytes                    # encoding of the inventory this step started from
    arithmetic: OpeningProof          # new + filled - old == 0
    below_cap: RangeProof             # limit - new >= 0
    above_floor: RangeProof           # limit + new >= 0


class StateAuditor:
    """Builds and checks the chain. The same object serves both sides.

    Proving needs the openings and verifying does not, which is the only
    difference; keeping them together stops the two sides from drifting apart in
    what they think the context string is, and a mismatched context is the
    failure that looks like a broken proof rather than a broken binding.
    """

    def __init__(self, group: Group, label: bytes = b"qomm:state:v1",
                 ceiling: int = 1 << 20):
        self.group = group
        self.key = Pedersen(group, label)
        self.ceiling = ceiling

    # --- the limit, committed once ---------------------------------------
    def commit_limit(self, limit: int, blinding: int) -> InventoryLimit:
        if not 0 <= limit <= self.ceiling:
            raise ValueError(f"limit {limit} outside [0, {self.ceiling}]")
        commitment, proof, _ = prove_bounded(
            self.key, limit, blinding, 0, self.ceiling, self._context(b"limit"))
        return InventoryLimit(commitment, proof, self.ceiling)

    def check_limit(self, limit: InventoryLimit) -> bool:
        return verify_bounded(self.key, limit.commitment, limit.range_proof,
                              0, limit.ceiling, self._context(b"limit"))

    # --- one step ---------------------------------------------------------
    def prove_update(self, *, step: int, old_inventory: int, old_blinding: int,
                     filled: int, fill_blinding: int, limit: int, limit_blinding: int,
                     new_blinding: int) -> tuple[StateStep, int]:
        """The maker's side. Returns the step and the new inventory value.

        `filled` is signed the way the maker's book moves: a maker that sold
        carries a negative position afterwards, so the new inventory is the old
        one *less* what left. Getting that sign backwards is the mistake this
        proof exists to make impossible to hide, so it is stated once here and
        the relation below is written to match.
        """
        new_inventory = old_inventory - filled
        if abs(new_inventory) > limit:
            raise ValueError(
                f"inventory {new_inventory} breaks the committed limit {limit}; "
                "the maker cannot prove this step and must decline the fill")

        old_commitment = self.key.commit(old_inventory, old_blinding)
        fill_commitment = self.key.commit(filled, fill_blinding)
        new_commitment = self.key.commit(new_inventory, new_blinding)
        context = self._context(f"step:{step}".encode())

        # new + filled - old == 0
        arithmetic = prove_linear(
            self.key, [new_blinding, fill_blinding, old_blinding], [1, 1, -1],
            context, commitments=[new_commitment, fill_commitment, old_commitment])

        below, above = self._containment(
            new_inventory, new_blinding, limit, limit_blinding, context)
        return StateStep(step=step, inventory=new_commitment, fill=fill_commitment,
                         follows=self.group.encode(old_commitment),
                         arithmetic=arithmetic, below_cap=below,
                         above_floor=above), new_inventory

    def _containment(self, inventory: int, blinding: int, limit: int,
                     limit_blinding: int, context: bytes) -> tuple[RangeProof, RangeProof]:
        """|inventory| <= limit, as two one-sided proofs on committed differences.

        The commitment each proof covers is the quotient of two commitments the
        verifier already holds, so passing the difference's own opening here
        produces exactly that point --- checked rather than assumed, because a
        mismatch would make the proof cover a number nobody constrained.
        """
        order = self.group.order
        proofs = []
        for sign in (+1, -1):
            value = limit - sign * inventory
            blind = (limit_blinding - sign * blinding) % order
            commitment, proof, _ = prove_bounded(
                self.key, value, blind, 0, 2 * self.ceiling,
                context + (b":below" if sign > 0 else b":above"))
            expected = self.group.mul(
                self.key.commit(limit, limit_blinding),
                self.group.neg(self.key.commit(sign * inventory % order,
                                               sign * blinding % order)))
            assert self.group.encode(commitment) == self.group.encode(expected)
            proofs.append(proof)
        return proofs[0], proofs[1]

    def verify_update(self, step: StateStep, old_commitment, limit: InventoryLimit) -> bool:
        """The venue's side. Nothing here needs an opening."""
        group = self.group
        if group.encode(old_commitment) != step.follows:
            return False                      # this step did not follow that state
        for point in (step.inventory, step.fill, old_commitment, limit.commitment):
            if not group.is_valid(point):
                return False
        context = self._context(f"step:{step.step}".encode())
        if not verify_linear(self.key,
                             [step.inventory, step.fill, old_commitment], [1, 1, -1],
                             0, step.arithmetic, context):
            return False
        for proof, sign, suffix in ((step.below_cap, +1, b":below"),
                                    (step.above_floor, -1, b":above")):
            difference = group.mul(
                limit.commitment,
                group.neg(group.point_pow(step.inventory, sign % group.order)))
            if not verify_bounded(self.key, difference, proof, 0, 2 * self.ceiling,
                                  context + suffix):
                return False
        return True

    def verify_chain(self, opening_commitment, steps: Sequence[StateStep],
                     limit: InventoryLimit) -> tuple[bool, str]:
        """Walk the chain from a known opening state.

        Returns the reason on failure rather than a bare false, because the three
        ways a chain breaks --- bad arithmetic, a breached limit, a state that
        does not follow the one before it --- call for different responses from
        the venue, and only the last of them is evidence of equivocation.
        """
        if not self.check_limit(limit):
            return False, "the committed limit is not itself in range"
        current = opening_commitment
        for index, step in enumerate(steps):
            if self.group.encode(current) != step.follows:
                return False, (f"step {step.step} (index {index}) does not follow the "
                               "state before it: a replayed or forked inventory")
            if not self.verify_update(step, current, limit):
                return False, f"step {step.step} (index {index}) failed its proofs"
            current = step.inventory
        return True, "ok"

    def _context(self, tag: bytes) -> bytes:
        return b"qomm:state:v1:" + tag
