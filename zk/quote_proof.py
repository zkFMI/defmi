"""Publicly verifiable proof that the opened quote is the correct one.

The receipts in `qomm_audit` bind a node to a result; they do not show the result
is right. This module closes that gap for the quote circuit, without a
general-purpose SNARK and without a trusted setup, by proving the statement the
circuit actually computes:

    for each maker i, key_i is the committed policy applied to the committed
    request, and the opened winner is the smallest of those keys.

Every step is a sigma protocol over Pedersen commitments, which matters for two
reasons. Sigma responses are linear in the witness, so the computing nodes can
assemble the proof jointly from shares (see `threshold_sigma`). And the whole
thing is checked by an ordinary verifier with no setup.

Structure per maker:

    depth_i    = slope_i * qty            product proof
    skew_i     = invcoef_i * inv_i        product proof
    ask_i      = mid_i + half_i + depth_i + skew_i        linear, free
    bid_i      = mid_i - half_i - depth_i + skew_i        linear, free
    fits_i     = maxqty_i - qty >= 0      range proof
    fresh_i    = expiry_i - now  >= 0     range proof
    ok_i       is a bit, and gates the cost                bit + product proofs
    key_i      = cost_i * M + i           linear, free

and then over the whole set:

    winner     key_j opens to the revealed value            opening proof
    minimality key_i - v >= 0 for every i                   range proofs

Minimality plus membership is exactly "v is the minimum", so an incorrect winner
cannot be proved.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .commit import (
    BitProof, OpeningProof, Pedersen, ProductProof, RangeProof, prove_bit,
    prove_opening, prove_product, prove_range, shift_commitment, verify_bit,
    verify_opening, verify_product, verify_range,
)
from .groups import Group


FIELDS = ("mid", "half", "slope", "invcoef", "inv", "maxqty", "expiry", "active")


@dataclass(frozen=True)
class MakerWitness:
    """A maker's policy and the blindings it registered it under.

    The blindings are what makes this a witness for a *registered* policy
    rather than for whatever the prover felt like committing. Without them the
    prover drew fresh blindings for every field at proving time, so the quote
    proof established a minimum over a set of commitments the prover had just
    invented -- true about those, and about nothing on the record.
    """

    mid: int
    half: int
    slope: int
    invcoef: int
    inv: int
    maxqty: int
    expiry: int
    active: int
    blindings: dict = field(default_factory=dict)

    def registered(self, key: Pedersen) -> dict:
        """The commitments this policy was registered under."""
        return {name: key.commit(getattr(self, name), self.blindings[name])
                for name in FIELDS}


def registry_digest(group: Group, registered: Sequence[Mapping[str, Any]]) -> bytes:
    """One digest over the whole eligible set, in order.

    Fixing this in the public statement is what makes maker *omission* visible:
    a prover that drops a maker to change the winner has to publish a different
    digest, and the digest was agreed before the request arrived.
    """
    hasher = hashlib.sha256(b"QOMM:QUOTE:REGISTRY:v1")
    hasher.update(len(registered).to_bytes(4, "big"))
    for policy in registered:
        for name in FIELDS:
            hasher.update(group.encode(policy[name]))
    return hasher.digest()


@dataclass(frozen=True)
class MakerProof:
    depth: ProductProof
    skew: ProductProof
    gate_cost: ProductProof
    fits: RangeProof
    fresh: RangeProof
    fits_bit: BitProof
    fresh_bit: BitProof
    fits_product: ProductProof
    fresh_product: ProductProof
    active_bit: BitProof
    conjunction: tuple            # (fits and fresh, that and active)
    commitments: dict


@dataclass(frozen=True)
class QuoteProof:
    winner_index: int
    winner_value: int
    maker_proofs: tuple
    winner_opening: OpeningProof
    minimality: tuple            # one range proof per maker
    key_commitments: tuple
    range_bits: int


class QuoteProver:
    """Builds the proof. The witness may be held by one party or shared."""

    def __init__(self, group: Group, key: Pedersen | None = None,
                 sentinel_bits: int = 24):
        self.group = group
        self.key = key or Pedersen(group, b"qomm:policy:v1")
        self.sentinel_bits = sentinel_bits

    def _blind(self) -> int:
        return self.key.random_blinding()

    def _ge_zero_bit(self, value: int, blinding: int, commitment, tag: bytes):
        """A bit that is 1 exactly when the committed value is non-negative.

        The same shape the rule language uses: one product for `bit * value`,
        and one range proof on `t = 2P - S + B - g`, which is non-negative when
        the bit is right and negative when it is not. Total in both directions,
        so an ineligible maker is representable rather than unprovable.
        """
        key, order = self.key, self.group.order
        holds = 1 if value >= 0 else 0
        r_bit = self._blind()
        c_bit = key.commit(holds, r_bit)
        bit_proof = prove_bit(key, c_bit, holds, r_bit, tag + b":bit")

        r_product = self._blind()
        product_proof = prove_product(key, c_bit, holds, r_bit, value, blinding,
                                      r_product, tag + b":prod")
        c_product = key.commit(holds * value, r_product)

        witness = 2 * holds * value - value + holds - 1
        r_witness = (2 * r_product - blinding + r_bit) % order
        c_witness = self.group.mul(
            self.group.mul(self.group.point_pow(c_product, 2),
                           self.group.neg(commitment)), c_bit)
        c_witness = self.group.mul(c_witness, self.group.neg(key.commit(1, 0)))
        range_proof = prove_range(key, c_witness, witness, r_witness,
                                  self.sentinel_bits + 2, tag + b":ge")
        return (holds, r_bit, c_bit, range_proof, bit_proof, product_proof,
                c_witness, c_product)

    def _and(self, left, right, tag: bytes):
        """Two bits multiplied. The result is a bit because the factors are."""
        key = self.key
        (a, r_a, c_a), (b, r_b, c_b) = left, right
        r_out = self._blind()
        proof = prove_product(key, c_a, a, r_a, b, r_b, r_out, tag)
        return (a * b, r_out, key.commit(a * b, r_out)), proof

    def prove(self, makers: Sequence[MakerWitness], *, qty: int, direction: int,
              now: int, sentinel: int, n_slots: int,
              market_digest: bytes = b"", slot: int = 0,
              context: bytes = b"") -> tuple[QuoteProof, dict]:
        key = self.key
        group = self.group
        order = group.order

        for index, maker in enumerate(makers):
            missing = [name for name in FIELDS if name not in maker.blindings]
            if missing:
                raise ValueError(
                    f"maker {index} has no registered blinding for {missing}: a "
                    "quote proof is about policies that were put on the record, "
                    "and a witness without them is a policy invented now")

        r_qty = self._blind()
        c_qty = key.commit(qty, r_qty)

        keys: list[int] = []
        key_blindings: list[int] = []
        key_commitments: list[Any] = []
        maker_proofs: list[MakerProof] = []

        for index, maker in enumerate(makers):
            tag = context + b":mm:" + index.to_bytes(2, "big")
            # Every field opens the commitment the maker registered. Drawing
            # fresh blindings here is what made the proof true about a set the
            # prover had just made up.
            blind = maker.blindings
            r_slope, r_invcoef, r_inv = (blind["slope"], blind["invcoef"], blind["inv"])
            c_slope = key.commit(maker.slope, r_slope)
            c_invcoef = key.commit(maker.invcoef, r_invcoef)
            c_inv = key.commit(maker.inv, r_inv)

            r_depth = self._blind()
            depth = maker.slope * qty
            depth_proof = prove_product(key, c_slope, maker.slope, r_slope,
                                        qty, r_qty, r_depth, tag + b":depth")
            r_skew = self._blind()
            skew = maker.invcoef * maker.inv
            skew_proof = prove_product(key, c_invcoef, maker.invcoef, r_invcoef,
                                       maker.inv, r_inv, r_skew, tag + b":skew")

            r_mid, r_half = blind["mid"], blind["half"]
            ask = maker.mid + maker.half + depth + skew
            bid = maker.mid - maker.half - depth + skew
            r_ask = (r_mid + r_half + r_depth + r_skew) % order
            r_bid = (r_mid - r_half - r_depth + r_skew) % order

            # Eligibility, proved in both directions and then multiplied out.
            #
            # It used to be two range proofs and a free bit: `fits` and `fresh`
            # were shown non-negative, `ok` was committed with a bit proof, and
            # nothing tied `ok` to them. Two things followed. An *ineligible*
            # maker could not be proved at all, since a negative difference has
            # no range proof --- the only way to quote was to leave it out, and
            # the register now makes that visible. And an *eligible* one could
            # be switched off: set `ok = 0`, both range proofs still pass on
            # non-negative values, and that maker is gated to the sentinel and
            # out of contention. Suppressing the best maker was free.
            r_maxqty, r_expiry = blind["maxqty"], blind["expiry"]
            c_fits = key.commit(maker.maxqty - qty, (r_maxqty - r_qty) % order)
            fits = self._ge_zero_bit(maker.maxqty - qty, (r_maxqty - r_qty) % order,
                                     c_fits, tag + b":fits")
            c_fresh = key.commit(maker.expiry - now, r_expiry)
            fresh = self._ge_zero_bit(maker.expiry - now - 1, r_expiry,
                                      shift_commitment(key, c_fresh, 1),
                                      tag + b":fresh")

            r_active = blind["active"]
            c_active = key.commit(maker.active, r_active)
            active_proof = prove_bit(key, c_active, maker.active, r_active, tag + b":active")

            # ok = fits and fresh and active, as two products of bits. A product
            # of two proved bits is a bit, so `ok` needs no bit proof of its own
            # and, more to the point, has no freedom left.
            both, conj_first = self._and(fits[:3], fresh[:3], tag + b":ok:1")
            ok_wire, conj_second = self._and(
                both, (maker.active, r_active, c_active), tag + b":ok:2")
            ok, r_ok, c_ok = ok_wire

            cost = -bid if direction == 1 else ask
            r_cost = (-r_bid if direction == 1 else r_ask) % order
            c_cost = key.commit(cost, r_cost)

            # gated = ok * (cost - sentinel), so gated + sentinel is the effective cost
            r_gated = self._blind()
            gated_proof = prove_product(key, c_ok, ok, r_ok, cost - sentinel,
                                        (r_cost - 0) % order, r_gated, tag + b":gate")
            effective = ok * (cost - sentinel) + sentinel
            r_effective = r_gated

            packed = effective * n_slots + index
            r_packed = (r_effective * n_slots) % order
            keys.append(packed)
            key_blindings.append(r_packed)
            key_commitments.append(key.commit(packed, r_packed))

            maker_proofs.append(MakerProof(
                depth=depth_proof, skew=skew_proof, gate_cost=gated_proof,
                fits=fits[3], fresh=fresh[3],
                fits_bit=fits[4], fresh_bit=fresh[4],
                fits_product=fits[5], fresh_product=fresh[5],
                active_bit=active_proof,
                conjunction=(conj_first, conj_second),
                commitments={
                    "fits_bit": fits[2], "fits_t": fits[6],
                    "fresh_bit": fresh[2], "fresh_t": fresh[6],
                    "fresh_t_input": shift_commitment(key, c_fresh, 1),
                    "fits_product": fits[7], "fresh_product": fresh[7],
                    "both": both[2],
                    "mid": key.commit(maker.mid, r_mid),
                    "half": key.commit(maker.half, r_half),
                    "maxqty": key.commit(maker.maxqty, r_maxqty),
                    "expiry": key.commit(maker.expiry, r_expiry),
                    "slope": c_slope, "invcoef": c_invcoef, "inv": c_inv,
                    "depth": key.commit(depth, r_depth), "skew": key.commit(skew, r_skew),
                    "fits": c_fits, "fresh": c_fresh, "active": c_active, "ok": c_ok,
                    "cost": c_cost, "gated": key.commit(ok * (cost - sentinel), r_gated),
                    "shifted_cost": key.commit(cost - sentinel, r_cost),
                }))

        winner = min(range(len(keys)), key=lambda i: keys[i])
        value = keys[winner]
        # Bind the *published* number, not merely the commitment. An opening
        # proof shows knowledge of some opening and says nothing about which, so
        # proving C_winner directly would leave the price a free parameter: a
        # venue could publish any figure and the proof would still verify.
        # Proving that C_winner / g^value is a pure power of h says the
        # commitment opens to this value and no other, at the same cost.
        winner_opening = prove_opening(
            key, shift_commitment(key, key_commitments[winner], value),
            0, key_blindings[winner], context + b":winner")

        span_bits = max(1, (sentinel * n_slots * 2).bit_length())
        minimality = []
        for index in range(len(keys)):
            difference = keys[index] - value
            r_diff = (key_blindings[index] - key_blindings[winner]) % order
            c_diff = shift_commitment(key, key_commitments[index], 0)
            c_diff = self.group.mul(c_diff, self.group.neg(key_commitments[winner]))
            minimality.append(prove_range(key, c_diff, difference, r_diff, span_bits,
                                          context + b":min:" + index.to_bytes(2, "big")))

        proof = QuoteProof(winner, value, tuple(maker_proofs), winner_opening,
                           tuple(minimality), tuple(key_commitments), span_bits)
        registered = [maker.registered(key) for maker in makers]
        public = {"qty_commitment": c_qty, "now": now, "sentinel": sentinel,
                  "n_slots": n_slots, "direction": direction,
                  # what the proof is *about*, as opposed to what it proves
                  "registry": registered,
                  "registry_digest": registry_digest(group, registered),
                  "market_digest": market_digest,
                  "slot": slot}
        return proof, public


class QuoteVerifier:
    def __init__(self, group: Group, key: Pedersen | None = None,
                 sentinel_bits: int = 24, assembled: bool = False):
        self.group = group
        self.key = key or Pedersen(group, b"qomm:policy:v1")
        self.sentinel_bits = sentinel_bits
        # `assembled` selects the two leaf proofs a shared prover can actually
        # produce. A disjunction picks which branch to simulate *from* the bit,
        # and a node holding a share cannot make a control-flow decision, so an
        # assembled proof shows `b*b = b` instead --- the same statement over a
        # prime field --- and its range proofs are built from those. Everything
        # above the leaves is identical, which is why this is a switch here
        # rather than a second verifier: a copy of this logic is where the next
        # defect would live.
        self.assembled = assembled
        if assembled:
            from .threshold_gadgets import verify_square_bit
            from .threshold_range import verify_threshold_range
            self._verify_bit = verify_square_bit
            self._verify_range = verify_threshold_range
        else:
            self._verify_bit = verify_bit
            self._verify_range = verify_range

    def _check_ge_zero_bit(self, c, maker, name: str, base, tag: bytes) -> bool:
        """The mirror of `_ge_zero_bit`: one product and one derived range."""
        key, group = self.key, self.group
        bit = c[f"{name}_bit"]
        product = c[f"{name}_product"]
        if not self._verify_bit(key, bit, getattr(maker, f"{name}_bit"), tag + b":bit"):
            return False
        if not verify_product(key, bit, base, product,
                              getattr(maker, f"{name}_product"), tag + b":prod"):
            return False
        witness = group.mul(group.mul(group.point_pow(product, 2), group.neg(base)), bit)
        witness = group.mul(witness, group.neg(key.commit(1, 0)))
        if group.encode(witness) != group.encode(c[f"{name}_t"]):
            return False
        return self._verify_range(key, c[f"{name}_t"], getattr(maker, name),
                                  tag + b":ge")

    def verify(self, proof: QuoteProof, public: Mapping[str, Any],
               context: bytes = b"") -> tuple[bool, str]:
        key = self.key
        group = self.group
        c_qty = public["qty_commitment"]

        # What the statement has to say before any of it means anything: which
        # policies, which set, and which request. Without these the proof
        # established a minimum over commitments the prover chose, which is
        # true and says nothing about the market that was registered.
        registered = public.get("registry")
        if registered is None:
            return False, ("the statement names no registered policies, so this "
                           "proof is about commitments the prover chose")
        if len(registered) != len(proof.maker_proofs):
            return False, (f"the statement registers {len(registered)} makers and "
                           f"the proof covers {len(proof.maker_proofs)}")
        expected = registry_digest(group, registered)
        if public.get("registry_digest") != expected:
            return False, "the registered set is not the one this statement names"

        # Shape, before any algebra. A proof with no makers used to verify
        # against an empty register, a winner index used to be a Python index
        # so a negative one silently named a different commitment, an index
        # past the end raised `IndexError` instead of refusing, and `minimality`
        # used to be iterated --- so deleting it verified. Each of those is a
        # proof that says nothing being accepted as one that says something.
        if not proof.maker_proofs:
            return False, "a proof about no makers is not a proof about a market"
        if len(proof.key_commitments) != len(proof.maker_proofs):
            return False, (f"{len(proof.key_commitments)} keys for "
                           f"{len(proof.maker_proofs)} makers")
        if len(proof.minimality) != len(proof.maker_proofs):
            return False, (f"{len(proof.minimality)} minimality proofs for "
                           f"{len(proof.maker_proofs)} makers; every maker has "
                           "to be shown at least the winner")
        if not 0 <= proof.winner_index < len(proof.key_commitments):
            return False, f"winner index {proof.winner_index} is not a maker"

        sentinel = public["sentinel"]
        n_slots = public["n_slots"]
        direction = public["direction"]

        for index, maker in enumerate(proof.maker_proofs):
            tag = context + b":mm:" + index.to_bytes(2, "big")
            c = maker.commitments
            for name in FIELDS:
                if name not in c:
                    return False, f"maker {index}: the proof does not carry {name}"
                if group.encode(c[name]) != group.encode(registered[index][name]):
                    return False, (f"maker {index}: {name} is not the one on the "
                                   "register")
            if not verify_product(key, c["slope"], c_qty, c["depth"], maker.depth,
                                  tag + b":depth"):
                return False, f"maker {index}: depth is not slope * quantity"
            if not verify_product(key, c["invcoef"], c["inv"], c["skew"], maker.skew,
                                  tag + b":skew"):
                return False, f"maker {index}: skew is not invcoef * inventory"
            # `fits` and `fresh` are derived, not published: the size test is
            # `maxqty - qty` against the register and the request, and the
            # freshness test is `expiry - now - 1` against the register and the
            # clock. Taking them from the proof would let a prover decide what
            # it was proving eligibility about.
            derived_fits = group.mul(c["maxqty"], group.neg(c_qty))
            if group.encode(derived_fits) != group.encode(c["fits"]):
                return False, (f"maker {index}: the size test is not "
                               "`maxqty - quantity` on the registered policy")
            derived_fresh = shift_commitment(
                key, group.mul(c["expiry"], group.neg(key.commit(public["now"], 0))), 1)
            if group.encode(derived_fresh) != group.encode(c["fresh_t_input"]):
                return False, (f"maker {index}: the freshness test is not "
                               "`expiry - now - 1` on the registered policy")
            for name, base in (("fits", c["fits"]), ("fresh", c["fresh_t_input"])):
                if not self._check_ge_zero_bit(c, maker, name, base,
                                               tag + b":" + name.encode()):
                    return False, (f"maker {index}: the {name} test is not what "
                                   "its bit says it is")
            if not self._verify_bit(key, c["active"], maker.active_bit, tag + b":active"):
                return False, f"maker {index}: active flag is not a bit"
            # ok = fits and fresh and active, proved rather than committed. This
            # is what stops an eligible maker being switched off: the bit is a
            # product of the three and none of them is the prover's to choose.
            first, second = maker.conjunction
            if not verify_product(key, c["fits_bit"], c["fresh_bit"], c["both"],
                                  first, tag + b":ok:1"):
                return False, f"maker {index}: `fits and fresh` does not check out"
            if not verify_product(key, c["both"], c["active"], c["ok"],
                                  second, tag + b":ok:2"):
                return False, (f"maker {index}: eligibility is not the "
                               "conjunction of its three tests")
            # The cost has to *be* the policy applied to the request, and the
            # key has to be that cost. Nothing used to say so: `cost` and
            # `shifted_cost` were commitments the prover supplied and the
            # verifier read, and `key_commitments` were unrelated to `gated`.
            # Replacing the cost commitment left the proof verifying, and a
            # proof built for one direction verified when published as the
            # other --- naming a winner that was not the winner. All of it is
            # linear, so all of it is an equality on commitments the verifier
            # already holds rather than a proof anyone has to produce.
            ask = group.mul(group.mul(group.mul(c["mid"], c["half"]),
                                      c["depth"]), c["skew"])
            bid = group.mul(group.mul(group.mul(c["mid"], group.neg(c["half"])),
                                      group.neg(c["depth"])), c["skew"])
            derived_cost = group.neg(bid) if direction == 1 else ask
            if group.encode(derived_cost) != group.encode(c["cost"]):
                return False, (f"maker {index}: the cost is not the registered "
                               "policy applied to this request in this direction")
            derived_shifted = group.mul(c["cost"], group.neg(key.commit(sentinel, 0)))
            if group.encode(derived_shifted) != group.encode(c["shifted_cost"]):
                return False, f"maker {index}: the gated cost is not cost - sentinel"
            if not verify_product(key, c["ok"], c["shifted_cost"], c["gated"],
                                  maker.gate_cost, tag + b":gate"):
                return False, f"maker {index}: cost is not gated by eligibility"
            # key = (gated + sentinel) * n_slots + index, which in the exponent
            # is the gated commitment raised to n_slots and shifted by a public
            # constant. The blinding follows because the prover scales it the
            # same way, so this is an equality and not another proof.
            derived_key = group.mul(group.point_pow(c["gated"], n_slots),
                                    key.commit(sentinel * n_slots + index, 0))
            if group.encode(derived_key) != group.encode(proof.key_commitments[index]):
                return False, (f"maker {index}: the key is not this maker's gated "
                               "cost packed with its slot")

        # The verifier reconstructs the same residual from the published value,
        # so a proof made for one price does not carry to another.
        if not verify_opening(key, shift_commitment(
                                  key, proof.key_commitments[proof.winner_index],
                                  proof.winner_value),
                              proof.winner_opening, context + b":winner"):
            return False, "the published winner value is not what the commitment opens to"

        for index, range_proof in enumerate(proof.minimality):
            difference = group.mul(proof.key_commitments[index],
                                   group.neg(proof.key_commitments[proof.winner_index]))
            if not self._verify_range(key, difference, range_proof,
                                      context + b":min:" + index.to_bytes(2, "big")):
                return False, f"maker {index}: not shown to be at least the winner"
        return True, "ok"
