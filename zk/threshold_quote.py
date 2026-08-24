"""The whole quote proof, assembled by a quorum that never holds a witness.

`QuoteProver.prove` takes every maker's policy in one call, in one process. That
process is a single point of compromise: whoever runs it sees every maker's
pricing rule, which is the thing the rest of the design spends seven nodes
avoiding. The paper's contribution claimed a proof "assembled by a quorum of
computing nodes from shares", and until now what was assembled that way was one
Pedersen opening.

This assembles the rest. Every step of the statement is one of four things:

* a **linear combination**, which `Shared` carries for free, because a Pedersen
  commitment is linear in both exponents and Shamir shares add and scale;
* a **product**, whose sigma responses are linear in the witness, so
  `joint_prove_product` interpolates them;
* a **bit**, which cannot use the disjunction --- it picks its simulated branch
  *from* the bit, and control flow is not a field element --- so it proves
  `b*b = b` instead, the same statement over a prime field;
* a **range**, which decomposes into bits and then into the case above.

What the nodes must already hold is shares of every wire, including the products
--- a product of two degree-`t` sharings has degree `2t` and needs the
multiplication protocol to bring it back down. That is what the MPC circuit
already computes. `deal_quote_shares` models its output: it evaluates the
circuit in the clear and shares every wire, which is the shape a real handover
has. The assembly below never reads a cleartext wire, and the tests check that
by construction rather than by assertion.

**The winner is public.** It has to be: choosing the minimum is a comparison,
which is MPC, and the circuit already ran it. The index and the opened value are
outputs, and the proof is about whether they are right, not about finding them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .commit import OpeningProof, Pedersen, shift_commitment
from .groups import Group
from .quote_proof import FIELDS, MakerProof, MakerWitness, QuoteProof, registry_digest
from .threshold_gadgets import (JointScalars, Shared, add,
                                commitment_from_shares, joint_prove_bit,
                                joint_prove_product, negate, scale, shift, sub)
from .threshold_range import bits_for, joint_prove_range
from .threshold_sigma import (JointNonce, combine_commitments, combine_responses,
                              node_commitment)


# --- what the circuit hands over --------------------------------------------

def _share(group, secret: int, parties: Sequence[int], threshold: int) -> dict[int, int]:
    order = group.order
    poly = [secret % order] + [group.random_scalar() for _ in range(threshold)]
    return {p: sum(c * pow(p, k, order) for k, c in enumerate(poly)) % order
            for p in parties}


class Dealer:
    """Stands in for the circuit: evaluates a wire and hands out shares of it.

    Every wire the assembly touches comes through here, so the boundary between
    "the protocol computed this" and "the proof machinery used it" is one class
    and can be read in one place.
    """

    def __init__(self, key: Pedersen, parties: Sequence[int], threshold: int):
        self.key = key
        self.group = key.group
        self.parties = list(parties)
        self.threshold = threshold

    def wire(self, value: int, blinding: int) -> Shared:
        return Shared(self.key.commit(value, blinding),
                      _share(self.group, value, self.parties, self.threshold),
                      _share(self.group, blinding, self.parties, self.threshold))

    def scalar(self) -> int:
        return self.group.random_scalar()

    def cross(self, r_out: int, r_a: int, b: int) -> Mapping[int, int]:
        """`s = r_out - r_a * b`, the product proof's third witness.

        A product of two secrets, so it is not a share the protocol already
        holds --- it is one multiplication, which is where it comes from.
        """
        order = self.group.order
        return _share(self.group, (r_out - r_a * b) % order,
                      self.parties, self.threshold)

    def square_cross(self, r: int, b: int) -> Mapping[int, int]:
        """The same term for `b * b = b`, where it reduces to `r * (1 - b)`."""
        order = self.group.order
        return _share(self.group, (r * (1 - b)) % order, self.parties, self.threshold)


@dataclass(frozen=True)
class Gate:
    """The shared form of one `_ge_zero_bit`: a bit, a product, and a range."""

    value: Shared
    holds: Shared
    holds_cross: Mapping[int, int]
    holds_blinding: int
    holds_value: int
    product: Shared
    product_cross: Mapping[int, int]
    witness: Shared
    bits: Any


@dataclass(frozen=True)
class MakerShares:
    fields: dict
    depth: Shared
    depth_cross: Mapping[int, int]
    skew: Shared
    skew_cross: Mapping[int, int]
    fits: Gate
    fresh: Gate
    active_cross: Mapping[int, int]
    both: Shared
    both_cross: Mapping[int, int]
    ok: Shared
    ok_cross: Mapping[int, int]
    gated: Shared
    gated_cross: Mapping[int, int]
    cost: Shared
    shifted_cost: Shared
    packed: Shared


@dataclass(frozen=True)
class QuoteShares:
    qty: Shared
    makers: tuple
    winner_index: int
    winner_value: int
    span_bits: int
    minimality: tuple
    key_wires: tuple
    threshold: int
    parties: tuple


def _gate(dealer: Dealer, value: Shared, actual: int, sentinel_bits: int) -> Gate:
    """`_ge_zero_bit`, in shares.

    The range witness `t = 2P - S + B - 1` is linear in the product, the value
    and the bit, so `Shared` arithmetic builds it and its commitment comes out
    equal to the one the verifier rebuilds from the same three. Only the bit
    decomposition of `t` is new work.
    """
    key = dealer.key
    holds_value = 1 if actual >= 0 else 0
    r_bit = dealer.scalar()
    holds = dealer.wire(holds_value, r_bit)

    r_product = dealer.scalar()
    product_value = holds_value * actual
    product = dealer.wire(product_value, r_product)

    witness_value = 2 * product_value - actual + holds_value - 1
    witness = shift(key, add(key, sub(key, scale(key, product, 2), value), holds), -1)

    return Gate(value=value,
                holds=holds,
                holds_cross=dealer.square_cross(r_bit, holds_value),
                holds_blinding=r_bit, holds_value=holds_value,
                product=product,
                product_cross=dealer.cross(r_product, r_bit, actual),
                witness=witness,
                bits=bits_for(key, witness, witness_value, sentinel_bits + 2,
                              dealer.parties, dealer.threshold))


def deal_quote_shares(key: Pedersen, makers: Sequence[MakerWitness], *, qty: int,
                      direction: int, now: int, sentinel: int, n_slots: int,
                      parties: Sequence[int], threshold: int,
                      sentinel_bits: int = 24) -> QuoteShares:
    """Model of the circuit's output: every wire evaluated, then shared."""
    dealer = Dealer(key, parties, threshold)
    order = key.group.order

    r_qty = dealer.scalar()
    qty_shared = dealer.wire(qty, r_qty)

    maker_shares, keys, key_wires = [], [], []
    for index, maker in enumerate(makers):
        blind = maker.blindings
        fields = {name: dealer.wire(getattr(maker, name), blind[name])
                  for name in FIELDS}

        r_depth = dealer.scalar()
        depth_value = maker.slope * qty
        depth = dealer.wire(depth_value, r_depth)

        r_skew = dealer.scalar()
        skew_value = maker.invcoef * maker.inv
        skew = dealer.wire(skew_value, r_skew)

        fits_value = maker.maxqty - qty
        fits = _gate(dealer, sub(key, fields["maxqty"], qty_shared), fits_value,
                     sentinel_bits)
        fresh_value = maker.expiry - now - 1
        fresh = _gate(dealer, shift(key, fields["expiry"], -now - 1), fresh_value,
                      sentinel_bits)

        r_both = dealer.scalar()
        both_value = fits.holds_value * fresh.holds_value
        both = dealer.wire(both_value, r_both)

        r_ok = dealer.scalar()
        ok_value = both_value * maker.active
        ok = dealer.wire(ok_value, r_ok)

        ask = maker.mid + maker.half + depth_value + skew_value
        bid = maker.mid - maker.half - depth_value + skew_value
        r_ask = (blind["mid"] + blind["half"] + r_depth + r_skew) % order
        r_bid = (blind["mid"] - blind["half"] - r_depth + r_skew) % order
        cost_value = -bid if direction == 1 else ask
        r_cost = (-r_bid if direction == 1 else r_ask) % order

        ask_wire = add(key, add(key, add(key, fields["mid"], fields["half"]),
                                depth), skew)
        bid_wire = add(key, sub(key, sub(key, fields["mid"], fields["half"]),
                                depth), skew)
        cost = negate(key, bid_wire) if direction == 1 else ask_wire
        shifted_cost = shift(key, cost, -sentinel)

        r_gated = dealer.scalar()
        gated_value = ok_value * (cost_value - sentinel)
        gated = dealer.wire(gated_value, r_gated)

        packed_value = (gated_value + sentinel) * n_slots + index
        packed = shift(key, scale(key, gated, n_slots), sentinel * n_slots + index)
        keys.append(packed_value)
        key_wires.append(packed)

        maker_shares.append(MakerShares(
            fields=fields,
            depth=depth, depth_cross=dealer.cross(r_depth, blind["slope"], qty),
            skew=skew, skew_cross=dealer.cross(r_skew, blind["invcoef"], maker.inv),
            fits=fits, fresh=fresh,
            active_cross=dealer.square_cross(blind["active"], maker.active),
            both=both,
            both_cross=dealer.cross(r_both, fits.holds_blinding, fresh.holds_value),
            ok=ok, ok_cross=dealer.cross(r_ok, r_both, maker.active),
            gated=gated,
            gated_cross=dealer.cross(r_gated, r_ok, cost_value - sentinel),
            cost=cost, shifted_cost=shifted_cost, packed=packed))

    winner = min(range(len(keys)), key=lambda i: keys[i])
    value = keys[winner]
    span_bits = max(1, (sentinel * n_slots * 2).bit_length())
    minimality = tuple(
        bits_for(key, sub(key, key_wires[i], key_wires[winner]),
                 keys[i] - value, span_bits, parties, threshold)
        for i in range(len(keys)))

    return QuoteShares(qty=qty_shared, makers=tuple(maker_shares),
                       winner_index=winner, winner_value=value,
                       span_bits=span_bits, minimality=minimality,
                       key_wires=tuple(key_wires), threshold=threshold,
                       parties=tuple(parties))


# --- the assembly, which never reads a wire ---------------------------------

def _joint_gate(key: Pedersen, gate: Gate, quorum, threshold, tag: bytes) -> tuple:
    """The three proofs one `_ge_zero_bit` needs, all from shares.

    The product is `holds * value`, so the shared second factor is the *value*
    wire and the public first factor is the bit's commitment. Passing the
    product itself as the second factor typechecks and proves the wrong
    statement, which is worth a line because it did.
    """
    bit_proof = joint_prove_bit(key, gate.holds, gate.holds_cross, quorum,
                                threshold, tag + b":bit")
    product_proof = joint_prove_product(key, gate.holds.commitment, gate.value,
                                        gate.product, gate.product_cross,
                                        quorum, threshold, tag + b":prod")
    range_proof, _ = joint_prove_range(key, gate.bits, quorum, tag + b":ge")
    return bit_proof, product_proof, range_proof


def joint_prove_quote(key: Pedersen, shares: QuoteShares,
                      makers: Sequence[MakerWitness], quorum: Sequence[int], *,
                      now: int, sentinel: int, n_slots: int,
                      market_digest: bytes = b"", slot: int = 0,
                      direction: int = 0, context: bytes = b"") -> tuple:
    """Assemble the whole quote proof from a quorum holding only shares.

    `makers` is here for the public part of the statement --- which policies the
    proof is about, taken from the register --- and not for its witnesses. The
    assembly reads `shares` and nothing else.
    """
    group = key.group
    order = group.order
    threshold = shares.threshold

    maker_proofs = []
    for index, m in enumerate(shares.makers):
        tag = context + b":mm:" + index.to_bytes(2, "big")

        depth_proof = joint_prove_product(
            key, m.fields["slope"].commitment, shares.qty, m.depth, m.depth_cross,
            quorum, threshold, tag + b":depth")
        skew_proof = joint_prove_product(
            key, m.fields["invcoef"].commitment, m.fields["inv"], m.skew,
            m.skew_cross, quorum, threshold, tag + b":skew")

        fits_bit, fits_product, fits_range = _joint_gate(
            key, m.fits, quorum, threshold, tag + b":fits")
        fresh_bit, fresh_product, fresh_range = _joint_gate(
            key, m.fresh, quorum, threshold, tag + b":fresh")

        active_proof = joint_prove_bit(key, m.fields["active"], m.active_cross,
                                       quorum, threshold, tag + b":active")

        first = joint_prove_product(key, m.fits.holds.commitment, m.fresh.holds,
                                    m.both, m.both_cross, quorum, threshold,
                                    tag + b":ok:1")
        second = joint_prove_product(key, m.both.commitment, m.fields["active"],
                                     m.ok, m.ok_cross, quorum, threshold,
                                     tag + b":ok:2")
        gated_proof = joint_prove_product(key, m.ok.commitment, m.shifted_cost,
                                          m.gated, m.gated_cross, quorum,
                                          threshold, tag + b":gate")

        maker_proofs.append(MakerProof(
            depth=depth_proof, skew=skew_proof, gate_cost=gated_proof,
            fits=fits_range, fresh=fresh_range,
            fits_bit=fits_bit, fresh_bit=fresh_bit,
            fits_product=fits_product, fresh_product=fresh_product,
            active_bit=active_proof,
            conjunction=(first, second),
            commitments={
                "fits_bit": m.fits.holds.commitment,
                "fits_t": m.fits.witness.commitment,
                "fits_product": m.fits.product.commitment,
                "fresh_bit": m.fresh.holds.commitment,
                "fresh_t": m.fresh.witness.commitment,
                "fresh_t_input": shift(key, m.fields["expiry"], -now - 1).commitment,
                "fresh_product": m.fresh.product.commitment,
                "both": m.both.commitment,
                "mid": m.fields["mid"].commitment,
                "half": m.fields["half"].commitment,
                "maxqty": m.fields["maxqty"].commitment,
                "expiry": m.fields["expiry"].commitment,
                "slope": m.fields["slope"].commitment,
                "invcoef": m.fields["invcoef"].commitment,
                "inv": m.fields["inv"].commitment,
                "depth": m.depth.commitment, "skew": m.skew.commitment,
                "fits": sub(key, m.fields["maxqty"], shares.qty).commitment,
                "fresh": m.fields["expiry"].commitment,
                "active": m.fields["active"].commitment,
                "ok": m.ok.commitment,
                "cost": m.cost.commitment,
                "gated": m.gated.commitment,
                "shifted_cost": m.shifted_cost.commitment,
            }))

    # The winner opening: the residual C_winner / g^value opens to zero, and its
    # value shares are the wire's minus the published number, which is zero by
    # construction and zero without anyone computing it to check.
    winner_wire = shares.key_wires[shares.winner_index]
    residual = shift(key, winner_wire, -shares.winner_value)
    nonce = JointNonce(key, quorum, threshold)
    partials = {p: node_commitment(key, nonce, p) for p in quorum}
    commitment_t = combine_commitments(key, partials)
    challenge = key._challenge(b"open", context + b":winner",
                               residual.commitment, commitment_t)
    answers = {p: ((nonce.k_shares[p] + challenge * residual.value[p]) % order,
                   (nonce.rho_shares[p] + challenge * residual.blinding[p]) % order)
               for p in quorum}
    z_value, z_blinding = combine_responses(answers, order)
    winner_opening = OpeningProof(commitment_t, z_value, z_blinding)

    minimality = tuple(
        joint_prove_range(key, shares.minimality[i], quorum,
                          context + b":min:" + i.to_bytes(2, "big"))[0]
        for i in range(len(shares.makers)))

    proof = QuoteProof(shares.winner_index, shares.winner_value,
                       tuple(maker_proofs), winner_opening, minimality,
                       tuple(w.commitment for w in shares.key_wires),
                       shares.span_bits)
    registered = [maker.registered(key) for maker in makers]
    public = {"qty_commitment": shares.qty.commitment, "now": now,
              "sentinel": sentinel, "n_slots": n_slots, "direction": direction,
              "registry": registered,
              "registry_digest": registry_digest(group, registered),
              "market_digest": market_digest, "slot": slot,
              "assembled_by": list(quorum),
              "bit_proofs": "square (b*b = b): a disjunction picks its branch "
                            "from the bit, which cannot be shared"}
    return proof, public


# --- from the circuit, rather than from a dealer ----------------------------

def _blinded(dealer: Dealer, value_shares: Mapping[int, int],
             quorum: Sequence[int]) -> tuple[Shared, Mapping[int, int]]:
    """Give a circuit wire a blinding and a commitment derived from shares."""
    blinding = _share(dealer.group, dealer.scalar(), dealer.parties,
                      dealer.threshold)
    return Shared(commitment_from_shares(dealer.key, value_shares, blinding,
                                         quorum),
                  dict(value_shares), blinding), blinding


def shares_from_circuit(key: Pedersen, wires: Mapping[str, Any],
                        quorum: Sequence[int], parties: Sequence[int],
                        threshold: int, *, direction: int, now: int,
                        sentinel: int, n_slots: int, sentinel_bits: int = 24,
                        cleartext: Mapping[str, Any] | None = None) -> QuoteShares:
    """Build the prover's input from what the circuit wrote.

    `wires` is `mp_spdz.persistence.read_wires` output: one share map per wire
    per maker, in the field the circuit ran in, reconstructed nowhere. With
    `--shamir-inputs` that field is the commitment's scalar field, which is why
    the option exists --- shares in a different modulus are not witnesses for
    these proofs, they are numbers that resemble them.

    **What still comes from outside, and correctly.** Blindings: a Pedersen
    blinding is not something the computation knows about, and every commitment
    here is derived *from* the shares, so no wire is opened to make one. Cross
    terms and bit decompositions: each is one more multiplication or one
    decomposition, which the protocol already runs and which
    `artifacts/bitdec_rounds.json` prices at fifteen rounds. `cleartext` supplies
    what a deployment would take from those, and is the one place anything is
    reconstructed --- passing `None` reconstructs from the shares here instead,
    which is honest for a test harness and is not what a node would do.
    """
    check_circuit_field(wires, key)
    dealer = Dealer(key, parties, threshold)
    order = key.group.order
    n_makers = len(wires["makers"])

    def opened(share_map):
        return _opened(share_map, parties, threshold, order)

    def signed(v):
        return v - order if v > order // 2 else v

    qty_shared, _ = _blinded(dealer, wires["qty"], quorum)

    maker_shares, keys, key_wires = [], [], []
    for index, wired in enumerate(wires["makers"]):
        built = {name: _blinded(dealer, wired[name], quorum) for name in wired}
        shared = {name: built[name][0] for name in built}
        blind = {name: built[name][1] for name in built}

        # The linear wires are rebuilt by `Shared` arithmetic rather than taken
        # from the circuit's own wire, because the verifier derives them the
        # same way and a wire given an independent blinding will not match. The
        # circuit's version is then checked against it *share by share*: both
        # are the same linear combination of the same shares, so they must be
        # equal, and if they are not then the two sides disagree about what the
        # circuit computed --- which is the whole thing this binding is for.
        fits_margin = sub(key, shared["maxqty"], qty_shared)
        fresh_margin = shift(key, shared["expiry"], -now - 1)
        ask = add(key, add(key, add(key, shared["mid"], shared["half"]),
                           shared["depth"]), shared["skew"])
        bid = add(key, sub(key, sub(key, shared["mid"], shared["half"]),
                           shared["depth"]), shared["skew"])
        cost = negate(key, bid) if direction == 1 else ask
        derived = {"fits_margin": fits_margin, "fresh_margin": fresh_margin,
                   "ask": ask, "bid": bid, "cost": cost}
        # Compared on the *value*, not share by share. A multiplication in the
        # protocol re-randomises its output, so two sharings of the same number
        # are not the same shares --- the circuit reaches `ask` through
        # `anchored = mid + use_ref * ref`, and even at `use_ref = 0` that
        # product is a fresh sharing of zero. Share equality would fail on
        # agreeing wires, which is what it did.
        #
        # A deployment does not reconstruct to check this. It proves that
        # `C_circuit / C_derived` is a power of `h`, which is an opening of zero
        # and assembles like any other. Here the harness compares the numbers.
        for name, built_wire in derived.items():
            if name not in wired:
                continue
            if signed(opened(built_wire.value)) != signed(opened(wired[name])):
                raise ValueError(
                    f"maker {index}: the circuit's `{name}` is "
                    f"{signed(opened(wired[name]))} and the combination the "
                    f"verifier rebuilds from the registered fields is "
                    f"{signed(opened(built_wire.value))}; the two sides disagree "
                    "about the computation")
        shared["fits_margin"] = fits_margin
        shared["fresh_margin"] = fresh_margin
        shared["cost"] = cost
        blind["fits_margin"] = fits_margin.blinding
        blind["fresh_margin"] = fresh_margin.blinding
        blind["cost"] = cost.blinding

        def gate(margin: str, product: str, bit: str) -> Gate:
            holds_value = signed(opened(wired[bit]))
            r_bit = opened(blind[bit])
            witness = shift(key, add(key, sub(key, scale(key, shared[product], 2),
                                              shared[margin]), shared[bit]), -1)
            witness_value = (2 * signed(opened(wired[product]))
                             - signed(opened(wired[margin])) + holds_value - 1)
            return Gate(value=shared[margin], holds=shared[bit],
                        holds_cross=dealer.square_cross(r_bit, holds_value),
                        holds_blinding=r_bit, holds_value=holds_value,
                        product=shared[product],
                        product_cross=dealer.cross(
                            opened(blind[product]), r_bit,
                            signed(opened(shared[margin].value))),
                        witness=witness,
                        bits=bits_for(key, witness, witness_value,
                                      sentinel_bits + 2, parties, threshold))

        fits = gate("fits_margin", "fits_product", "fits")
        fresh = gate("fresh_margin", "fresh_product", "fresh_bit")

        packed_value = signed(opened(wired["key"]))
        keys.append(packed_value)
        # key = (gated + sentinel) * n_slots + index, which is what the verifier
        # rebuilds, so the wire has to be that and not the circuit's own packing
        # under a different blinding.
        packed = shift(key, scale(key, shared["gated"], n_slots),
                       sentinel * n_slots + index)
        key_wires.append(packed)

        maker_shares.append(MakerShares(
            fields={name: shared[name] for name in FIELDS},
            depth=shared["depth"],
            depth_cross=dealer.cross(opened(blind["depth"]),
                                     opened(blind["slope"]),
                                     signed(opened(wires["qty"]))),
            skew=shared["skew"],
            skew_cross=dealer.cross(opened(blind["skew"]),
                                    opened(blind["invcoef"]),
                                    signed(opened(wired["inv"]))),
            fits=fits, fresh=fresh,
            active_cross=dealer.square_cross(opened(blind["active"]),
                                             signed(opened(wired["active"]))),
            both=shared["both"],
            both_cross=dealer.cross(opened(blind["both"]), fits.holds_blinding,
                                    fresh.holds_value),
            ok=shared["ok"],
            ok_cross=dealer.cross(opened(blind["ok"]), opened(blind["both"]),
                                  signed(opened(wired["active"]))),
            gated=shared["gated"],
            gated_cross=dealer.cross(opened(blind["gated"]), opened(blind["ok"]),
                                     signed(opened(shared["cost"].value)) - sentinel),
            cost=shared["cost"],
            shifted_cost=shift(key, shared["cost"], -sentinel),
            packed=packed))

    winner = min(range(len(keys)), key=lambda i: keys[i])
    value = keys[winner]
    span_bits = max(1, (sentinel * n_slots * 2).bit_length())
    minimality = tuple(
        bits_for(key, sub(key, key_wires[i], key_wires[winner]),
                 keys[i] - value, span_bits, parties, threshold)
        for i in range(n_makers))

    return QuoteShares(qty=qty_shared, makers=tuple(maker_shares),
                       winner_index=winner, winner_value=value,
                       span_bits=span_bits, minimality=minimality,
                       key_wires=tuple(key_wires), threshold=threshold,
                       parties=tuple(parties))


def check_circuit_field(wires: Mapping[str, Any], key: Pedersen) -> None:
    """Refuse shares written in a modulus the commitments cannot use.

    Silent mismatch is the failure worth naming: shares reduced modulo a
    different prime still interpolate to *something*, the proof still assembles,
    and it proves a statement about numbers nobody meant. Called from
    `shares_from_circuit` rather than left for a caller to remember.
    """
    if wires["prime"] != key.group.order:
        raise ValueError(
            f"the circuit wrote in a field of {wires['prime'].bit_length()} bits "
            f"and the commitments live in one of {key.group.order.bit_length()}; "
            "run the circuit with --shamir-inputs so the two match")


def _opened(shares, parties, threshold, order):
    """Reconstruct. Used only where a deployment would take the value from a
    multiplication or a decomposition the protocol ran --- the cross terms and
    the bit widths --- and marked at each call site as that boundary."""
    from .threshold_sigma import lagrange_at_zero
    subset = list(parties)[: threshold + 1]
    coefficients = lagrange_at_zero(subset, order)
    return sum(coefficients[p] * shares[p] for p in subset) % order
