"""zkPI: a payment instruction whose contents stay hidden from the settlement venue.

Settling a private quote in the clear undoes the work that produced it: the asset
moved, the amount and the counterparties are all visible on chain, which reveals
the market the multi-asset circuit was built to hide. A zkPI closes that by
making the instruction itself a commitment plus a proof, so a settlement venue
can check that an instruction is well-formed, authorised and unspent without
learning what it moves.

Deliberately pluggable. The venue side needs only:

    SettlementVenue(group, quorum_key=...).verify(instruction, now=...) -> (ok, reason)
    nullifier(instruction)                -> bytes, spent at most once

so a DEX that already has its own matching engine can accept zkPIs from this one,
or from any other issuer that speaks the same interface. Nothing in the checks
below depends on how the price was reached.

What a verifier learns: that some enrolled entity holds an instruction whose
asset and amount lie in the declared ranges, whose price matches the quote the
computing nodes signed, whose deadline has not passed, and whose nullifier has
not been seen. What it does not learn: the asset, the amount, the price, or which
entity.

**This is the reference prototype, not the security candidate.** The Rust port
in `rust/qomm-zkpi` is the one to read for the current construction: it binds
the quote key into the signed digest, verifies each committed field against its
own range proof, and takes its quorum public key from a FROST deal rather than
from the instruction. What is here came first and is kept because the
measurements in the paper's Python column were taken against it. Two things it
gets wrong and the port does not are recorded above the code that gets them
wrong.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .commit import (
    Pedersen, RangeProof, prove_bounded, prove_opening, verify_bounded, verify_opening,
)
from .groups import DOMAIN, Group
from .threshold_sigma import ShareSet, deal, joint_prove_opening

PI_DOMAIN = DOMAIN + b":zkpi:v1"


def _sign_context(digest: bytes) -> bytes:
    """Fiat-Shamir context for the quorum signature: the instruction itself."""
    return PI_DOMAIN + b":sign:" + digest


@dataclass(frozen=True)
class InstructionBounds:
    """What the settlement venue is willing to accept, published in advance."""

    amount: tuple[int, int] = (1, 1_000_000)
    price: tuple[int, int] = (1, 10_000_000)
    max_horizon: int = 3_600

    def fields(self) -> tuple[str, ...]:
        return ("amount", "price")

    def for_field(self, name: str) -> tuple[int, int]:
        return getattr(self, name)


@dataclass(frozen=True)
class ZkPaymentInstruction:
    """Everything the venue sees. No plaintext leg details anywhere."""

    asset_commitment: Any
    amount_commitment: Any
    price_commitment: Any
    payer_handle: Any            # scope nullifier of the paying entity
    payee_handle: Any            # scope nullifier of the receiving entity
    deadline: int
    nonce: bytes
    range_proofs: Mapping[str, RangeProof]
    quote_binding: Any           # commitment tying this to the signed quote
    quote_proof: Any             # opening proof for the binding
    quorum_signature: Any        # threshold signature by the computing nodes
    quorum: tuple

    def digest(self, group: Group) -> bytes:
        parts = [group.encode(self.asset_commitment), group.encode(self.amount_commitment),
                 group.encode(self.price_commitment), group.encode(self.payer_handle),
                 group.encode(self.payee_handle),
                 self.deadline.to_bytes(8, "big"), self.nonce]
        h = hashlib.sha256(PI_DOMAIN)
        for part in parts:
            h.update(len(part).to_bytes(4, "big"))
            h.update(part)
        return h.digest()

    def nullifier(self, group: Group) -> bytes:
        """One-time spend tag. Binds the payer to this instruction only."""
        return hashlib.sha256(PI_DOMAIN + b":null:" + group.encode(self.payer_handle)
                              + self.nonce).digest()


class InstructionIssuer:
    """Built by the winning parties from values only they can read."""

    def __init__(self, group: Group, key: Pedersen | None = None,
                 bounds: InstructionBounds | None = None,
                 quorum_secret: int | None = None,
                 quorum_blinding: int | None = None):
        self.group = group
        self.key = key or Pedersen(group, b"qomm:zkpi:v1")
        self.bounds = bounds or InstructionBounds()
        # The quorum this issuer signs with. Dealing a fresh one per instruction
        # -- which is what happened when these are None -- means the "quorum"
        # is whatever the issuer made up a moment ago, and a venue that reads
        # the key out of the instruction cannot tell that from a real one. Fix
        # them here and hand `quorum_key` to the venue, and the two are talking
        # about the same set of nodes.
        self.quorum_secret = quorum_secret
        self.quorum_blinding = quorum_blinding

    @property
    def quorum_key(self):
        """The public key a venue should be constructed to trust, or None."""
        if self.quorum_secret is None or self.quorum_blinding is None:
            return None
        return self.key.commit(self.quorum_secret, self.quorum_blinding)

    def issue(self, *, asset: int, amount: int, price: int, payer_handle: Any,
              payee_handle: Any, deadline: int, nonce: bytes,
              quote_key: int, nodes: Sequence[int], threshold: int,
              quorum: Sequence[int]) -> tuple[ZkPaymentInstruction, dict]:
        key = self.key
        group = self.group
        blindings = {name: key.random_blinding() for name in ("asset", "amount", "price")}
        asset_commitment = key.commit(asset, blindings["asset"])

        proofs: dict[str, RangeProof] = {}
        commitments: dict[str, Any] = {"asset": asset_commitment}
        for name, value in (("amount", amount), ("price", price)):
            low, high = self.bounds.for_field(name)
            commitment, proof, _ = prove_bounded(
                key, value, blindings[name], low, high, PI_DOMAIN + b":" + name.encode())
            commitments[name] = commitment
            proofs[name] = proof

        # tie the instruction to the quote the computing nodes actually opened
        binding_blinding = key.random_blinding()
        binding = key.commit(quote_key, binding_blinding)
        binding_proof = prove_opening(key, binding, quote_key, binding_blinding,
                                      PI_DOMAIN + b":quote")

        instruction = ZkPaymentInstruction(
            asset_commitment=commitments["asset"],
            amount_commitment=commitments["amount"],
            price_commitment=commitments["price"],
            payer_handle=payer_handle, payee_handle=payee_handle,
            deadline=deadline, nonce=nonce, range_proofs=proofs,
            quote_binding=binding, quote_proof=binding_proof,
            quorum_signature=None, quorum=tuple(quorum))

        # The computing nodes sign jointly, so no node can issue alone. The
        # instruction digest goes into the Fiat-Shamir transcript rather than
        # into the committed value: that is what binds the signature to *this*
        # instruction, so altering any field invalidates it.
        secret = (self.quorum_secret if self.quorum_secret is not None
                  else key.random_blinding())
        blinding = (self.quorum_blinding if self.quorum_blinding is not None
                    else key.random_blinding())
        shares = deal(key, secret, blinding, list(nodes), threshold)
        signature, transcript = joint_prove_opening(
            key, shares, list(quorum), _sign_context(instruction.digest(group)))
        signed = ZkPaymentInstruction(
            **{**instruction.__dict__, "quorum_signature": (signature, shares.commitment)})
        return signed, {"transcript": transcript, "blindings": blindings,
                        "quote_blinding": binding_blinding}


class SettlementVenue:
    """The pluggable side. Any DEX can run exactly this and nothing else."""

    def __init__(self, group: Group, key: Pedersen | None = None,
                 bounds: InstructionBounds | None = None,
                 quorum_key: Any | None = None):
        self.group = group
        self.key = key or Pedersen(group, b"qomm:zkpi:v1")
        self.bounds = bounds or InstructionBounds()
        # The quorum the venue trusts, fixed before any instruction arrives.
        # Without it the venue checked the signature against a commitment
        # carried *inside the instruction*, and the issuer generates that
        # commitment itself -- so anyone could deal themselves a quorum and
        # sign their own payment instruction with it. A venue built without one
        # still runs, for the fixtures, and says what it is not checking.
        self.quorum_key = quorum_key
        self._spent: set[bytes] = set()

    def verify(self, instruction: ZkPaymentInstruction, *, now: int
               ) -> tuple[bool, str]:
        key = self.key
        group = self.group
        if not now < instruction.deadline <= now + self.bounds.max_horizon:
            return False, "deadline outside the permitted horizon"
        if len(instruction.nonce) < 16:
            return False, "nonce too short to be a one-time value"
        for handle in (instruction.payer_handle, instruction.payee_handle):
            if not group.is_valid(handle):
                return False, "entity handle is not a group element"
        if group.encode(instruction.payer_handle) == group.encode(instruction.payee_handle):
            return False, "payer and payee are the same entity"

        for name in self.bounds.fields():
            proof = instruction.range_proofs.get(name)
            if proof is None:
                return False, f"{name} carries no range proof"
            commitment = getattr(instruction, f"{name}_commitment")
            low, high = self.bounds.for_field(name)
            if not verify_bounded(key, commitment, proof, low, high,
                                  PI_DOMAIN + b":" + name.encode()):
                return False, f"{name} not shown to lie in [{low}, {high}]"

        if not verify_opening(key, instruction.quote_binding, instruction.quote_proof,
                              PI_DOMAIN + b":quote"):
            return False, "instruction is not bound to a signed quote"

        if instruction.quorum_signature is None:
            return False, "no quorum signature"
        signature, commitment = instruction.quorum_signature
        if not group.is_valid(commitment):
            return False, "quorum key is not a group element"
        if self.quorum_key is None:
            return False, ("this venue trusts no quorum, so it cannot tell an "
                           "instruction signed by the computing nodes from one "
                           "signed by whoever wrote it; construct it with "
                           "quorum_key=")
        if group.encode(commitment) != group.encode(self.quorum_key):
            return False, "signed by a quorum this venue does not trust"
        # the digest is recomputed here, so a signature made for a different
        # instruction cannot be replayed onto this one
        if not verify_opening(key, commitment, signature,
                              _sign_context(instruction.digest(group))):
            return False, "quorum signature does not cover this instruction"

        tag = instruction.nullifier(group)
        if tag in self._spent:
            return False, "instruction already settled"
        return True, "ok"

    def settle(self, instruction: ZkPaymentInstruction, *, now: int) -> tuple[bool, str]:
        ok, reason = self.verify(instruction, now=now)
        if not ok:
            return False, reason
        self._spent.add(instruction.nullifier(self.group))
        return True, "settled"

    def spent(self) -> int:
        return len(self._spent)
