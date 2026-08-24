"""Zero-knowledge audit of a market maker's price policy.

The design gives the market maker exactly the privacy the proposal promises: the
price rule, the inventory and the size limit stay secret. That privacy is worth
nothing to the venue unless the hidden policy can still be shown to be
well-formed, and worth nothing to the user unless the policy the audit covers is
the policy the MPC actually evaluated. Both are handled here.

    well-formedness   every field lies in the band the venue published, proved
                      by Pedersen commitments plus range proofs
    binding           the shares the computing nodes hold open to the committed
                      values, proved by Pedersen verifiable secret sharing
    accountability    the policy is signed under a KYB credential, so a bad
                      policy is attributable to a legal entity without the
                      policy or the entity becoming public

These used not to be the shares MP-SPDZ consumes, and that was the gap
`BINDING.md` opens with: the circuit read additive shares over the integers
while this committed to Shamir shares over the group's scalar field, so a maker
could have one policy audited and a different one computed. **`zk/binding.py`
closes it**, by the only route that needs no new cryptography --- the same call
commits and deals, and the MPC runs over the field a share is an element of, so
the two sharings are one sharing rather than two that agree. Measured at 1.00x
rounds and 2.00x traffic, and run end to end in `scripts/run_binding_chain.py`.

What this module still is on its own: the range proofs and the KYB binding. Use
`BindingDealer` for anything that has to reach the circuit.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .commit import (
    OpeningProof, Pedersen, RangeProof, prove_bounded, prove_opening,
    verify_bounded, verify_opening,
)
from .groups import DOMAIN, Group

# Field name -> (low, high) bounds the venue publishes. A policy outside these
# is rejected without anyone learning what it actually said.
@dataclass(frozen=True)
class PolicyBounds:
    half: tuple[int, int] = (1, 200)              # half spread, ticks
    slope: tuple[int, int] = (0, 16)              # per-lot price impact
    invcoef: tuple[int, int] = (0, 8)             # inventory skew coefficient
    maxqty: tuple[int, int] = (1, 1000)           # lots the maker will fill
    inv: tuple[int, int] = (-4000, 4000)          # signed inventory
    mid_band: int = 2000                          # ticks around the public reference

    def for_field(self, name: str, ref_mid: int) -> tuple[int, int]:
        if name == "mid":
            return (ref_mid - self.mid_band, ref_mid + self.mid_band)
        return getattr(self, name)

    def audited_fields(self) -> tuple[str, ...]:
        return ("mid", "half", "slope", "invcoef", "inv", "maxqty")


@dataclass(frozen=True)
class PolicyShare:
    """One computing node's share of one field, with its blinding share."""

    party: int
    value_share: int
    blinding_share: int


@dataclass(frozen=True)
class FieldCommitment:
    """Pedersen commitment to a field plus the VSS coefficient commitments."""

    commitment: Any
    coefficient_commitments: tuple


@dataclass(frozen=True)
class PolicyAudit:
    ref_mid: int
    now_t: int
    expiry: int
    fields: Mapping[str, FieldCommitment]
    range_proofs: Mapping[str, RangeProof]
    active_proof: Any                     # bit proof that `active` is 0 or 1
    active_commitment: Any
    entity_signature: bytes               # binds the audit to a KYB credential
    entity_nullifier: Any


class PolicyCommitter:
    """Commits a policy, shares it verifiably, and proves it is in range."""

    def __init__(self, group: Group, bounds: PolicyBounds | None = None,
                 label: bytes = b"qomm:policy:v1"):
        self.group = group
        self.key = Pedersen(group, label)
        self.bounds = bounds or PolicyBounds()

    # --- verifiable secret sharing ---------------------------------------
    def share(self, value: int, blinding: int, n_parties: int, threshold: int
              ) -> tuple[FieldCommitment, list[PolicyShare]]:
        """Pedersen VSS: shares that every node can check against the commitment."""
        group = self.group
        order = group.order
        value_poly = [value % order] + [group.random_scalar() for _ in range(threshold)]
        blind_poly = [blinding % order] + [group.random_scalar() for _ in range(threshold)]
        coefficient_commitments = tuple(
            self.key.commit(value_poly[k], blind_poly[k]) for k in range(threshold + 1))
        shares = []
        for party in range(1, n_parties + 1):
            v = sum(value_poly[k] * pow(party, k, order) for k in range(threshold + 1)) % order
            b = sum(blind_poly[k] * pow(party, k, order) for k in range(threshold + 1)) % order
            shares.append(PolicyShare(party, v, b))
        return FieldCommitment(coefficient_commitments[0], coefficient_commitments), shares

    def verify_share(self, share: PolicyShare, commitment: FieldCommitment) -> bool:
        """A node accepts its share only if it opens against the public commitments."""
        group = self.group
        expected = group.identity()
        for k, coefficient in enumerate(commitment.coefficient_commitments):
            expected = group.mul(expected, group.point_pow(coefficient, pow(share.party, k, group.order)))
        actual = self.key.commit(share.value_share, share.blinding_share)
        return group.encode(actual) == group.encode(expected)

    # --- the audit itself -------------------------------------------------
    def audit(self, policy: Mapping[str, int], *, ref_mid: int, now_t: int,
              n_parties: int, threshold: int, entity_nullifier: Any,
              entity_signer=None) -> tuple[PolicyAudit, dict[str, list[PolicyShare]], dict[str, int]]:
        group = self.group
        commitments: dict[str, FieldCommitment] = {}
        range_proofs: dict[str, RangeProof] = {}
        all_shares: dict[str, list[PolicyShare]] = {}
        blindings: dict[str, int] = {}

        context = self._context(ref_mid, now_t, policy["expiry"], entity_nullifier)
        for name in self.bounds.audited_fields():
            low, high = self.bounds.for_field(name, ref_mid)
            value = policy[name]
            blinding = self.key.random_blinding()
            blindings[name] = blinding
            commitment, proof, _ = prove_bounded(
                self.key, value, blinding, low, high, context + b":" + name.encode())
            field_commitment, shares = self.share(value, blinding, n_parties, threshold)
            # the VSS constant term must be the very commitment the range proof covers
            assert group.encode(field_commitment.commitment) == group.encode(commitment)
            commitments[name] = field_commitment
            range_proofs[name] = proof
            all_shares[name] = shares

        active_blinding = self.key.random_blinding()
        from .commit import prove_bit
        active_commitment = self.key.commit(policy["active"], active_blinding)
        active_proof = prove_bit(self.key, active_commitment, policy["active"],
                                 active_blinding, context + b":active")
        blindings["active"] = active_blinding

        signature = b""
        if entity_signer is not None:
            signature = entity_signer(self._digest(commitments, active_commitment, context))

        audit = PolicyAudit(
            ref_mid=ref_mid, now_t=now_t, expiry=policy["expiry"],
            fields=commitments, range_proofs=range_proofs,
            active_proof=active_proof, active_commitment=active_commitment,
            entity_signature=signature, entity_nullifier=entity_nullifier,
        )
        return audit, all_shares, blindings

    def _context(self, ref_mid: int, now_t: int, expiry: int, nullifier: Any) -> bytes:
        digest = hashlib.sha256(DOMAIN + b":policy-ctx:")
        for part in (ref_mid, now_t, expiry):
            digest.update(int(part).to_bytes(16, "big", signed=True))
        digest.update(self.group.encode(nullifier))
        return digest.digest()

    def _digest(self, commitments: Mapping[str, FieldCommitment], active_commitment,
                context: bytes) -> bytes:
        digest = hashlib.sha256(DOMAIN + b":policy-digest:" + context)
        for name in sorted(commitments):
            digest.update(name.encode())
            for coefficient in commitments[name].coefficient_commitments:
                digest.update(self.group.encode(coefficient))
        digest.update(self.group.encode(active_commitment))
        return digest.digest()


class PolicyAuditor:
    """The venue side: accepts a policy only if the hidden values are legal."""

    def __init__(self, group: Group, bounds: PolicyBounds | None = None,
                 label: bytes = b"qomm:policy:v1"):
        self.group = group
        self.key = Pedersen(group, label)
        self.bounds = bounds or PolicyBounds()
        self._committer = PolicyCommitter(group, bounds, label)

    def verify(self, audit: PolicyAudit, *, now_t: int, ref_mid: int,
               max_horizon: int, entity_verifier=None) -> tuple[bool, str]:
        group = self.group
        if audit.ref_mid != ref_mid or audit.now_t != now_t:
            return False, "audit is not bound to the current reference state"
        if not now_t < audit.expiry <= now_t + max_horizon:
            return False, "expiry outside the permitted horizon"
        context = self._committer._context(ref_mid, now_t, audit.expiry, audit.entity_nullifier)

        for name in self.bounds.audited_fields():
            if name not in audit.fields or name not in audit.range_proofs:
                return False, f"missing proof for {name}"
            low, high = self.bounds.for_field(name, ref_mid)
            commitment = audit.fields[name].commitment
            if group.encode(commitment) != group.encode(
                    audit.fields[name].coefficient_commitments[0]):
                return False, f"{name}: commitment does not match the sharing"
            if not verify_bounded(self.key, commitment, audit.range_proofs[name],
                                  low, high, context + b":" + name.encode()):
                return False, f"{name}: value outside [{low}, {high}]"

        from .commit import verify_bit
        if not verify_bit(self.key, audit.active_commitment, audit.active_proof,
                          context + b":active"):
            return False, "active flag is not a bit"

        if entity_verifier is not None:
            digest = self._committer._digest(audit.fields, audit.active_commitment, context)
            if not entity_verifier(digest, audit.entity_signature):
                return False, "policy is not signed by the KYB credential"
        return True, "ok"

    def verify_node_share(self, share: PolicyShare, commitment: FieldCommitment) -> bool:
        return self._committer.verify_share(share, commitment)


def reconstruct(group: Group, shares: Sequence[PolicyShare], threshold: int) -> int:
    """Lagrange interpolation at zero, for tests and for the reveal path."""
    order = group.order
    chosen = list(shares)[: threshold + 1]
    total = 0
    for i, share in enumerate(chosen):
        numerator = 1
        denominator = 1
        for j, other in enumerate(chosen):
            if i == j:
                continue
            numerator = (numerator * (-other.party)) % order
            denominator = (denominator * (share.party - other.party)) % order
        total = (total + share.value_share * numerator * pow(denominator, -1, order)) % order
    return total
