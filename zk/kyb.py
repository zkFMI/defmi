"""KYB: anonymous legal-entity credentials with entity-level limits.

The proposal protects a legal entity, not a wallet. Two things follow.

First, the protected unit has to survive an entity opening more wallets, so the
limit is keyed on a scope nullifier derived from the entity secret. Every wallet
of one entity produces the same nullifier inside a scope, so counting is exact,
while the nullifier reveals nothing about which entity it is and does not carry
across scopes.

Second, business attributes (jurisdiction, entity type, collateral tier) have to
be usable as gates without revealing them. Proving a predicate about a hidden
registry entry inside the one-out-of-N proof would cost a proof per entry. This
module instead uses cohort registries: the issuer publishes one signed registry
per satisfied predicate and enrols an entity in every cohort it qualifies for,
so membership in the "tier at least 3" registry *is* the attribute proof and
costs the prover nothing extra.

The trade is explicit. The anonymity set becomes the cohort rather than the
whole population, and an observer who sees the same scope nullifier in two
cohort presentations learns those two cohorts share an entity. Re-randomisable
credentials (BBS+ and its relatives) avoid both, at the cost of a pairing-based
implementation; that comparison is in SURVEY.md.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from .groups import DOMAIN, Group
from .or_dleq import OrDleqProver, OrDleqVerifier, Proof, Statement


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


@dataclass(frozen=True)
class BusinessAttributes:
    jurisdiction: str
    entity_type: str            # e.g. "bank", "broker", "fund"
    collateral_tier: int        # monotone: a higher tier satisfies every lower gate

    def cohorts(self, max_tier: int) -> tuple[str, ...]:
        """Every cohort this entity qualifies for, including all lower tiers."""
        return tuple(
            cohort_id(self.jurisdiction, self.entity_type, tier)
            for tier in range(1, min(self.collateral_tier, max_tier) + 1)
        )


def cohort_id(jurisdiction: str, entity_type: str, min_tier: int) -> str:
    return f"{jurisdiction}/{entity_type}/tier>={min_tier}"


@dataclass(frozen=True)
class KybCredential:
    control_group_id: str          # the legal entity / control group
    secret_scalar: int
    public_point: Any
    attributes: BusinessAttributes
    cohorts: tuple[str, ...]


@dataclass(frozen=True)
class SignedCohortRegistry:
    cohort: str
    registry_epoch: int
    expires_at: int
    points: tuple
    issuer_public_key_hex: str
    registry_id: str
    signature_hex: str

    def signed_body(self, group: Group) -> dict:
        return {
            "cohort": self.cohort,
            "registry_epoch": self.registry_epoch,
            "expires_at": self.expires_at,
            "points": [group.encode(p).hex() for p in self.points],
            "issuer_public_key_hex": self.issuer_public_key_hex,
        }


@dataclass(frozen=True)
class KybPresentation:
    cohort: str
    registry_id: str
    scope: str
    context_hash: str
    proof: Proof


class KybIssuer:
    """Enrols legal entities and publishes one signed registry per cohort."""

    def __init__(self, group: Group, private_key: Ed25519PrivateKey | None = None,
                 max_tier: int = 5):
        self.group = group
        self._private_key = private_key or Ed25519PrivateKey.generate()
        self.public_key = self._private_key.public_key()
        self.max_tier = max_tier
        self._enrolled: dict[str, KybCredential] = {}

    def enroll(self, control_group_id: str, attributes: BusinessAttributes) -> KybCredential:
        if control_group_id in self._enrolled:
            raise ValueError(f"control group {control_group_id} already enrolled")
        secret = self.group.random_scalar()
        credential = KybCredential(
            control_group_id=control_group_id,
            secret_scalar=secret,
            public_point=self.group.base_pow(secret),
            attributes=attributes,
            cohorts=attributes.cohorts(self.max_tier),
        )
        self._enrolled[control_group_id] = credential
        return credential

    def publish(self, cohort: str, registry_epoch: int, expires_at: int) -> SignedCohortRegistry:
        members = [c for c in self._enrolled.values() if cohort in c.cohorts]
        if not members:
            raise ValueError(f"no entity qualifies for {cohort}")
        points = tuple(sorted((c.public_point for c in members),
                              key=lambda p: self.group.encode(p)))
        public_key_hex = self.public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        body = {
            "cohort": cohort, "registry_epoch": registry_epoch, "expires_at": expires_at,
            "points": [self.group.encode(p).hex() for p in points],
            "issuer_public_key_hex": public_key_hex,
        }
        registry_id = hashlib.sha256(DOMAIN + b":kyb-registry:" + _canonical(body)).hexdigest()
        signature = self._private_key.sign(
            _canonical({**body, "registry_id": registry_id})).hex()
        return SignedCohortRegistry(cohort, registry_epoch, expires_at, points,
                                    public_key_hex, registry_id, signature)

    def sign_policy_digest(self, digest: bytes) -> bytes:
        """Attribution hook: a bad policy stays traceable to an enrolled entity."""
        return self._private_key.sign(digest)


def verify_registry(group: Group, registry: SignedCohortRegistry,
                    trusted_issuer: Ed25519PublicKey, now: int) -> tuple[bool, str]:
    expected_key = trusted_issuer.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    if registry.issuer_public_key_hex != expected_key:
        return False, "registry is not from the trusted issuer"
    if registry.expires_at <= now:
        return False, "registry epoch has expired"
    if len(set(group.encode(p) for p in registry.points)) != len(registry.points):
        return False, "duplicate registry entries"
    if any(not group.is_valid(p) for p in registry.points):
        return False, "registry contains an invalid point"
    body = registry.signed_body(group)
    expected_id = hashlib.sha256(DOMAIN + b":kyb-registry:" + _canonical(body)).hexdigest()
    if expected_id != registry.registry_id:
        return False, "registry id does not match its contents"
    try:
        trusted_issuer.verify(bytes.fromhex(registry.signature_hex),
                              _canonical({**body, "registry_id": registry.registry_id}))
    except (InvalidSignature, ValueError):
        return False, "bad issuer signature"
    return True, "ok"


def _statement(group: Group, registry: SignedCohortRegistry, scope: str,
               context: Mapping[str, Any]) -> tuple[Statement, str]:
    context_hash = hashlib.sha256(
        DOMAIN + b":kyb-context:" + _canonical(dict(context))).hexdigest()
    return Statement(registry.registry_id, registry.points, scope, context_hash), context_hash


def present(group: Group, credential: KybCredential, registry: SignedCohortRegistry,
            *, scope: str, context: Mapping[str, Any]) -> KybPresentation:
    if registry.cohort not in credential.cohorts:
        raise ValueError("credential does not qualify for this cohort")
    encoded = [group.encode(p) for p in registry.points]
    try:
        index = encoded.index(group.encode(credential.public_point))
    except ValueError as exc:
        raise ValueError("credential is not in this registry") from exc
    statement, context_hash = _statement(group, registry, scope, context)
    proof = OrDleqProver(group).prove(statement, credential.secret_scalar, index)
    return KybPresentation(registry.cohort, registry.registry_id, scope, context_hash, proof)


def verify_presentation(group: Group, presentation: KybPresentation,
                        registry: SignedCohortRegistry, trusted_issuer: Ed25519PublicKey,
                        *, scope: str, context: Mapping[str, Any], now: int,
                        required_cohort: str) -> tuple[bool, str]:
    ok, reason = verify_registry(group, registry, trusted_issuer, now)
    if not ok:
        return False, reason
    if registry.cohort != required_cohort or presentation.cohort != required_cohort:
        return False, "presentation is for a different cohort than the venue requires"
    if presentation.registry_id != registry.registry_id:
        return False, "presentation is bound to a different registry epoch"
    statement, context_hash = _statement(group, registry, scope, context)
    if presentation.scope != scope or presentation.context_hash != context_hash:
        return False, "presentation is bound to a different scope or context"
    if not OrDleqVerifier(group).verify(statement, presentation.proof):
        return False, "membership proof failed"
    return True, "ok"


@dataclass
class EntityLimits:
    """Per-entity caps the venue enforces, keyed on the scope nullifier.

    The numbers are a venue's to set and these are a default. What they should
    be set against is measured in `artifacts/probe_budget.json`: reading a
    maker's inventory off its own two-sided quotes gives a correlation of about
    0.53 that does not grow with the budget, and a confidence that does --- a
    majority of seeds are distinguishable from zero at 24 probes and nearly all
    at 96. So a cap does not prevent the attack; it sets how often an entity can
    refresh the picture. 60 an epoch sits between those two figures, which is a
    choice rather than a derivation, and a venue that cares should derive it.
    """

    max_requests: int = 60
    max_probe_lots: int = 2_000
    max_epsilon: float = 1.0


class EntityRateLimiter:
    """Counts against the legal entity, not the wallet.

    The nullifier is identical for every wallet the entity controls inside a
    scope, so opening more wallets buys no extra allowance. That is the whole
    point of putting the limit here rather than on an address.
    """

    def __init__(self, group: Group, limits: EntityLimits | None = None):
        self.group = group
        self.limits = limits or EntityLimits()
        self._requests: dict[tuple[bytes, int], int] = {}
        self._lots: dict[tuple[bytes, int], int] = {}
        self._epsilon: dict[tuple[bytes, int], float] = {}

    def _key(self, nullifier, epoch: int) -> tuple[bytes, int]:
        return (self.group.encode(nullifier), epoch)

    def allow_request(self, nullifier, epoch: int, lots: int = 0) -> tuple[bool, str]:
        key = self._key(nullifier, epoch)
        if self._requests.get(key, 0) + 1 > self.limits.max_requests:
            return False, "entity request cap reached for this epoch"
        if self._lots.get(key, 0) + lots > self.limits.max_probe_lots:
            return False, "entity probing volume cap reached for this epoch"
        self._requests[key] = self._requests.get(key, 0) + 1
        self._lots[key] = self._lots.get(key, 0) + lots
        return True, "ok"

    def spend_epsilon(self, nullifier, epoch: int, epsilon: float) -> tuple[bool, str]:
        key = self._key(nullifier, epoch)
        if self._epsilon.get(key, 0.0) + epsilon > self.limits.max_epsilon + 1e-12:
            return False, "entity privacy budget exhausted for this epoch"
        self._epsilon[key] = self._epsilon.get(key, 0.0) + epsilon
        return True, "ok"

    def usage(self, nullifier, epoch: int) -> dict:
        key = self._key(nullifier, epoch)
        return {"requests": self._requests.get(key, 0),
                "lots": self._lots.get(key, 0),
                "epsilon": self._epsilon.get(key, 0.0)}


def scope_nullifier(group: Group, credential: KybCredential, scope: str):
    """What the venue counts against. Equal across wallets, unequal across scopes."""
    return group.point_pow(group.hash_to_point(scope.encode()), credential.secret_scalar)
