"""One-out-of-N proof of equality of discrete logarithms, over a pluggable group.

Statement proved, for a signed registry of public points y_0..y_{N-1}, a scope
generator h and a nullifier n:

    I know x and an index j such that  y_j = g^x  and  n = h^x,
    without revealing j.

This is the Cramer-Damgard-Schoenmakers OR composition of Chaum-Pedersen, made
non-interactive by Fiat-Shamir. It is the same protocol the research MVP
shipped; only the arithmetic underneath changes.

Cost is O(N) group operations for both prover and verifier: two commitments per
registry entry. Logarithmic-size alternatives (Groth-Kohlweiss and its
descendants) shrink the proof to O(log N) but need O(N log N) prover work, so
they win on bandwidth, not on proving time. See SURVEY.md.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any, Sequence

from .groups import DOMAIN, Group, make_group


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


@dataclass(frozen=True)
class Statement:
    """Everything the verifier already knows."""

    registry_id: str
    points: tuple            # public points of every enrolled control group
    scope: str
    context_hash: str


@dataclass(frozen=True)
class Proof:
    nullifier: Any
    challenges: tuple[int, ...]
    responses: tuple[int, ...]

    def size_bytes(self, group: Group) -> int:
        scalar_bytes = (group.order.bit_length() + 7) // 8
        return len(group.encode(self.nullifier)) + 2 * len(self.challenges) * scalar_bytes


class OrDleqProver:
    def __init__(self, group: Group):
        self.group = group

    def _challenge(self, statement: Statement, nullifier, commit_g: Sequence, commit_h: Sequence) -> int:
        digest = hashlib.sha512(DOMAIN + b":fs:")
        digest.update(_canonical({"registry_id": statement.registry_id,
                                  "scope": statement.scope,
                                  "context_hash": statement.context_hash}))
        for point in (nullifier, *statement.points, *commit_g, *commit_h):
            encoded = self.group.encode(point)
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
        return int.from_bytes(digest.digest(), "big") % self.group.order

    def prove(self, statement: Statement, secret: int, index: int) -> Proof:
        group = self.group
        order = group.order
        h_scope = group.hash_to_point(statement.scope.encode())
        nullifier = group.point_pow(h_scope, secret)

        n = len(statement.points)
        challenges = [0] * n
        responses = [0] * n
        commit_g: list[Any] = [None] * n
        commit_h: list[Any] = [None] * n

        witness_nonce = group.random_scalar()
        for position, point in enumerate(statement.points):
            if position == index:
                commit_g[position] = group.base_pow(witness_nonce)
                commit_h[position] = group.point_pow(h_scope, witness_nonce)
                continue
            # simulate: pick the response and challenge first, derive the commitment
            challenges[position] = group.random_scalar()
            responses[position] = group.random_scalar()
            commit_g[position] = group.base_commit(responses[position], point, challenges[position])
            commit_h[position] = group.commit(
                h_scope, responses[position], nullifier, challenges[position])

        total = self._challenge(statement, nullifier, commit_g, commit_h)
        challenges[index] = (total - sum(challenges)) % order
        responses[index] = (witness_nonce + challenges[index] * secret) % order
        return Proof(nullifier, tuple(challenges), tuple(responses))


class OrDleqVerifier:
    def __init__(self, group: Group):
        self.group = group
        self._prover = OrDleqProver(group)

    def verify(self, statement: Statement, proof: Proof) -> bool:
        group = self.group
        n = len(statement.points)
        if len(proof.challenges) != n or len(proof.responses) != n:
            return False
        if any(not 0 <= value < group.order for value in (*proof.challenges, *proof.responses)):
            return False
        if not group.is_valid(proof.nullifier):
            return False
        h_scope = group.hash_to_point(statement.scope.encode())
        commit_g = []
        commit_h = []
        for point, challenge, response in zip(statement.points, proof.challenges, proof.responses):
            commit_g.append(group.base_commit(response, point, challenge))
            commit_h.append(group.commit(h_scope, response, proof.nullifier, challenge))
        expected = self._prover._challenge(statement, proof.nullifier, commit_g, commit_h)
        return sum(proof.challenges) % group.order == expected


def build_registry(group: Group, size: int, seed: int | None = None) -> tuple[Statement, list[int]]:
    """Deterministic registry fixture: returns the statement and every secret."""
    rng = secrets.SystemRandom() if seed is None else _SeededRandom(seed)
    secrets_list = []
    points = []
    for _ in range(size):
        scalar = rng.randrange(1, group.order)
        secrets_list.append(scalar)
        points.append(group.base_pow(scalar))
    statement = Statement(
        registry_id="fixture", points=tuple(points), scope="qomm:quote:v1",
        context_hash=hashlib.sha256(b"context").hexdigest(),
    )
    return statement, secrets_list


class _SeededRandom:
    def __init__(self, seed: int):
        import random

        self._rng = random.Random(seed)

    def randrange(self, low: int, high: int) -> int:
        return self._rng.randrange(low, high)


def prove_and_verify(group_name: str, size: int, index: int = 0, seed: int = 7):
    group = make_group(group_name)
    statement, secret_scalars = build_registry(group, size, seed)
    prover = OrDleqProver(group)
    verifier = OrDleqVerifier(group)
    proof = prover.prove(statement, secret_scalars[index], index)
    return group, statement, proof, verifier.verify(statement, proof)
