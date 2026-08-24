"""The commitment layer as a choice, so a different one can be measured.

`groups.py` already made the *group* pluggable, which covers every
discrete-logarithm scheme and no others. VOLE-based commitments are not group
elements at all --- a commitment is an information-theoretic MAC, and the
homomorphic operations are field arithmetic rather than scalar multiplications
--- so the seam has to move up from the group to the commitment.

    commit(value, blinding)     ->  Commitment
    add(a, b)                   ->  Commitment      (was group.mul)
    scale(c, k)                 ->  Commitment      (was group.point_pow)
    negate(c), zero(), encode(c), equal(a, b)
    scalar_modulus, random_scalar(), random_blinding()

Two implementations, and **they do not promise the same thing**, which is the
point of writing the difference down rather than hiding it behind an interface:

`PedersenScheme` is *publicly verifiable*. A commitment is a group element that
anybody can hold, combine and check, which is what `threshold_sigma` and the
quote proof need to convince a verifier who was not present.

`VoleScheme` is *designated verifier*. The prover holds `(x, M)` and the
verifier holds `(K, Delta)` with `M = K + Delta*x`; nothing is published, and
only the holder of `Delta` can check an opening. Making it publicly verifiable
is what VOLE-in-the-Head does (Baum et al., CRYPTO 2023), at about twice the
communication of the designated-verifier protocol --- and that transform is
**not implemented here**. What is implemented is the commitment underneath it,
so the cost of the homomorphic operations can be measured against Pedersen's.

Binding for the VOLE scheme is `1/|F|` per opening rather than computational,
and hiding is perfect given that `K` is uniform. Neither is a discrete-log
assumption, which is why the scheme is post-quantum and why there is no group
order for the MPC field to match.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Any, Protocol, Sequence, runtime_checkable

from .commit import Pedersen
from .groups import DOMAIN


@runtime_checkable
class CommitmentScheme(Protocol):
    """What a protocol in this package needs from a commitment scheme."""

    name: str
    publicly_verifiable: bool

    @property
    def scalar_modulus(self) -> int: ...

    def commit(self, value: int, blinding: int) -> Any: ...
    def random_blinding(self) -> int: ...
    def random_scalar(self) -> int: ...
    def add(self, a: Any, b: Any) -> Any: ...
    def scale(self, commitment: Any, scalar: int) -> Any: ...
    def negate(self, commitment: Any) -> Any: ...
    def zero(self) -> Any: ...
    def encode(self, commitment: Any) -> bytes: ...

    def equal(self, a: Any, b: Any) -> bool:
        return self.encode(a) == self.encode(b)


class PedersenScheme:
    """The scheme this repository already uses, behind the seam.

    Every operation is one or two scalar multiplications on the curve, which is
    where the cost is: `add` is a group multiplication and `scale` is a full
    scalar multiplication.
    """

    name = "pedersen"
    publicly_verifiable = True

    def __init__(self, key: Pedersen):
        self.key = key
        self.group = key.group

    @property
    def scalar_modulus(self) -> int:
        return self.group.order

    def commit(self, value: int, blinding: int):
        return self.key.commit(value, blinding)

    def random_blinding(self) -> int:
        return self.key.random_blinding()

    def random_scalar(self) -> int:
        return self.group.random_scalar()

    def add(self, a, b):
        return self.group.mul(a, b)

    def scale(self, commitment, scalar: int):
        return self.group.point_pow(commitment, scalar % self.group.order)

    def negate(self, commitment):
        return self.group.neg(commitment)

    def zero(self):
        return self.group.identity()

    def encode(self, commitment) -> bytes:
        return self.group.encode(commitment)

    def equal(self, a, b) -> bool:
        return self.encode(a) == self.encode(b)


@dataclass(frozen=True)
class VoleCommitment:
    """One MAC. `tag` is the prover's share; the verifier recomputes it.

    Carrying the value alongside the tag is what a prover holds anyway --- it
    has to open eventually --- and it keeps the homomorphic operations honest:
    combining commitments has to combine the values the same way, or the
    opening stops matching.
    """

    value: int
    tag: int


class VoleScheme:
    """A linearly homomorphic commitment from a VOLE correlation.

    `M = K + Delta*x` over a prime field. The prover holds `(x, M)`, the
    verifier holds `(K, Delta)`. Adding two commitments adds the values and the
    tags; scaling by a public constant scales both. Every operation is field
    arithmetic, which is the reason to measure it.

    This is the *designated-verifier* primitive. Section 7 of `BINDING.md` says
    what the public-verifiability transform costs and that it is not here.
    """

    name = "vole"
    publicly_verifiable = False

    # 2^127 - 1 is prime, so binding fails with probability about 2^-127 an
    # opening --- the same order as the curve, without the curve.
    DEFAULT_MODULUS = (1 << 127) - 1

    def __init__(self, modulus: int | None = None, delta: int | None = None,
                 label: bytes = b"qomm:vole:v1"):
        self.modulus = modulus or self.DEFAULT_MODULUS
        self.label = label
        # the verifier's secret. A prover that learned it could open to any
        # value, which is exactly the binding assumption.
        self._delta = delta if delta is not None else self.random_scalar()
        self._keys: dict[int, int] = {}
        self._next = 0

    @property
    def scalar_modulus(self) -> int:
        return self.modulus

    def random_scalar(self) -> int:
        return secrets.randbelow(self.modulus - 1) + 1

    def random_blinding(self) -> int:
        return self.random_scalar()

    def commit(self, value: int, blinding: int) -> VoleCommitment:
        """`blinding` is the verifier's key here, which is what makes it hide.

        The signature matches the Pedersen one so the protocols above do not
        have to know which scheme they are on. What differs is the meaning: the
        blinding is not a second exponent but the key the verifier holds.
        """
        key = blinding % self.modulus
        tag = (key + self._delta * value) % self.modulus
        return VoleCommitment(value % self.modulus, tag)

    def add(self, a: VoleCommitment, b: VoleCommitment) -> VoleCommitment:
        return VoleCommitment((a.value + b.value) % self.modulus,
                              (a.tag + b.tag) % self.modulus)

    def scale(self, commitment: VoleCommitment, scalar: int) -> VoleCommitment:
        k = scalar % self.modulus
        return VoleCommitment((commitment.value * k) % self.modulus,
                              (commitment.tag * k) % self.modulus)

    def negate(self, commitment: VoleCommitment) -> VoleCommitment:
        return VoleCommitment((-commitment.value) % self.modulus,
                              (-commitment.tag) % self.modulus)

    def zero(self) -> VoleCommitment:
        return VoleCommitment(0, 0)

    def encode(self, commitment: VoleCommitment) -> bytes:
        width = (self.modulus.bit_length() + 7) // 8
        return (commitment.value.to_bytes(width, "big")
                + commitment.tag.to_bytes(width, "big"))

    def equal(self, a: VoleCommitment, b: VoleCommitment) -> bool:
        return a.value == b.value and a.tag == b.tag

    # --- what only this scheme has -----------------------------------------

    def opens(self, commitment: VoleCommitment, value: int, key: int) -> bool:
        """The verifier's check, which needs Delta and so is not public."""
        return commitment.tag == (key + self._delta * value) % self.modulus

    def commitment_bytes(self) -> int:
        """What one commitment costs on the wire, for the comparison."""
        return 2 * ((self.modulus.bit_length() + 7) // 8)


def make_scheme(name: str, **kwargs) -> CommitmentScheme:
    """One place that knows the names, so a runner can take a flag."""
    if name == "pedersen":
        from .groups import make_group
        group = kwargs.pop("group", "ed25519")
        label = kwargs.pop("label", b"qomm:pedersen:v1")
        return PedersenScheme(Pedersen(make_group(group), label))
    if name == "vole":
        return VoleScheme(**kwargs)
    raise ValueError(f"unknown commitment scheme {name}; "
                     f"choose from ['pedersen', 'vole']")


# --- the second seam, which the first one turned out to need ---------------
#
# `CommitmentScheme` above is shaped like Pedersen: one commitment per value,
# combined by anyone who holds them. Writing the VOLE-in-the-Head strategy
# showed that shape does not fit, and the mismatch is not an implementation
# detail --- it is what the scheme is.
#
# A VOLEitH commitment is not per value. The prover commits to the whole vector
# at once (a hash of 2^depth * repeats leaf commitments) and publishes one
# correction per value against it; there is no object per value that a verifier
# can hold and scale on its own, because scaling happens against a `Delta` that
# does not exist until the proof is made. Forcing it through `commit/add/scale`
# would have meant either lying about what the object is or reconstructing the
# trees on every call.
#
# So the seam for a *publicly verifiable* comparison is one level up: commit to
# a vector, prove one public linear statement about it, verify from the proof
# alone. Pedersen implements it by delegating to `input_check`, which is what it
# already did; VOLEitH implements it natively. Same statement, same coefficient
# discipline, two schemes --- which is the only way the comparison means
# anything.


@runtime_checkable
class LinearProofScheme(Protocol):
    """Commit to a vector, prove one public linear combination of it."""

    name: str
    publicly_verifiable: bool
    post_quantum: bool

    def prove_linear(self, values: Sequence[int], context: bytes,
                     challenge_bits: int = 40) -> Any: ...
    def verify_linear(self, proof: Any, context: bytes,
                      challenge_bits: int = 40) -> tuple[bool, str]: ...
    def proof_bytes(self, proof: Any) -> int: ...
    def size_breakdown(self, proof: Any) -> dict[str, int]: ...


class PedersenLinearProof:
    """The stack's existing input check, behind the second seam.

    Binding is discrete log, so it is not post-quantum, and the field the MPC
    runs in has to hold the group order --- which is section 1 of `BINDING.md`
    and the reason the alternative is worth measuring at all.
    """

    name = "pedersen"
    publicly_verifiable = True
    post_quantum = False

    def __init__(self, key: Pedersen | None = None, value_bits: int = 32):
        from .groups import make_group
        self.scheme = PedersenScheme(key or Pedersen(make_group("ed25519"),
                                                     b"qomm:pedersen:v1"))
        self.value_bits = value_bits

    # The challenge stands in for the value a deployment opens once every input
    # has been read. It is not optional and it is not derivable from the
    # commitments --- `artifacts/coefficient_timing_flaw.json` is what happens
    # when it is.
    CHALLENGE = 0x9E3779B97F4A7C15

    def prove_linear(self, values, context, challenge_bits: int = 40):
        from . import input_check
        blindings = [self.scheme.random_blinding() for _ in values]
        return input_check.build(self.scheme, list(values), blindings, context,
                                 self.CHALLENGE, challenge_bits=challenge_bits,
                                 value_bits=self.value_bits)

    def verify_linear(self, proof, context, challenge_bits: int = 40):
        from . import input_check
        return input_check.verify(self.scheme, proof, context, self.CHALLENGE)

    def size_breakdown(self, proof) -> dict[str, int]:
        point = len(self.scheme.encode(proof.commitments[0]))
        width = (self.scheme.scalar_modulus.bit_length() + 7) // 8
        return {
            "commitments": len(proof.commitments) * point,
            "mask_commitments": len(proof.mask_commitments) * point,
            "openings": len(proof.openings) * width,
            "opening_blindings": len(proof.opening_blindings) * width,
        }

    def proof_bytes(self, proof) -> int:
        return sum(self.size_breakdown(proof).values())


class VoleInTheHeadLinearProof:
    """The same statement from a random oracle and nothing else.

    No group, so nothing for the MPC field to match; symmetric primitives only,
    so post-quantum; and one opening per commitment, which the prover enforces
    rather than documents.
    """

    name = "voleith"
    publicly_verifiable = True
    post_quantum = True

    DEFAULT_MODULUS = (1 << 127) - 1

    def __init__(self, modulus: int | None = None, depth: int | None = None,
                 repeats: int | None = None):
        from . import voleith
        self._v = voleith
        self.modulus = modulus or self.DEFAULT_MODULUS
        self.depth = depth or voleith.DEFAULT_DEPTH
        self.repeats = repeats or voleith.DEFAULT_REPEATS

    def prove_linear(self, values, context, challenge_bits: int = 40):
        prover = self._v.Prover(self.modulus, self.depth, self.repeats)
        root, correction, _ = prover.commit(list(values))
        coeffs = self._v.coefficients(root, correction, context, self.modulus,
                                      challenge_bits, len(values))
        return prover.prove(coeffs, context)

    def verify_linear(self, proof, context, challenge_bits: int = 40):
        coeffs = self._v.coefficients(proof.root, proof.witness_correction, context,
                                      self.modulus, challenge_bits, proof.n_values)
        return self._v.verify(proof, coeffs, context)

    def size_breakdown(self, proof) -> dict[str, int]:
        return proof.size_breakdown()

    def proof_bytes(self, proof) -> int:
        return proof.size_bytes()


def make_linear_proof(name: str, **kwargs) -> LinearProofScheme:
    if name == "pedersen":
        return PedersenLinearProof(**kwargs)
    if name == "voleith":
        return VoleInTheHeadLinearProof(**kwargs)
    raise ValueError(f"unknown linear-proof scheme {name}; "
                     f"choose from ['pedersen', 'voleith']")
