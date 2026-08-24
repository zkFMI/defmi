"""Prime-order group backends for the sigma protocols, one per optimisation step.

Every backend implements the same interface, so the 1-out-of-N OR proof is
written once and the speed-up of each step can be attributed separately:

    modp_naive   RFC 3526 group 14, inverse by Fermat  -- what the MVP shipped
    modp_inv     same group, inverse by extended Euclid
    modp_negexp  same group, y^-c computed as y^(Q-c)  -- no inverse at all
    modp_multiexp same group, one interleaved two-base exponentiation
    ed25519      libsodium's prime-order Ed25519 group

The single operation the proof actually needs is

    commit(base, s, point, c) = base^s * point^(-c)

so that is what each backend specialises. Everything else is bookkeeping.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Protocol

# RFC 3526 MODP group 14. P is a safe prime, Q=(P-1)/2, and G=2 generates the
# prime-order quadratic-residue subgroup. Roughly 112-bit classical security.
MODP_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFF"
    "FFFFFFFF",
    16,
)
MODP_Q = (MODP_P - 1) // 2
MODP_G = 2

DOMAIN = b"QOMM:ZK:v1"


class Group(Protocol):
    name: str
    order: int
    security_bits: int

    def random_scalar(self) -> int: ...
    def base_pow(self, scalar: int): ...
    def point_pow(self, point, scalar: int): ...
    def commit(self, base, s: int, point, c: int): ...
    def base_commit(self, s: int, point, c: int): ...
    def hash_to_point(self, label: bytes): ...
    def encode(self, point) -> bytes: ...
    def decode(self, raw: bytes): ...
    def is_valid(self, point) -> bool: ...
    def mul(self, a, b): ...
    def neg(self, a): ...
    def identity(self): ...


class _ModpBase:
    """Shared plumbing for the RFC 3526 backends."""

    order = MODP_Q
    security_bits = 112

    def random_scalar(self) -> int:
        return secrets.randbelow(MODP_Q - 1) + 1

    def base_pow(self, scalar: int) -> int:
        return pow(MODP_G, scalar, MODP_P)

    def point_pow(self, point: int, scalar: int) -> int:
        return pow(point, scalar, MODP_P)

    def base_commit(self, s: int, point: int, c: int) -> int:
        return self.commit(MODP_G, s, point, c)

    def hash_to_point(self, label: bytes) -> int:
        counter = 0
        while True:
            digest = hashlib.sha256(DOMAIN + b":h2p:" + label + counter.to_bytes(4, "big")).digest()
            candidate = pow(int.from_bytes(digest, "big") % MODP_P, 2, MODP_P)
            if candidate not in (0, 1, MODP_G):
                return candidate
            counter += 1

    def encode(self, point: int) -> bytes:
        return point.to_bytes(256, "big")

    def decode(self, raw: bytes) -> int:
        """Back to a point, rejecting anything that is not one.

        A transcript that records points it cannot parse is not a transcript.
        Attribution of a faulty partial is supposed to be something any observer
        can perform from the published record, and that needs the record to
        round-trip; validation is here rather than at the caller so a malformed
        entry cannot be mistaken for a well-formed one that simply fails a check.
        """
        if len(raw) != 256:
            raise ValueError(f"a point is 256 bytes, got {len(raw)}")
        point = int.from_bytes(raw, "big")
        if not self.is_valid(point):
            raise ValueError("not a point of the prime-order subgroup")
        return point

    def is_valid(self, point: int) -> bool:
        return isinstance(point, int) and 1 < point < MODP_P - 1 and pow(point, MODP_Q, MODP_P) == 1

    def mul(self, a: int, b: int) -> int:
        return (a * b) % MODP_P

    def neg(self, a: int) -> int:
        return pow(a, -1, MODP_P)

    def identity(self) -> int:
        return 1


class ModpNaive(_ModpBase):
    """The MVP's original arithmetic: modular inverse by Fermat's little theorem.

    ``pow(x, P-2, P)`` is a full 2048-bit exponentiation. It is used twice per
    simulated branch, which is where most of the original proving time went.
    """

    name = "modp_naive"

    def commit(self, base: int, s: int, point: int, c: int) -> int:
        return (pow(base, s, MODP_P) * pow(pow(point, c, MODP_P), MODP_P - 2, MODP_P)) % MODP_P


class ModpInverse(_ModpBase):
    """Same group, inverse by extended Euclid instead of Fermat."""

    name = "modp_inv"

    def commit(self, base: int, s: int, point: int, c: int) -> int:
        return (pow(base, s, MODP_P) * pow(pow(point, c, MODP_P), -1, MODP_P)) % MODP_P


class ModpNegExp(_ModpBase):
    """Same group, no inversion at all.

    The subgroup has order Q, so point^(-c) = point^(Q-c) and the inversion
    disappears into the exponent that was going to be computed anyway.
    """

    name = "modp_negexp"

    def commit(self, base: int, s: int, point: int, c: int) -> int:
        return (pow(base, s, MODP_P) * pow(point, (MODP_Q - c) % MODP_Q, MODP_P)) % MODP_P


class ModpMultiexp(_ModpBase):
    """Same group, one interleaved two-base exponentiation instead of two.

    Squarings are shared between the two bases, so the cost drops from two full
    exponentiations to one square-and-multiply pass with a four-entry table.
    """

    name = "modp_multiexp"

    def commit(self, base: int, s: int, point: int, c: int) -> int:
        other = (MODP_Q - c) % MODP_Q
        table = (1, base % MODP_P, point % MODP_P, (base * point) % MODP_P)
        bits = max(s.bit_length(), other.bit_length())
        result = 1
        for index in range(bits - 1, -1, -1):
            result = (result * result) % MODP_P
            selector = ((s >> index) & 1) | (((other >> index) & 1) << 1)
            if selector:
                result = (result * table[selector]) % MODP_P
        return result


class Ed25519Group:
    """libsodium's prime-order Ed25519 group.

    Same sigma protocol, a 255-bit group instead of a 2048-bit one. This is the
    step that changes the cost by orders of magnitude, and it raises the security
    level at the same time (about 126 bits against about 112).
    """

    name = "ed25519"
    # l = 2^252 + 27742317777372353535851937790883648493
    order = 2 ** 252 + 27742317777372353535851937790883648493
    security_bits = 126

    def __init__(self) -> None:
        from nacl import bindings  # imported lazily so the MODP backends stay dependency-free

        self._b = bindings

    def random_scalar(self) -> int:
        return int.from_bytes(
            self._b.crypto_core_ed25519_scalar_reduce(secrets.token_bytes(64)), "little")

    def _scalar_bytes(self, scalar: int) -> bytes:
        return (scalar % self.order).to_bytes(32, "little")

    def base_pow(self, scalar: int) -> bytes:
        # libsodium refuses to return the neutral element, so zero is handled here
        if scalar % self.order == 0:
            return self.identity()
        return self._b.crypto_scalarmult_ed25519_base_noclamp(self._scalar_bytes(scalar))

    def point_pow(self, point: bytes, scalar: int) -> bytes:
        if scalar % self.order == 0 or point == self.identity():
            return self.identity()
        return self._b.crypto_scalarmult_ed25519_noclamp(self._scalar_bytes(scalar), point)

    def commit(self, base: bytes, s: int, point: bytes, c: int) -> bytes:
        return self._b.crypto_core_ed25519_sub(self.point_pow(base, s), self.point_pow(point, c))

    def base_commit(self, s: int, point: bytes, c: int) -> bytes:
        return self._b.crypto_core_ed25519_sub(self.base_pow(s), self.point_pow(point, c))

    def hash_to_point(self, label: bytes) -> bytes:
        """Try-and-increment, then clear the cofactor.

        The generator must have an unknown discrete logarithm relative to the
        base point: deriving it as t*B would make the nullifier publicly
        recomputable from a registry entry and destroy anonymity. So the point
        comes straight from a hash.

        Passing libsodium's point validity check is not sufficient. A decoded
        point can still carry a component of the order-8 torsion subgroup, and
        such a point does not satisfy h^L = identity, which silently breaks every
        proof that relies on the group having prime order. Multiplying by the
        cofactor projects onto the prime-order subgroup and fixes that.
        """
        counter = 0
        while counter < 1_000_000:
            candidate = hashlib.sha512(
                DOMAIN + b":h2p:" + label + counter.to_bytes(4, "big")).digest()[:32]
            try:
                if self._b.crypto_core_ed25519_is_valid_point(candidate):
                    cleared = self.point_pow(candidate, 8)
                    if cleared != self.identity():
                        return cleared
            except Exception:  # libsodium raises on malformed encodings
                pass
            counter += 1
        raise RuntimeError("hash to point failed")

    def mul(self, a: bytes, b: bytes) -> bytes:
        if a == self.identity():
            return b
        if b == self.identity():
            return a
        return self._b.crypto_core_ed25519_add(a, b)

    def neg(self, a: bytes) -> bytes:
        """Negate by flipping the compressed sign bit of x.

        Passing the neutral element to libsodium's point subtraction is not an
        option: it treats a small-order point as invalid, and the wrapper does
        not surface the failure, so the result is silently wrong.
        """
        if a == self.identity():
            return a
        return bytes(a[:31]) + bytes([a[31] ^ 0x80])

    def identity(self) -> bytes:
        # the neutral element in Ed25519 compressed form
        return b"\x01" + b"\x00" * 31

    def encode(self, point: bytes) -> bytes:
        return point

    def decode(self, raw: bytes) -> bytes:
        """Back to a point, rejecting anything that is not one.

        The encoding is the point here, so this is entirely the validation ---
        which is the part that matters, since libsodium's own point check is not
        a subgroup check and the identity has to be admitted deliberately.
        """
        raw = bytes(raw)
        if raw == self.identity():
            return raw
        if not self.is_valid(raw):
            raise ValueError("not a valid Ed25519 point")
        return raw

    def is_valid(self, point: bytes) -> bool:
        if not isinstance(point, (bytes, bytearray)) or len(point) != 32:
            return False
        try:
            return bool(self._b.crypto_core_ed25519_is_valid_point(bytes(point)))
        except Exception:
            return False


BACKENDS: dict[str, type] = {
    ModpNaive.name: ModpNaive,
    ModpInverse.name: ModpInverse,
    ModpNegExp.name: ModpNegExp,
    ModpMultiexp.name: ModpMultiexp,
    Ed25519Group.name: Ed25519Group,
}


def make_group(name: str) -> Group:
    if name not in BACKENDS:
        raise ValueError(f"unknown group {name}; choose from {sorted(BACKENDS)}")
    return BACKENDS[name]()
