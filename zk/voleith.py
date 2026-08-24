"""VOLE-in-the-Head: the transform that makes a VOLE commitment public.

`scheme.VoleScheme` is a commitment from a VOLE correlation `M = K + Delta*x`,
and it beat Pedersen by 113x on a scale because a field multiply beats a scalar
multiplication. It is also **designated verifier**: only the holder of `Delta`
can check an opening, so it cannot convince a regulator who was not present.
This module is the transform that fixes that, and the reason to write it is to
find out what the 113x becomes once public verifiability is paid for.

The construction is Baum, Braun, Delpech de Saint Guilhem, Kloo{\\ss}, Orsini,
Roy and Scholl (CRYPTO 2023), section 1.2 and figure 7, instantiated with the
`[tau, 1, tau]` repetition code the same paper uses for FAEST. Nothing here is
new; what is new is running it on this stack's statement and measuring it.

**Where the VOLE comes from.** Take `N` random field vectors `t_0 .. t_{N-1}`
that the prover knows entirely and the verifier knows all but one of --- index
`Delta`, which the verifier chooses. Then

    u = sum_x t_x                    (prover)
    V = -sum_x x*t_x                 (prover)
    Q = sum_{x != Delta} (Delta - x) * t_x
      = Delta * sum_x t_x - sum_x x*t_x
      = Delta*u + V                  (verifier, from what it has)

so the two sides hold a VOLE correlation on `u`, and the verifier never learned
`u` because the one vector it is missing is uniform. The prover commits to a
witness `w` by publishing the correction `d = w - u`; the verifier folds it in
as `Q + Delta*d`, which is a VOLE on `w`.

**Where the public verifiability comes from.** The `N` vectors are the leaves of
a GGM tree, so revealing all but one costs the `depth` sibling seeds on the
co-path rather than `N` vectors, and `Delta` is derived by Fiat--Shamir from the
transcript instead of being sent by a live verifier. Anyone who recomputes the
hash gets the same `Delta` and can run the check.

**Why there are `tau` of them.** One repetition has soundness `1/N`, because a
cheating prover only has to guess `Delta`. `N = 2^depth` is bounded by the
`N` PRG calls it costs, so soundness comes from repeating: `depth * repeats`
bits, and the default 8 x 16 is the 128 that FAEST's fastest parameter set uses.

**What the repetitions cost, which is the finding.** Each repetition produces
its own `u`, and the witness has to be committed against one of them, so the
prover publishes `repeats - 1` corrections of `ell` field elements each. Over
`F_2`, where FAEST lives, those are bits and the paper's "2x the
designated-verifier communication" holds. Over a 127-bit prime, which is where
this stack's arithmetic lives, they are 16-byte elements, and they dominate the
proof. `LinearProof.size_breakdown()` reports the split rather than a total, so
this is visible instead of inferred.

The escape looks like section 6.1 of the paper --- a linear code in place of the
repetition code turns `(repeats - 1) * ell` into `ell * (n_C - k_C)` with `n_C`
columns, trading corrections for trees --- but it is not a drop-in. Section 6.1
opens by saying that the repetition code is what makes this a linearly
homomorphic commitment for messages in `F_p`, and that a general code is
homomorphic only across the `k_C`-blocks. The statement here is an inner product
with a distinct coefficient per value, which is within a block, so the general
code needs the paper's degree-2 protocol and its stated 2x overhead. **Not
implemented here**; `BINDING.md` section 4.6 prices both ways of counting it.

**These commitments open once.** After `Delta` is published the correlation is
no longer binding, so a second statement about the same commitment proves
nothing. Baum and Zok (`eprint 2026/337`) formalise exactly this --- their
phrase is "one-time linearly homomorphic" --- and buy a second opening by
committing to the opening in the random oracle. `Prover` raises rather than
allowing a second proof, because a scheme that silently permits an unsound
operation is worse than one that lacks the feature.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Sequence

DOMAIN = b"qomm:voleith:v1"

# 8 x 16 = 128 bits of soundness. FAEST's table 2 measures the same trade at
# q = 2^7 .. 2^11 and finds 2^8 fastest, which is this row.
DEFAULT_DEPTH = 8
DEFAULT_REPEATS = 16

SEED_BYTES = 16          # lambda = 128
COMMIT_BYTES = 32        # 2*lambda, the leaf commitments and the root
STATISTICAL_BITS = 64    # how far the leaf values reach past the modulus


class OneTimeError(RuntimeError):
    """Raised on a second proof from one commitment. See the module docstring."""


# --- the GGM tree ---------------------------------------------------------

def _prg(seed: bytes, label: bytes) -> tuple[bytes, bytes]:
    """One length-doubling step. Two children from one seed."""
    out = hashlib.shake_128(DOMAIN + b"|prg|" + label + seed).digest(2 * SEED_BYTES)
    return out[:SEED_BYTES], out[SEED_BYTES:]


def expand_tree(root: bytes, depth: int, rep: int) -> list[bytes]:
    """`2^depth` leaf seeds, in index order."""
    level = [root]
    for d in range(depth):
        nxt = []
        label = rep.to_bytes(2, "big") + d.to_bytes(2, "big")
        for seed in level:
            left, right = _prg(seed, label)
            nxt.append(left)
            nxt.append(right)
        level = nxt
    return level


def copath(root: bytes, depth: int, rep: int, index: int) -> list[bytes]:
    """The `depth` sibling seeds that open every leaf except `index`."""
    if not 0 <= index < (1 << depth):
        raise ValueError(f"leaf {index} is outside a depth-{depth} tree")
    out, seed = [], root
    for d in range(depth):
        bit = (index >> (depth - 1 - d)) & 1
        label = rep.to_bytes(2, "big") + d.to_bytes(2, "big")
        left, right = _prg(seed, label)
        out.append(right if bit == 0 else left)
        seed = left if bit == 0 else right
    return out


def open_copath(path: Sequence[bytes], depth: int, rep: int,
                index: int) -> list[bytes | None]:
    """Every leaf the co-path reaches. `None` at `index`, which stays hidden."""
    if len(path) != depth:
        raise ValueError(f"a depth-{depth} tree has a {depth}-seed co-path")
    leaves: list[bytes | None] = [None] * (1 << depth)
    for d, sibling in enumerate(path):
        bit = (index >> (depth - 1 - d)) & 1
        # the sibling subtree hangs at depth d and covers 2^(depth-1-d) leaves,
        # starting where the path turns away from `index`
        prefix = index >> (depth - d)
        sub_index = (prefix << 1) | (1 - bit)
        span = 1 << (depth - 1 - d)
        base = sub_index * span
        level = [sibling]
        for dd in range(d + 1, depth):
            label = rep.to_bytes(2, "big") + dd.to_bytes(2, "big")
            nxt = []
            for seed in level:
                left, right = _prg(seed, label)
                nxt.append(left)
                nxt.append(right)
            level = nxt
        for offset, leaf in enumerate(level):
            leaves[base + offset] = leaf
    return leaves


def leaf_commitment(leaf: bytes, rep: int, index: int) -> bytes:
    return hashlib.shake_128(DOMAIN + b"|leaf|" + rep.to_bytes(2, "big")
                             + index.to_bytes(4, "big") + leaf).digest(COMMIT_BYTES)


# --- packing --------------------------------------------------------------
#
# The sums that build the VOLE run over every leaf of every tree, which at the
# default parameters is 4,096 vectors of `ell` field elements each. Done one
# element at a time in CPython that is the whole cost of the module. Packing the
# vector into one integer, with enough headroom per slot that the sums cannot
# carry across, turns each leaf into four big-integer operations instead of
# `4*ell`, and the reduction mod p happens once per element at the end rather
# than once per element per leaf.


@dataclass(frozen=True)
class Packing:
    modulus: int
    length: int
    depth: int

    @property
    def value_bits(self) -> int:
        # past the modulus by `STATISTICAL_BITS`, so a leaf value reduced mod p
        # is within 2^-64 of uniform and the correction `d = w - u` hides `w`
        return self.modulus.bit_length() + STATISTICAL_BITS

    @property
    def slot_bits(self) -> int:
        # the widest sum is `sum_x x*t_x` with x < 2^depth over 2^depth leaves,
        # so `2*depth` bits of carry, and one spare
        return self.value_bits + 2 * self.depth + 1

    @property
    def slot_bytes(self) -> int:
        return (self.slot_bits + 7) // 8

    @property
    def blob_bytes(self) -> int:
        return self.length * self.slot_bytes

    @property
    def mask(self) -> int:
        one = (1 << self.value_bits) - 1
        acc = 0
        for i in range(self.length):
            acc |= one << (self.slot_bytes * 8 * i)
        return acc

    def leaf(self, seed: bytes, rep: int, index: int, mask: int) -> int:
        """`length` field-sized values from one seed, as one packed integer."""
        blob = hashlib.shake_128(DOMAIN + b"|vec|" + rep.to_bytes(2, "big")
                                 + index.to_bytes(4, "big") + seed
                                 ).digest(self.blob_bytes)
        return int.from_bytes(blob, "little") & mask

    def unpack(self, packed: int) -> list[int]:
        width = self.slot_bytes * 8
        slot = (1 << width) - 1
        return [((packed >> (width * i)) & slot) % self.modulus
                for i in range(self.length)]


# --- the proof ------------------------------------------------------------

@dataclass(frozen=True)
class LinearProof:
    """What is published. Anyone holding this and the statement can check it.

    `witness_correction` is `d = w - u`, which is what commits the witness;
    `vole_corrections` are what make the `repeats` independent trees agree on
    one `u`; `opening` and `tags` are the response; the co-paths and the
    punctured leaf commitments are the all-but-one opening.
    """

    root: bytes
    witness_correction: list[int]
    vole_corrections: list[list[int]]
    opening: int
    tags: list[int]
    copaths: list[list[bytes]]
    punctured: list[bytes]
    depth: int
    repeats: int
    modulus: int

    @property
    def n_values(self) -> int:
        return len(self.witness_correction)

    def soundness_bits(self) -> int:
        return self.depth * self.repeats

    def size_breakdown(self) -> dict[str, int]:
        """Bytes by part, because the total hides which part is the problem."""
        width = (self.modulus.bit_length() + 7) // 8
        return {
            "root": COMMIT_BYTES,
            "witness_correction": self.n_values * width,
            "vole_corrections": len(self.vole_corrections) * self.n_values * width,
            "opening": width,
            "tags": len(self.tags) * width,
            "copaths": sum(len(p) for p in self.copaths) * SEED_BYTES,
            "punctured": len(self.punctured) * COMMIT_BYTES,
        }

    def size_bytes(self) -> int:
        return sum(self.size_breakdown().values())


# --- Fiat-Shamir ----------------------------------------------------------

def _absorb(hasher, *parts: bytes) -> None:
    for part in parts:
        hasher.update(len(part).to_bytes(4, "big"))
        hasher.update(part)


def _ints(values: Sequence[int], width: int) -> bytes:
    return b"".join(int(v).to_bytes(width, "big") for v in values)


def coefficients(root: bytes, correction: Sequence[int], context: bytes,
                 modulus: int, challenge_bits: int, count: int) -> list[int]:
    """Public coefficients, derived after the witness is fixed and not before.

    Same discipline as `input_check.coefficients`: the commitment is
    `(root, correction)` here rather than a list of group elements, and the
    coefficients depend on all of it, so a prover choosing an error cannot see
    the coefficient that would cancel it.
    """
    width = (modulus.bit_length() + 7) // 8
    seed = hashlib.sha512(DOMAIN + b"|coeff|")
    _absorb(seed, context, root, _ints(correction, width))
    seed.update(count.to_bytes(4, "big"))
    base = seed.digest()
    span = (1 << challenge_bits) - 1
    return [1 + int.from_bytes(hashlib.sha512(base + i.to_bytes(4, "big")).digest(),
                               "big") % span
            for i in range(count)]


def challenge(root: bytes, correction: Sequence[int],
              vole_corrections: Sequence[Sequence[int]], opening: int,
              tags: Sequence[int], context: bytes, modulus: int,
              depth: int, repeats: int) -> list[int]:
    """`Delta` for each repetition, over everything the prover could still choose.

    Derived last. Every value the prover sends is inside the hash, so the tree
    openings are the only thing left and they are forced by `root`.
    """
    width = (modulus.bit_length() + 7) // 8
    hasher = hashlib.sha512(DOMAIN + b"|delta|")
    _absorb(hasher, context, root, _ints(correction, width))
    for row in vole_corrections:
        _absorb(hasher, _ints(row, width))
    _absorb(hasher, int(opening).to_bytes(width, "big"), _ints(tags, width))
    base = hasher.digest()
    span = 1 << depth
    return [int.from_bytes(hashlib.sha512(base + j.to_bytes(4, "big")).digest(),
                           "big") % span
            for j in range(repeats)]


# --- the prover -----------------------------------------------------------

class Prover:
    """Commit to a vector once, then prove one linear statement about it.

    Split into `commit` and `prove` because they are genuinely two phases: the
    coefficients are derived from the commitment, so nothing that depends on
    them can happen until it exists.
    """

    def __init__(self, modulus: int, depth: int = DEFAULT_DEPTH,
                 repeats: int = DEFAULT_REPEATS, roots: Sequence[bytes] | None = None):
        if depth < 1 or repeats < 1:
            raise ValueError("a tree needs a level and a proof needs a repetition")
        self.modulus = modulus
        self.depth = depth
        self.repeats = repeats
        self._roots = list(roots) if roots is not None else [
            secrets.token_bytes(SEED_BYTES) for _ in range(repeats)]
        self._committed = False
        self._proved = False

    # -- phase one
    def commit(self, values: Sequence[int]) -> tuple[bytes, list[int], list[list[int]]]:
        """Publish `(root, d, corrections)`. Everything else stays here."""
        if self._committed:
            raise OneTimeError("this commitment is already made; build another Prover")
        n = len(values)
        if n < 1:
            raise ValueError("a proof over no values proves nothing")
        pack = Packing(self.modulus, n, self.depth)
        mask = pack.mask
        self._pack = pack

        us, vs, commitments = [], [], []
        for rep in range(self.repeats):
            leaves = expand_tree(self._roots[rep], self.depth, rep)
            u_packed = 0
            w_packed = 0
            for index, leaf in enumerate(leaves):
                t = pack.leaf(leaf, rep, index, mask)
                u_packed += t
                w_packed += index * t
                commitments.append(leaf_commitment(leaf, rep, index))
            us.append(pack.unpack(u_packed))
            vs.append([(-x) % self.modulus for x in pack.unpack(w_packed)])

        root = hashlib.shake_128(DOMAIN + b"|root|"
                                 + b"".join(commitments)).digest(COMMIT_BYTES)
        reference = us[0]
        correction = [(int(v) - u) % self.modulus for v, u in zip(values, reference)]
        vole_corrections = [[(reference[i] - us[j][i]) % self.modulus
                             for i in range(n)]
                            for j in range(1, self.repeats)]

        self._values = [int(v) % self.modulus for v in values]
        self._vs = vs
        self._root = root
        self._correction = correction
        self._vole_corrections = vole_corrections
        self._committed = True
        return root, correction, vole_corrections

    # -- phase two
    def prove(self, coeffs: Sequence[int], context: bytes) -> LinearProof:
        """One linear statement. The commitment is spent after this."""
        if not self._committed:
            raise RuntimeError("commit before proving; the coefficients need the root")
        if self._proved:
            raise OneTimeError(
                "these commitments open once --- Delta is public after the first "
                "proof, so a second statement about the same commitment is not "
                "bound by anything. See eprint 2026/337 section 1.1, which buys a "
                "second opening with a random-oracle commitment to the opening "
                "rather than by reusing Delta.")
        if len(coeffs) != len(self._values):
            raise ValueError("one coefficient per value")

        p = self.modulus
        opening = sum(c * v for c, v in zip(coeffs, self._values)) % p
        tags = [sum(c * v for c, v in zip(coeffs, self._vs[j])) % p
                for j in range(self.repeats)]
        deltas = challenge(self._root, self._correction, self._vole_corrections,
                           opening, tags, context, p, self.depth, self.repeats)

        paths, punctured = [], []
        for rep, delta in enumerate(deltas):
            paths.append(copath(self._roots[rep], self.depth, rep, delta))
            leaf = expand_tree(self._roots[rep], self.depth, rep)[delta]
            punctured.append(leaf_commitment(leaf, rep, delta))

        self._proved = True
        return LinearProof(self._root, self._correction, self._vole_corrections,
                           opening, tags, paths, punctured, self.depth,
                           self.repeats, p)


# --- the verifier ---------------------------------------------------------

def verify(proof: LinearProof, coeffs: Sequence[int],
           context: bytes) -> tuple[bool, str]:
    """Anyone's side. Rebuild the trees from the co-paths and run the check.

    Everything the verifier needs is in `proof` and the public coefficients;
    there is no `Delta` held back and no state from the proving side, which is
    the whole difference from `scheme.VoleScheme`.
    """
    p = proof.modulus
    n = proof.n_values
    if n < 1:
        return False, "the proof covers no values"
    if len(coeffs) != n:
        return False, "one coefficient per value"
    if len(proof.vole_corrections) != proof.repeats - 1:
        return False, "one VOLE correction per repetition after the first"
    if len(proof.copaths) != proof.repeats or len(proof.punctured) != proof.repeats:
        return False, "one opening per repetition"

    deltas = challenge(proof.root, proof.witness_correction, proof.vole_corrections,
                       proof.opening, proof.tags, context, p, proof.depth,
                       proof.repeats)
    pack = Packing(p, n, proof.depth)
    mask = pack.mask

    commitments: list[bytes] = []
    for rep, delta in enumerate(deltas):
        leaves = open_copath(proof.copaths[rep], proof.depth, rep, delta)
        sum_packed = 0
        weighted = 0
        for index, leaf in enumerate(leaves):
            if index == delta:
                commitments.append(proof.punctured[rep])
                continue
            if leaf is None:
                return False, f"repetition {rep} left leaf {index} unopened"
            t = pack.leaf(leaf, rep, index, mask)
            sum_packed += t
            weighted += index * t
            commitments.append(leaf_commitment(leaf, rep, index))

        totals = pack.unpack(sum_packed)
        weights = pack.unpack(weighted)
        # Q = Delta*sum t - sum x*t, then folded onto the witness by the two
        # corrections: the one that makes this repetition agree with the first,
        # and the one that commits the witness
        shift = proof.witness_correction if rep == 0 else [
            (a + b) % p for a, b in zip(proof.witness_correction,
                                        proof.vole_corrections[rep - 1])]
        combined = 0
        for i in range(n):
            q = (delta * totals[i] - weights[i] + delta * shift[i]) % p
            combined = (combined + coeffs[i] * q) % p
        if combined != (proof.opening * delta + proof.tags[rep]) % p:
            return False, (f"repetition {rep} does not hold: the values the "
                           f"opening combines are not the committed ones")

    root = hashlib.shake_128(DOMAIN + b"|root|"
                             + b"".join(commitments)).digest(COMMIT_BYTES)
    if root != proof.root:
        return False, "the opened leaves are not the committed ones"
    return True, "ok"


# --- what it costs, without running it ------------------------------------

def proof_size(n_values: int, modulus_bits: int = 127, depth: int = DEFAULT_DEPTH,
               repeats: int = DEFAULT_REPEATS) -> dict[str, int]:
    """The size arithmetic on its own, so a parameter sweep needs no prover."""
    width = (modulus_bits + 7) // 8
    parts = {
        "root": COMMIT_BYTES,
        "witness_correction": n_values * width,
        "vole_corrections": (repeats - 1) * n_values * width,
        "opening": width,
        "tags": repeats * width,
        "copaths": repeats * depth * SEED_BYTES,
        "punctured": repeats * COMMIT_BYTES,
    }
    parts["total"] = sum(parts.values())
    parts["hashes"] = repeats * (1 << depth) * 2      # one PRG and one commitment
    parts["soundness_bits"] = depth * repeats
    return parts
