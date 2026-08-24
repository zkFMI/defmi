"""Groth--Kohlweiss one-out-of-many proof, for measuring rather than assuming.

We previously argued this construction away on the grounds that it shrinks the
proof to O(log N) but needs O(N log N) prover exponentiations, so it loses on
proving time to the plain O(N) OR proof. That is what the original paper says
(roughly N log N exponentiations to prove, N to verify), but an argument is not
a measurement, so it is implemented here and benchmarked against the OR proof in
the same group on the same host.

Statement: given commitments C_0..C_{N-1}, the prover knows an index l and
randomness r with C_l = Com(0; r). Written for N a power of two.

Protocol (paper notation):
    for each bit j of l, commit to l_j, a_j and l_j*a_j
    challenge x
    f_j  = l_j x + a_j,  z_aj = r_j x + s_j,  z_bj = r_j (x - f_j) + t_j
    p_i(x) = prod_j f_{j, i_j}   with f_{j,1} = f_j and f_{j,0} = x - f_j
    G_k = prod_i C_i^{p_{i,k}} * Com(0; rho_k)
    z_d = r x^n - sum_k rho_k x^k
    check prod_i C_i^{p_i(x)} * prod_k G_k^{-x^k} = Com(0; z_d)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Sequence

from .commit import Pedersen
from .groups import DOMAIN, Group


@dataclass(frozen=True)
class GkProof:
    cl: tuple            # commitments to the bits of the index
    ca: tuple
    cb: tuple
    gk: tuple            # the n polynomial-coefficient commitments
    f: tuple
    za: tuple
    zb: tuple
    zd: int

    def size_bytes(self, group: Group) -> int:
        scalars = len(self.f) + len(self.za) + len(self.zb) + 1
        points = len(self.cl) + len(self.ca) + len(self.cb) + len(self.gk)
        return points * len(group.encode(self.cl[0])) + scalars * 32


def _challenge(key: Pedersen, *parts) -> int:
    digest = hashlib.sha512(DOMAIN + b":gk:")
    for part in parts:
        if isinstance(part, (list, tuple)):
            for item in part:
                encoded = key.group.encode(item)
                digest.update(len(encoded).to_bytes(4, "big"))
                digest.update(encoded)
        elif isinstance(part, bytes):
            digest.update(part)
        else:
            encoded = key.group.encode(part)
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
    return int.from_bytes(digest.digest(), "big") % key.group.order


def _bits(value: int, width: int) -> list[int]:
    return [(value >> j) & 1 for j in range(width)]


def _poly_coefficients(index: int, bits: int, a: Sequence[int], ell: Sequence[int],
                       order: int) -> list[int]:
    """Coefficients of p_i(x) = prod_j f_{j, i_j}, as a polynomial in x.

    f_{j,1} = l_j x + a_j and f_{j,0} = (1 - l_j) x - a_j, so each factor is
    linear and the product is built by convolution. This is the O(N log N) part.
    """
    poly = [1]
    for j in range(bits):
        bit = (index >> j) & 1
        if bit == 1:
            linear = [a[j] % order, ell[j] % order]            # a_j + l_j x
        else:
            linear = [(-a[j]) % order, (1 - ell[j]) % order]   # -a_j + (1-l_j) x
        product = [0] * (len(poly) + 1)
        for p, coefficient in enumerate(poly):
            product[p] = (product[p] + coefficient * linear[0]) % order
            product[p + 1] = (product[p + 1] + coefficient * linear[1]) % order
        poly = product
    return poly


class GkProver:
    def __init__(self, group: Group, key: Pedersen | None = None):
        self.group = group
        self.key = key or Pedersen(group, b"qomm:gk:v1")

    def prove(self, commitments: Sequence[Any], index: int, randomness: int) -> GkProof:
        group = self.group
        key = self.key
        order = group.order
        size = len(commitments)
        bits = size.bit_length() - 1
        if 1 << bits != size:
            raise ValueError("this implementation takes a power-of-two set")

        ell = _bits(index, bits)
        a = [group.random_scalar() for _ in range(bits)]
        r = [group.random_scalar() for _ in range(bits)]
        s = [group.random_scalar() for _ in range(bits)]
        t = [group.random_scalar() for _ in range(bits)]
        cl = [key.commit(ell[j], r[j]) for j in range(bits)]
        ca = [key.commit(a[j], s[j]) for j in range(bits)]
        cb = [key.commit((ell[j] * a[j]) % order, t[j]) for j in range(bits)]

        # coefficients of p_i for every i: the O(N log N) work
        coefficients = [_poly_coefficients(i, bits, a, ell, order) for i in range(size)]

        rho = [group.random_scalar() for _ in range(bits)]
        gk = []
        for k in range(bits):
            acc = key.commit(0, rho[k])
            for i in range(size):
                acc = group.mul(acc, group.point_pow(commitments[i], coefficients[i][k]))
            gk.append(acc)

        x = _challenge(key, cl, ca, cb, gk)
        f = [(ell[j] * x + a[j]) % order for j in range(bits)]
        za = [(r[j] * x + s[j]) % order for j in range(bits)]
        zb = [(r[j] * ((x - f[j]) % order) + t[j]) % order for j in range(bits)]
        zd = (randomness * pow(x, bits, order)
              - sum(rho[k] * pow(x, k, order) for k in range(bits))) % order
        return GkProof(tuple(cl), tuple(ca), tuple(cb), tuple(gk),
                       tuple(f), tuple(za), tuple(zb), zd)


class GkVerifier:
    def __init__(self, group: Group, key: Pedersen | None = None):
        self.group = group
        self.key = key or Pedersen(group, b"qomm:gk:v1")

    def verify(self, commitments: Sequence[Any], proof: GkProof) -> bool:
        group = self.group
        key = self.key
        order = group.order
        size = len(commitments)
        bits = size.bit_length() - 1
        if len(proof.f) != bits:
            return False
        x = _challenge(key, list(proof.cl), list(proof.ca), list(proof.cb), list(proof.gk))

        for j in range(bits):
            # Com(f_j; z_aj) must equal c_lj^x * c_aj
            left = key.commit(proof.f[j], proof.za[j])
            right = group.mul(group.point_pow(proof.cl[j], x), proof.ca[j])
            if group.encode(left) != group.encode(right):
                return False
            # Com(0; z_bj) must equal c_lj^(x - f_j) * c_bj
            left = key.commit(0, proof.zb[j])
            right = group.mul(group.point_pow(proof.cl[j], (x - proof.f[j]) % order),
                              proof.cb[j])
            if group.encode(left) != group.encode(right):
                return False

        # the O(N) part: prod_i C_i^{p_i(x)} * prod_k G_k^{-x^k} = Com(0; z_d)
        acc = group.identity()
        for i in range(size):
            value = 1
            for j in range(bits):
                factor = proof.f[j] if (i >> j) & 1 else (x - proof.f[j]) % order
                value = (value * factor) % order
            acc = group.mul(acc, group.point_pow(commitments[i], value))
        for k in range(bits):
            acc = group.mul(acc, group.neg(group.point_pow(proof.gk[k], pow(x, k, order))))
        return group.encode(acc) == group.encode(key.commit(0, proof.zd))


def build_set(group: Group, size: int, index: int, key: Pedersen | None = None):
    """A set of commitments where exactly the one at `index` opens to zero."""
    key = key or Pedersen(group, b"qomm:gk:v1")
    randomness = key.random_blinding()
    commitments = []
    for position in range(size):
        if position == index:
            commitments.append(key.commit(0, randomness))
        else:
            commitments.append(key.commit(group.random_scalar(), key.random_blinding()))
    return commitments, randomness
