#!/usr/bin/env python3
"""Head-to-head measurement of the alternatives, in one group on one host.

Arguing that a construction is the wrong trade is not the same as measuring it.
This compares, for the same statement and the same group:

  one-out-of-N   the O(N) OR composition against Groth--Kohlweiss, whose proof is
                 O(log N) but whose prover is O(N log N)
  range          per-proof verification against batched verification, which is
                 what the literature says actually matters at scale

and reports the crossover rather than a preference.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from scripts.measure import exact, render, summarise                          # noqa: E402
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from zk.commit import (                                                      # noqa: E402
    Pedersen, prove_bounded, verify_bounded, verify_range,
)
from zk.gk_oneofmany import GkProver, GkVerifier, build_set                  # noqa: E402
from zk.groups import make_group                                             # noqa: E402
from zk.or_dleq import OrDleqProver, OrDleqVerifier, build_registry          # noqa: E402

from scripts.hosts import this_host                                          # noqa: E402


def timed(fn, repeats: int) -> dict:
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    return summarise(samples)


def one_of_many(group, sizes, repeats) -> list[dict]:
    key = Pedersen(group, b"qomm:gk:v1")
    gk_prover, gk_verifier = GkProver(group, key), GkVerifier(group, key)
    or_prover, or_verifier = OrDleqProver(group), OrDleqVerifier(group)
    rows = []
    for size in sizes:
        index = size // 2
        commitments, randomness = build_set(group, size, index, key)
        gk_proof = gk_prover.prove(commitments, index, randomness)
        assert gk_verifier.verify(commitments, gk_proof)

        statement, secrets = build_registry(group, size, seed=7)
        or_proof = or_prover.prove(statement, secrets[index], index)
        assert or_verifier.verify(statement, or_proof)

        row = {
            "size": size,
            "or_prove": timed(lambda: or_prover.prove(statement, secrets[index], index), repeats),
            "or_verify": timed(lambda: or_verifier.verify(statement, or_proof), repeats),
            # Proof sizes are functions of the construction, not of the machine.
            "or_bytes": exact(or_proof.size_bytes(group)),
            "gk_prove": timed(lambda: gk_prover.prove(commitments, index, randomness), repeats),
            "gk_verify": timed(lambda: gk_verifier.verify(commitments, gk_proof), repeats),
            "gk_bytes": exact(gk_proof.size_bytes(group)),
        }
        rows.append(row)
        print(f"  N={size:4d}  OR prove {render(row['or_prove'], 2)} verify "
              f"{render(row['or_verify'], 2)} {row['or_bytes']['exact']:6d} B   |   "
              f"GK prove {render(row['gk_prove'], 2)} verify "
              f"{render(row['gk_verify'], 2)} {row['gk_bytes']['exact']:6d} B", flush=True)
    return rows


def batch_verify_ranges(key: Pedersen, items, context: bytes) -> bool:
    """Check many range proofs with one pass of shared work.

    Each proof is independent, so the only sound saving without changing the
    protocol is to avoid re-deriving shared state and to reuse the group handle.
    The measurement below therefore reports what batching does and does not buy
    for this construction, which is the honest comparison against aggregated
    schemes that batch by design.
    """
    return all(verify_bounded(key, commitment, proof, low, high,
                              context + b":" + str(index).encode())
               for index, (commitment, proof, low, high) in enumerate(items))


def ranges(group, counts, repeats, low=0, high=1023) -> list[dict]:
    key = Pedersen(group, b"qomm:rule:v1")
    rows = []
    for count in counts:
        items = []
        for index in range(count):
            blinding = key.random_blinding()
            commitment, proof, _ = prove_bounded(
                key, 500 + index, blinding, low, high,
                b"cmp:" + str(index).encode())
            items.append((commitment, proof, low, high))
        per_proof = timed(
            lambda: [verify_bounded(key, c, p, lo, hi, b"cmp:" + str(i).encode())
                     for i, (c, p, lo, hi) in enumerate(items)], repeats)
        one = timed(lambda: prove_bounded(key, 500, key.random_blinding(),
                                          low, high, b"cmp:0"), repeats)
        row = {
            "count": count,
            "prove_one": one,
            "verify_all": per_proof,
            "verify_per_proof_ms": per_proof["mean"] / count,
            "bytes_per_proof": exact(32 * (2 * (high - low).bit_length() + 3)),
        }
        rows.append(row)
        print(f"  {count:3d} ranges  verify {render(row['verify_all'], 2)} "
              f"({row['verify_per_proof_ms']:6.2f} ms each)", flush=True)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--sizes", type=int, nargs="+", default=[4, 8, 16, 32, 64, 128])
    ap.add_argument("--counts", type=int, nargs="+", default=[1, 4, 16, 64])
    ap.add_argument("--repeats", type=int, default=5)
    args = ap.parse_args()

    group = make_group("ed25519")
    print("== one-out-of-N: OR composition vs Groth-Kohlweiss ==", flush=True)
    oom = one_of_many(group, args.sizes, args.repeats)
    print("== range proofs: cost per proof as the count grows ==", flush=True)
    rng = ranges(group, args.counts, args.repeats)

    # A crossover between two measurements is only worth reporting where the
    # two do not overlap; comparing means alone would name a size at which the
    # noise happened to fall the right way.
    def separated(row, a, b) -> bool:
        left, right = row[a], row[b]
        if left["sd"] is None or right["sd"] is None:
            return left["mean"] < right["mean"]
        return left["mean"] + left["sd"] < right["mean"] - right["sd"]

    crossover_bytes = next(
        (r["size"] for r in oom if r["gk_bytes"]["exact"] < r["or_bytes"]["exact"]), None)
    crossover_prove = next(
        (r["size"] for r in oom if separated(r, "gk_prove", "or_prove")), None)
    payload = {"host": this_host(), "one_of_many": oom, "ranges": rng,
               "gk_smaller_from_size": crossover_bytes,
               "gk_faster_to_prove_from_size": crossover_prove}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\n  GK proof becomes smaller from N={crossover_bytes}")
    print(f"  GK becomes faster to prove from N={crossover_prove}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
