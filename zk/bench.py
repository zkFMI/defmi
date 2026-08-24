#!/usr/bin/env python3
"""Measure the ZK optimisation ladder and the primitive costs behind it.

Reports, per backend and registry size, the median prove and verify time, the
proof size, and the cost of the group operations the protocol is built from, so
that the speed-up of each step can be attributed rather than asserted.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from scripts.measure import render, summarise                          # noqa: E402
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from zk.groups import BACKENDS, MODP_G, MODP_P, MODP_Q, make_group   # noqa: E402
from zk.kyb import (                                                 # noqa: E402
    BusinessAttributes, KybIssuer, cohort_id, present, scope_nullifier, verify_presentation,
)
from zk.or_dleq import OrDleqProver, OrDleqVerifier, build_registry  # noqa: E402
from zk.policy_audit import PolicyAuditor, PolicyCommitter           # noqa: E402

from scripts.hosts import this_host                                          # noqa: E402


def timed(fn, repeats: int) -> dict:
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    samples.sort()
    summary = summarise(samples)
    # p95 is kept because a tail matters for a verifier that must answer in a
    # slot, and a standard deviation does not show one.
    summary["p95"] = samples[min(len(samples) - 1, int(0.95 * len(samples)))]
    return summary


def primitive_costs() -> dict:
    """The unit costs that explain every number in the ladder."""
    import secrets

    out: dict = {}
    scalar = secrets.randbelow(MODP_Q)
    point = pow(MODP_G, secrets.randbelow(MODP_Q), MODP_P)
    out["modp_fixed_base_exp"] = timed(lambda: pow(MODP_G, scalar, MODP_P), 20)
    out["modp_var_base_exp"] = timed(lambda: pow(point, scalar, MODP_P), 20)
    out["modp_inverse_fermat"] = timed(lambda: pow(point, MODP_P - 2, MODP_P), 20)
    out["modp_inverse_euclid"] = timed(lambda: pow(point, -1, MODP_P), 500)
    out["modp_mul"] = timed(lambda: (point * point) % MODP_P, 5000)
    try:
        group = make_group("ed25519")
        pt = group.base_pow(12345)
        out["ed25519_fixed_base_mul"] = timed(lambda: group.base_pow(scalar), 500)
        out["ed25519_var_base_mul"] = timed(lambda: group.point_pow(pt, scalar), 500)
        out["ed25519_hash_to_point"] = timed(lambda: group.hash_to_point(b"scope"), 200)
    except Exception as exc:  # pragma: no cover - environment without libsodium
        out["ed25519_error"] = str(exc)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+", default=[8, 32, 128])
    ap.add_argument("--backends", nargs="+", default=list(BACKENDS))
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--fast-repeats", type=int, default=200,
                    help="repeats for backends that finish in under a millisecond")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    payload = {
        "host": this_host(),
        "python": platform.python_version(),
        "machine": platform.machine(),
        "primitives": primitive_costs(),
        "ladder": [],
    }

    for name in args.backends:
        try:
            group = make_group(name)
        except Exception as exc:
            payload["ladder"].append({"backend": name, "error": str(exc)})
            continue
        prover = OrDleqProver(group)
        verifier = OrDleqVerifier(group)
        for size in args.sizes:
            statement, secret_scalars = build_registry(group, size, seed=7)
            index = size // 2
            secret = secret_scalars[index]
            proof = prover.prove(statement, secret, index)
            if not verifier.verify(statement, proof):
                payload["ladder"].append({"backend": name, "size": size, "error": "verify failed"})
                continue
            repeats = args.fast_repeats if name == "ed25519" else args.repeats
            row = {
                "backend": name,
                "registry_size": size,
                "security_bits": group.security_bits,
                "proof_bytes": proof.size_bytes(group),
                "prove": timed(lambda: prover.prove(statement, secret, index), repeats),
                "verify": timed(lambda: verifier.verify(statement, proof), repeats),
            }
            payload["ladder"].append(row)
            print(f"{name:15s} N={size:4d}  prove {render(row['prove'], 4)} ms   "
                  f"verify {render(row['verify'], 4)} ms   "
                  f"proof {row['proof_bytes']:5d} B", flush=True)

    # --- the two application-level proofs, on the fastest backend ---
    payload["applications"] = []
    for backend in ("modp_multiexp", "ed25519"):
        try:
            group = make_group(backend)
        except Exception:
            continue
        repeats = 50 if backend == "ed25519" else 3

        committer = PolicyCommitter(group)
        auditor = PolicyAuditor(group)
        nullifier = group.hash_to_point(b"entity")
        policy = dict(mid=100_000, half=14, slope=2, invcoef=1, inv=-320,
                      maxqty=400, expiry=1_600, active=1)
        audit, shares, _ = committer.audit(policy, ref_mid=100_000, now_t=1_000,
                                           n_parties=7, threshold=2,
                                           entity_nullifier=nullifier)
        assert auditor.verify(audit, now_t=1_000, ref_mid=100_000, max_horizon=3_600)[0]
        payload["applications"].append({
            "proof": "market_maker_policy_audit",
            "backend": backend,
            "fields_audited": len(audit.fields) + 1,
            "parties": 7,
            "prove": timed(lambda: committer.audit(
                policy, ref_mid=100_000, now_t=1_000, n_parties=7, threshold=2,
                entity_nullifier=nullifier), repeats),
            "verify": timed(lambda: auditor.verify(
                audit, now_t=1_000, ref_mid=100_000, max_horizon=3_600), repeats),
            "share_check_all_nodes": timed(lambda: [
                committer.verify_share(share, audit.fields[name])
                for name, field_shares in shares.items() for share in field_shares], repeats),
        })

        for cohort_size in (8, 64):
            issuer = KybIssuer(group)
            for index in range(cohort_size):
                issuer.enroll(f"GROUP-{index}", BusinessAttributes("JP", "bank", 4))
            registry = issuer.publish(cohort_id("JP", "bank", 2), 1, 9_999)
            credential = issuer._enrolled["GROUP-0"]
            context = {"venue": "qomm", "asset": 1}
            presentation = present(group, credential, registry,
                                   scope="qomm:quote:epoch7", context=context)
            assert verify_presentation(group, presentation, registry, issuer.public_key,
                                       scope="qomm:quote:epoch7", context=context, now=100,
                                       required_cohort=registry.cohort)[0]
            payload["applications"].append({
                "proof": "kyb_cohort_presentation",
                "backend": backend,
                "cohort_size": cohort_size,
                "prove": timed(lambda: present(group, credential, registry,
                                               scope="qomm:quote:epoch7", context=context),
                               repeats),
                "verify": timed(lambda: verify_presentation(
                    group, presentation, registry, issuer.public_key,
                    scope="qomm:quote:epoch7", context=context, now=100,
                    required_cohort=registry.cohort), repeats),
                "nullifier": timed(lambda: scope_nullifier(
                    group, credential, "qomm:quote:epoch7"), repeats),
            })

    for row in payload["applications"]:
        label = row["proof"] + (f"/N={row['cohort_size']}" if "cohort_size" in row else "")
        print(f"{label:34s} {row['backend']:15s} prove {render(row['prove'], 3)} ms   "
              f"verify {render(row['verify'], 3)} ms", flush=True)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
