#!/usr/bin/env python3
"""Acceptance test for the native DeFMI Avalanche L1.

This uses real AvalancheGo processes and the custom VM JSON-RPC API.  It also
simulates a crash after L1 acceptance but before the local projection is
updated, then proves that retrying the exact operation repairs the projection
without creating another transition.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from defmi.avalanche import AvalancheRpcClient, FacilityAvalancheBridge  # noqa: E402
from defmi.facility import (AccountOpening, AssetDefinition, AssetKind,  # noqa: E402
                            DefmiFacility, QuorumAuthorizer,
                            SettlementOrder, StateLeg)


def digest(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def tool_record(path: Path | None) -> dict | None:
    if path is None:
        return None
    resolved = path.resolve()
    if not resolved.is_file():
        raise RuntimeError("acceptance tool path is not a file")
    completed = subprocess.run(
        [str(resolved), "--version"], check=False, capture_output=True,
        text=True, timeout=20)
    if completed.returncode != 0:
        raise RuntimeError("acceptance tool did not report its version")
    return {
        "version": (completed.stdout or completed.stderr).strip(),
        "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
    }


def committee(domain: str) -> tuple[QuorumAuthorizer, dict[str, Ed25519PrivateKey]]:
    # These deterministic keys match config/test-genesis.json and are for a
    # disposable acceptance network only. Production keys must come from the
    # configured external key providers.
    keys = {
        f"node-{index}": Ed25519PrivateKey.from_private_bytes(
            digest(f"key:{index}"))
        for index in range(7)
    }
    authorizer = QuorumAuthorizer(
        {name: key.public_key() for name, key in keys.items()}, threshold=3,
        domain=domain)
    return authorizer, keys


def approval(authorizer: QuorumAuthorizer,
             keys: dict[str, Ed25519PrivateKey], statement: bytes,
             before_root: bytes):
    return authorizer.approve(
        statement, before_root,
        {name: keys[name] for name in sorted(keys)[:3]})


def clients(node_uris: list[str], chain_id: str) -> list[AvalancheRpcClient]:
    return [
        AvalancheRpcClient(
            f"{uri.rstrip('/')}/ext/bc/{chain_id}",
            allow_insecure_localhost=True,
        )
        for uri in node_uris
    ]


def wait_for_roots(rpc_clients: list[AvalancheRpcClient], expected: bytes,
                   timeout_seconds: float = 30.0) -> list[str]:
    deadline = time.monotonic() + timeout_seconds
    last: list[str] = []
    while True:
        try:
            roots = [client.state_root() for client in rpc_clients]
            last = [root.hex() for root in roots]
            if roots and all(root == expected for root in roots):
                return last
        except Exception:  # a restarted node may briefly refuse connections
            pass
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"Avalanche nodes did not converge to {expected.hex()}; last={last}")
        time.sleep(0.2)


def restart_node(runner: Path, runner_endpoint: str, node: str,
                 plugin_dir: Path | None) -> float:
    started = time.perf_counter()
    command = [str(runner), "control", "restart-node", node,
               f"--endpoint={runner_endpoint}", "--request-timeout=3m"]
    if plugin_dir is not None:
        command.append(f"--plugin-dir={plugin_dir.resolve()}")
    completed = subprocess.run(command, check=False, capture_output=True,
                               text=True, timeout=180)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout)[-2000:]
        raise RuntimeError(f"Avalanche node restart failed: {detail}")
    healthy = subprocess.run(
        [str(runner), "control", "wait-for-healthy",
         f"--endpoint={runner_endpoint}", "--request-timeout=3m"],
        check=False, capture_output=True, text=True, timeout=180)
    if healthy.returncode != 0:
        detail = (healthy.stderr or healthy.stdout)[-2000:]
        raise RuntimeError(f"Avalanche network did not recover: {detail}")
    return (time.perf_counter() - started) * 1000


def run(args: argparse.Namespace) -> dict:
    started = time.perf_counter()
    rpc_clients = clients(args.node_uri, args.chain_id)
    network = rpc_clients[0].call("defmivm.network")
    if network.get("chainID") != args.chain_id:
        raise RuntimeError("Avalanche RPC chain identifier does not match the requested L1")
    initial_roots = [client.state_root() for client in rpc_clients]
    if len(set(initial_roots)) != 1:
        raise RuntimeError("Avalanche nodes disagree before the acceptance run")

    authorizer, keys = committee(args.chain_id)
    receipt_key = Ed25519PrivateKey.from_private_bytes(
        digest("qomm-avalanche-acceptance-receipt-key-v1"))
    facility = DefmiFacility(args.projection, authorizer, receipt_key)
    operation_timings: dict[str, float] = {}
    try:
        bridge = FacilityAvalancheBridge(facility, rpc_clients[0])

        # This exact fixture may already be accepted from an interrupted prior
        # run. In that case the bridge repairs the missing local projection.
        jpy = AssetDefinition(digest("asset:JPY"), "JPY", AssetKind.CASH, 0,
                              digest("terms:JPY"))
        before = time.perf_counter()
        bootstrap_root = facility.state_root()
        bootstrap = bridge.register_asset(
            jpy, approval(authorizer, keys, jpy.statement, bootstrap_root))
        operation_timings["bootstrap_or_recovery_ms"] = (
            time.perf_counter() - before) * 1000

        # Deliberately create the L1/local crash window.
        instrument = AssetDefinition(
            digest("asset:avalanche-acceptance-v1"), "QOMM-ACCEPT-V1",
            AssetKind.OTHER, 0, digest("terms:avalanche-acceptance-v1"))
        local_before_crash = facility.state_root()
        instrument_approval = approval(
            authorizer, keys, instrument.statement, local_before_crash)
        direct_tx = rpc_clients[0].issue_asset(
            instrument, instrument_approval, local_before_crash)
        direct_acceptance = rpc_clients[0].wait_accepted(direct_tx)
        if facility.state_root() != local_before_crash:
            raise RuntimeError("local projection changed before recovery was requested")
        before = time.perf_counter()
        recovered = bridge.register_asset(instrument, instrument_approval)
        operation_timings["crash_window_recovery_ms"] = (
            time.perf_counter() - before) * 1000
        if recovered.tx_id != direct_acceptance.tx_id:
            raise RuntimeError("crash recovery created a second transaction")

        left = AccountOpening(
            digest("account:avalanche-acceptance-left-v1"), instrument.asset_id,
            digest("commitment:left:0:v1"), digest("issuance:left:v1"))
        right = AccountOpening(
            digest("account:avalanche-acceptance-right-v1"), instrument.asset_id,
            digest("commitment:right:0:v1"), digest("issuance:right:v1"))
        before = time.perf_counter()
        left_accepted = bridge.open_account(
            left, approval(authorizer, keys, left.statement, facility.state_root()))
        right_accepted = bridge.open_account(
            right, approval(authorizer, keys, right.statement, facility.state_root()))
        operation_timings["two_accounts_ms"] = (time.perf_counter() - before) * 1000

        order = SettlementOrder(
            digest("operation:avalanche-acceptance-v1"),
            digest("nullifier:avalanche-acceptance-v1"),
            4_102_444_800,
            digest("zkpi:avalanche-acceptance-v1"),
            digest("proof:avalanche-acceptance-v1"),
            digest("market:avalanche-acceptance-v1"),
            (
                StateLeg(left.handle, instrument.asset_id,
                         digest("commitment:left:0:v1"),
                         digest("commitment:left:1:v1"), 0),
                StateLeg(right.handle, instrument.asset_id,
                         digest("commitment:right:0:v1"),
                         digest("commitment:right:1:v1"), 0),
            ),
        )
        before = time.perf_counter()
        local_receipt, settlement = bridge.settle(
            order, approval(authorizer, keys, order.statement, facility.state_root()),
            now=int(time.time()))
        operation_timings["settlement_ms"] = (time.perf_counter() - before) * 1000
        final_root = facility.state_root()
        roots_before_restart = wait_for_roots(rpc_clients, final_root)

        restart_ms = None
        roots_after_restart = roots_before_restart
        if args.runner is not None:
            restart_ms = restart_node(args.runner, args.runner_endpoint,
                                      args.restart_node, args.plugin_dir)
            rpc_clients = clients(args.node_uri, args.chain_id)
            roots_after_restart = wait_for_roots(rpc_clients, final_root)

        last_accepted = rpc_clients[0].call("defmivm.lastAccepted")
        result = {
            "passed": True,
            "environment": (
                f"{len(rpc_clients)} local AvalancheGo processes on one host; "
                "not geographically separate validators"),
            "evm_used": False,
            "network": network,
            "chain_id": args.chain_id,
            "external_binaries": {
                "avalanchego": tool_record(args.avalanchego),
                "avalanche_network_runner": tool_record(args.runner),
            },
            "nodes": len(rpc_clients),
            "initial_roots": [root.hex() for root in initial_roots],
            "final_root": final_root.hex(),
            "roots_before_restart": roots_before_restart,
            "roots_after_restart": roots_after_restart,
            "crash_recovery": {
                "same_transaction": recovered.tx_id == direct_acceptance.tx_id,
                "transaction_id": recovered.tx_id,
                "accepted_height": recovered.height,
            },
            "accepted_transitions": {
                "bootstrap_asset": {"tx_id": bootstrap.tx_id,
                                    "height": bootstrap.height},
                "instrument_asset": {"tx_id": recovered.tx_id,
                                     "height": recovered.height},
                "left_account": {"tx_id": left_accepted.tx_id,
                                 "height": left_accepted.height},
                "right_account": {"tx_id": right_accepted.tx_id,
                                  "height": right_accepted.height},
                "settlement": {"tx_id": settlement.tx_id,
                               "height": settlement.height},
            },
            "local_receipt": {
                "digest": local_receipt.digest.hex(),
                "before_root": local_receipt.before_root.hex(),
                "after_root": local_receipt.after_root.hex(),
                "verified_chain": facility.verify_receipt_chain(),
            },
            "operation_timings_ms": operation_timings,
            "restart": {"node": args.restart_node, "elapsed_ms": restart_ms,
                        "root_recovered": roots_after_restart == roots_before_restart},
            "last_accepted_block_id": last_accepted["blockID"],
            "elapsed_seconds": time.perf_counter() - started,
        }
        if not result["local_receipt"]["verified_chain"]:
            raise RuntimeError("local settlement receipt chain did not verify")
        return result
    finally:
        facility.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chain-id", required=True)
    parser.add_argument("--node-uri", action="append", required=True,
                        help="repeat for every AvalancheGo HTTP base URI")
    parser.add_argument("--projection", type=Path, required=True)
    parser.add_argument("--out", type=Path,
                        default=ROOT / "artifacts" / "avalanche_l1_acceptance.json")
    parser.add_argument("--runner", type=Path)
    parser.add_argument("--avalanchego", type=Path)
    parser.add_argument("--runner-endpoint", default="localhost:8080")
    parser.add_argument("--restart-node", default="node3")
    parser.add_argument("--plugin-dir", type=Path)
    args = parser.parse_args()
    if len(args.node_uri) < 3:
        raise SystemExit("at least three AvalancheGo nodes are required")
    result = run(args)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.out.with_suffix(args.out.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    temporary.replace(args.out)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
