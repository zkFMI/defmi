"""Avalanche L1 connection for the DeFMI state machine.

The target is a dedicated Avalanche custom VM, not a generic EVM contract.  The
VM orders and validates asset registration, account opening and settlement
transactions.  This module is the production-facing JSON-RPC client and the
crash-safe projection bridge into :mod:`defmi.facility`.

Only opaque commitments and their authorization are sent.  Payment amounts,
prices, account owners and MPC shares are not RPC fields.
"""

from __future__ import annotations

import json
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Mapping

from .facility import (AccountOpening, AssetDefinition, DefmiFacility,
                       QuorumApproval, SettlementOrder, SettlementReceipt)


class AvalancheRpcError(RuntimeError):
    """An authenticated request reached the L1 endpoint but did not succeed."""


def _approval_json(approval: QuorumApproval) -> dict:
    return {
        "statement": approval.statement.hex(),
        "signerEpoch": approval.signer_epoch,
        "domain": approval.domain,
        "beforeRoot": approval.before_root.hex(),
        "approvals": [
            {"nodeID": item.node_id, "signature": item.signature.hex()}
            for item in approval.approvals
        ],
    }


def _asset_json(asset: AssetDefinition) -> dict:
    return {
        "assetID": asset.asset_id.hex(),
        "code": asset.code,
        "kind": asset.kind.value,
        "decimals": asset.decimals,
        "termsDigest": asset.terms_digest.hex(),
    }


def _opening_json(opening: AccountOpening) -> dict:
    return {
        "handle": opening.handle.hex(),
        "assetID": opening.asset_id.hex(),
        "commitment": opening.commitment.hex(),
        "issuanceNonce": opening.issuance_nonce.hex(),
    }


def _order_json(order: SettlementOrder) -> dict:
    return {
        "operationID": order.operation_id.hex(),
        "nullifier": order.nullifier.hex(),
        "deadline": order.deadline,
        "paymentInstructionDigest": order.payment_instruction_digest.hex(),
        "proofDigest": order.proof_digest.hex(),
        "marketStatementDigest": order.market_statement_digest.hex(),
        "legs": [
            {
                "handle": leg.handle.hex(),
                "assetID": leg.asset_id.hex(),
                "beforeCommitment": leg.before_commitment.hex(),
                "afterCommitment": leg.after_commitment.hex(),
                "beforeSequence": leg.before_sequence,
            }
            for leg in order.legs
        ],
    }


@dataclass(frozen=True)
class AcceptedTransition:
    tx_id: str
    block_id: str
    height: int
    statement: bytes
    before_root: bytes
    after_root: bytes

    @classmethod
    def parse(cls, value: Mapping) -> "AcceptedTransition":
        try:
            parsed = cls(
                tx_id=str(value["txID"]),
                block_id=str(value["blockID"]),
                height=int(value["height"]),
                statement=bytes.fromhex(value["statement"]),
                before_root=bytes.fromhex(value["beforeRoot"]),
                after_root=bytes.fromhex(value["afterRoot"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AvalancheRpcError("L1 returned a malformed acceptance receipt") from exc
        if (
            parsed.height < 0
            or len(parsed.statement) != 32
            or len(parsed.before_root) != 32
            or len(parsed.after_root) != 32
        ):
            raise AvalancheRpcError("L1 acceptance receipt has invalid field widths")
        return parsed


class AvalancheRpcClient:
    """Small fail-closed client for the dedicated DeFMI VM JSON-RPC API."""

    def __init__(
        self,
        endpoint: str,
        *,
        timeout_seconds: float = 10.0,
        ssl_context: ssl.SSLContext | None = None,
        allow_insecure_localhost: bool = False,
        opener: Callable | None = None,
    ):
        parsed = urllib.parse.urlparse(endpoint)
        is_loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Avalanche endpoint must be an absolute HTTP(S) URL")
        if parsed.scheme != "https" and not (allow_insecure_localhost and is_loopback):
            raise ValueError("plaintext Avalanche RPC is allowed only for an explicit localhost test")
        if timeout_seconds <= 0:
            raise ValueError("RPC timeout must be positive")
        self.endpoint = endpoint
        self.timeout_seconds = timeout_seconds
        self.ssl_context = ssl_context
        self._opener = opener or urllib.request.urlopen
        self._next_id = 1

    def call(self, method: str, params: Mapping | None = None):
        request_id = self._next_id
        self._next_id += 1
        body = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method,
             "params": dict(params or {})},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        request = urllib.request.Request(
            self.endpoint,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with self._opener(
                request, timeout=self.timeout_seconds, context=self.ssl_context
            ) as response:
                raw = response.read(1_048_577)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise AvalancheRpcError(f"Avalanche RPC transport failed: {exc}") from exc
        if len(raw) > 1_048_576:
            raise AvalancheRpcError("Avalanche RPC response exceeded one MiB")
        try:
            envelope = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AvalancheRpcError("Avalanche RPC returned invalid JSON") from exc
        if not isinstance(envelope, dict) or envelope.get("id") != request_id:
            raise AvalancheRpcError("Avalanche RPC response identifier does not match")
        if envelope.get("error") is not None:
            error = envelope["error"]
            message = error.get("message", "unknown error") if isinstance(error, dict) else str(error)
            raise AvalancheRpcError(f"Avalanche RPC rejected the request: {message}")
        if "result" not in envelope:
            raise AvalancheRpcError("Avalanche RPC response has no result")
        return envelope["result"]

    def state_root(self) -> bytes:
        result = self.call("defmivm.stateRoot")
        try:
            root = bytes.fromhex(result["stateRoot"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AvalancheRpcError("L1 returned an invalid state root") from exc
        if len(root) != 32:
            raise AvalancheRpcError("L1 state root must be 32 bytes")
        return root

    def issue_asset(self, asset: AssetDefinition, approval: QuorumApproval,
                    expected_before_root: bytes) -> str:
        result = self.call(
            "defmivm.issueAsset", {"asset": _asset_json(asset),
                                   "approval": _approval_json(approval),
                                   "expectedBeforeRoot": expected_before_root.hex()}
        )
        return self._tx_id(result)

    def issue_account(self, opening: AccountOpening, approval: QuorumApproval,
                      expected_before_root: bytes) -> str:
        result = self.call(
            "defmivm.issueAccount", {"opening": _opening_json(opening),
                                     "approval": _approval_json(approval),
                                     "expectedBeforeRoot": expected_before_root.hex()}
        )
        return self._tx_id(result)

    def issue_settlement(self, order: SettlementOrder,
                         approval: QuorumApproval,
                         expected_before_root: bytes) -> str:
        result = self.call(
            "defmivm.issueSettlement", {"order": _order_json(order),
                                        "approval": _approval_json(approval),
                                        "expectedBeforeRoot": expected_before_root.hex()}
        )
        return self._tx_id(result)

    @staticmethod
    def _tx_id(result) -> str:
        if not isinstance(result, dict) or not isinstance(result.get("txID"), str):
            raise AvalancheRpcError("L1 did not return a transaction identifier")
        return result["txID"]

    def wait_accepted(self, tx_id: str, *, timeout_seconds: float = 30.0,
                      poll_seconds: float = 0.2) -> AcceptedTransition:
        if timeout_seconds <= 0 or poll_seconds <= 0:
            raise ValueError("acceptance timeout and polling interval must be positive")
        deadline = time.monotonic() + timeout_seconds
        while True:
            result = self.call("defmivm.txStatus", {"txID": tx_id})
            if not isinstance(result, dict):
                raise AvalancheRpcError("L1 returned a malformed transaction status")
            status = result.get("status")
            if status == "accepted":
                return AcceptedTransition.parse(result)
            if status == "rejected":
                raise AvalancheRpcError(
                    f"Avalanche consensus rejected transaction {tx_id}: "
                    f"{result.get('reason', 'unspecified')}"
                )
            # A node can briefly lose its local mempool view while a submitted
            # transaction is moving into consensus or while the node catches
            # up after a restart.  The returned transaction identifier is the
            # durable correlation key, so keep polling until acceptance,
            # explicit rejection or the caller's deadline.
            if status not in {"pending", "processing", "unknown"}:
                raise AvalancheRpcError(f"L1 returned unknown transaction status {status!r}")
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Avalanche transaction {tx_id} was not accepted in time")
            time.sleep(poll_seconds)


class FacilityAvalancheBridge:
    """Keeps the durable local projection exactly aligned with Avalanche."""

    def __init__(self, facility: DefmiFacility, client: AvalancheRpcClient):
        self.facility = facility
        self.client = client
        self._lock = threading.RLock()

    def _require_aligned(self) -> bytes:
        local = self.facility.state_root()
        remote = self.client.state_root()
        if local != remote:
            raise RuntimeError(
                f"DeFMI projection is out of sync (local={local.hex()}, L1={remote.hex()})"
            )
        return local

    @staticmethod
    def _check(receipt: AcceptedTransition, statement: bytes,
               before_root: bytes) -> None:
        if receipt.statement != statement:
            raise RuntimeError("Avalanche accepted a different authorized statement")
        if receipt.before_root != before_root:
            raise RuntimeError("Avalanche applied the transition to an unexpected state root")

    def _require_approval(self, statement: bytes, before_root: bytes,
                          approval: QuorumApproval) -> None:
        if not self.facility.authorizer.verify(statement, before_root, approval):
            raise PermissionError(
                "the transition approval is not bound to this L1 and state root")

    def register_asset(self, asset: AssetDefinition,
                       approval: QuorumApproval) -> AcceptedTransition:
        with self._lock:
            before = self.facility.state_root()
            self._require_approval(asset.statement, before, approval)
            accepted = self.client.wait_accepted(
                self.client.issue_asset(asset, approval, before))
            self._check(accepted, asset.statement, before)
            self.facility.register_asset(asset, approval)
            if self.facility.state_root() != accepted.after_root:
                raise RuntimeError("asset projection root differs from Avalanche")
            return accepted

    def open_account(self, opening: AccountOpening,
                     approval: QuorumApproval) -> AcceptedTransition:
        with self._lock:
            before = self.facility.state_root()
            self._require_approval(opening.statement, before, approval)
            accepted = self.client.wait_accepted(
                self.client.issue_account(opening, approval, before))
            self._check(accepted, opening.statement, before)
            self.facility.open_account(opening, approval)
            if self.facility.state_root() != accepted.after_root:
                raise RuntimeError("account projection root differs from Avalanche")
            return accepted

    def settle(self, order: SettlementOrder, approval: QuorumApproval,
               *, now: int) -> tuple[SettlementReceipt, AcceptedTransition]:
        with self._lock:
            before = self.facility.state_root()
            self._require_approval(order.statement, before, approval)
            accepted = self.client.wait_accepted(
                self.client.issue_settlement(order, approval, before)
            )
            self._check(accepted, order.statement, before)
            local = self.facility.settle(order, approval, now=now)
            if (local.before_root != accepted.before_root
                    or local.after_root != accepted.after_root):
                raise RuntimeError("settlement projection root differs from Avalanche")
            return local, accepted
