"""Chain-neutral, durable DeFMI settlement facility.

This is the state machine a CSD, cash rail, fund register, commodity register or
environmental-value register needs from DeFMI.  Values remain 32-byte
commitments.  A configurable k-of-n QOMM quorum signs the exact transition after
checking zkPI and the proofs.  SQLite provides crash-atomic multi-leg commits,
stale-state detection, replay protection, recovery and online backup.

No field assumes an equity.  The same transaction settles security DvP, FX PvP,
fund units, commodities or carbon instruments as long as the assets have been
registered and each account stays on its declared asset rail.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DOMAIN = b"QOMM:DEFMI:FACILITY:v2"
ASSET_DOMAIN = b"QOMM:DEFMI:ASSET:v1"
ACCOUNT_DOMAIN = b"QOMM:DEFMI:ACCOUNT:v1"
SETTLEMENT_DOMAIN = b"QOMM:DEFMI:SETTLEMENT:v1"
RECEIPT_DOMAIN = b"QOMM:DEFMI:RECEIPT:v1"
ZERO = b"\x00" * 32


def _hex(value: bytes, name: str) -> str:
    if len(value) != 32:
        raise ValueError(f"{name} must be 32 bytes")
    return value.hex()


def _nonzero_hex(value: bytes, name: str) -> str:
    encoded = _hex(value, name)
    if value == ZERO:
        raise ValueError(f"{name} cannot be the all-zero identifier")
    return encoded


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()


def _digest(domain: bytes, value) -> bytes:
    return hashlib.sha256(domain + _canonical(value)).digest()


class AssetKind(str, Enum):
    CASH = "cash"
    SECURITY = "security"
    FUND = "fund"
    COMMODITY = "commodity"
    CARBON = "carbon"
    OTHER = "other"


@dataclass(frozen=True)
class AssetDefinition:
    asset_id: bytes
    code: str
    kind: AssetKind
    decimals: int
    terms_digest: bytes

    def body(self) -> dict:
        if not self.code or not 0 <= self.decimals <= 30:
            raise ValueError("asset code or decimal precision is invalid")
        return {"asset_id": _nonzero_hex(self.asset_id, "asset_id"), "code": self.code,
                "kind": self.kind.value, "decimals": self.decimals,
                "terms_digest": _nonzero_hex(self.terms_digest, "terms_digest")}

    @property
    def statement(self) -> bytes:
        return _digest(ASSET_DOMAIN, self.body())


@dataclass(frozen=True)
class AccountOpening:
    handle: bytes
    asset_id: bytes
    commitment: bytes
    issuance_nonce: bytes

    def body(self) -> dict:
        return {"handle": _nonzero_hex(self.handle, "handle"),
                "asset_id": _nonzero_hex(self.asset_id, "asset_id"),
                "commitment": _nonzero_hex(self.commitment, "commitment"),
                "issuance_nonce": _nonzero_hex(self.issuance_nonce, "issuance_nonce")}

    @property
    def statement(self) -> bytes:
        return _digest(ACCOUNT_DOMAIN, self.body())


@dataclass(frozen=True)
class StateLeg:
    handle: bytes
    asset_id: bytes
    before_commitment: bytes
    after_commitment: bytes
    before_sequence: int

    def body(self) -> dict:
        if self.before_sequence < 0:
            raise ValueError("account sequence cannot be negative")
        return {"handle": _nonzero_hex(self.handle, "handle"),
                "asset_id": _nonzero_hex(self.asset_id, "asset_id"),
                "before_commitment": _nonzero_hex(self.before_commitment,
                                                   "before_commitment"),
                "after_commitment": _nonzero_hex(self.after_commitment,
                                                  "after_commitment"),
                "before_sequence": self.before_sequence}


@dataclass(frozen=True)
class SettlementOrder:
    operation_id: bytes
    nullifier: bytes
    deadline: int
    payment_instruction_digest: bytes
    proof_digest: bytes
    market_statement_digest: bytes
    legs: tuple[StateLeg, ...]

    def body(self) -> dict:
        if self.deadline <= 0 or not self.legs:
            raise ValueError("settlement needs a positive deadline and at least one leg")
        handles = [leg.handle for leg in self.legs]
        if len(set(handles)) != len(handles):
            raise ValueError("a settlement cannot update one handle twice")
        return {
            "operation_id": _nonzero_hex(self.operation_id, "operation_id"),
            "nullifier": _nonzero_hex(self.nullifier, "nullifier"),
            "deadline": self.deadline,
            "payment_instruction_digest": _nonzero_hex(
                self.payment_instruction_digest, "payment_instruction_digest"),
            "proof_digest": _nonzero_hex(self.proof_digest, "proof_digest"),
            "market_statement_digest": _nonzero_hex(
                self.market_statement_digest, "market_statement_digest"),
            "legs": [leg.body() for leg in self.legs],
        }

    @property
    def statement(self) -> bytes:
        return _digest(SETTLEMENT_DOMAIN, self.body())


@dataclass(frozen=True)
class NodeApproval:
    node_id: str
    signature: bytes


@dataclass(frozen=True)
class QuorumApproval:
    statement: bytes
    signer_epoch: int
    domain: str
    before_root: bytes
    approvals: tuple[NodeApproval, ...]


class QuorumAuthorizer:
    def __init__(self, nodes: dict[str, Ed25519PublicKey], threshold: int,
                 epoch: int = 1, domain: str = "defmi:local"):
        if (not nodes or len(nodes) > 64 or not 1 <= threshold <= len(nodes)
                or epoch <= 0):
            raise ValueError("invalid k-of-n signer configuration")
        allowed_node = frozenset(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/+-")
        if any(not isinstance(name, str) or not 1 <= len(name) <= 128
               or any(char not in allowed_node for char in name)
               for name in nodes):
            raise ValueError("quorum node identifiers contain invalid characters")
        try:
            domain_bytes = domain.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("approval domain must be ASCII") from exc
        if not 1 <= len(domain_bytes) <= 128:
            raise ValueError("approval domain must be between 1 and 128 bytes")
        encoded_keys = [key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            for key in nodes.values()]
        if any(value == bytes(32) for value in encoded_keys):
            raise ValueError("quorum public keys cannot use the all-zero encoding")
        if len(set(encoded_keys)) != len(encoded_keys):
            raise ValueError("one quorum public key cannot occupy two node identities")
        self.nodes = dict(nodes)
        self.threshold = threshold
        self.epoch = epoch
        self.domain = domain

    def verify(self, expected: bytes, before_root: bytes,
               approval: QuorumApproval) -> bool:
        if len(expected) != 32 or approval.statement != expected:
            return False
        if (len(before_root) != 32 or approval.before_root != before_root
                or approval.domain != self.domain
                or approval.signer_epoch != self.epoch
                or len(approval.approvals) > 64):
            return False
        seen = set()
        valid = 0
        domain = self.domain.encode("ascii")
        body = (DOMAIN + self.epoch.to_bytes(8, "big")
                + len(domain).to_bytes(2, "big") + domain
                + before_root + expected)
        for signed in approval.approvals:
            if signed.node_id in seen or signed.node_id not in self.nodes:
                continue
            seen.add(signed.node_id)
            try:
                self.nodes[signed.node_id].verify(signed.signature, body)
                valid += 1
            except InvalidSignature:
                pass
        return valid >= self.threshold

    def approve(self, statement: bytes, before_root: bytes,
                signers: dict[str, Ed25519PrivateKey]) -> QuorumApproval:
        if len(statement) != 32 or len(before_root) != 32:
            raise ValueError("statement and before_root must be 32 bytes")
        if not signers or not set(signers).issubset(self.nodes):
            raise ValueError("approval signers must be configured quorum nodes")
        for node, key in signers.items():
            supplied = key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            configured = self.nodes[node].public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            if supplied != configured:
                raise ValueError("approval signer key does not match the quorum configuration")
        domain = self.domain.encode("ascii")
        body = (DOMAIN + self.epoch.to_bytes(8, "big")
                + len(domain).to_bytes(2, "big") + domain
                + before_root + statement)
        return QuorumApproval(
            statement, self.epoch, self.domain, before_root,
            tuple(NodeApproval(node, key.sign(body))
                  for node, key in sorted(signers.items())))


@dataclass(frozen=True)
class SettlementReceipt:
    operation_id: bytes
    nullifier: bytes
    statement: bytes
    before_root: bytes
    after_root: bytes
    previous_receipt: bytes
    committed_at_ns: int
    elapsed_ns: int
    request_bytes: int
    response_bytes: int
    database_bytes_before: int
    database_bytes_after: int
    signature: bytes

    def unsigned(self) -> bytes:
        return RECEIPT_DOMAIN + _canonical({
            "operation_id": _hex(self.operation_id, "operation_id"),
            "nullifier": _hex(self.nullifier, "nullifier"),
            "statement": _hex(self.statement, "statement"),
            "before_root": _hex(self.before_root, "before_root"),
            "after_root": _hex(self.after_root, "after_root"),
            "previous_receipt": _hex(self.previous_receipt, "previous_receipt"),
            "committed_at_ns": self.committed_at_ns,
            "elapsed_ns": self.elapsed_ns,
            "request_bytes": self.request_bytes,
            "response_bytes": self.response_bytes,
            "database_bytes_before": self.database_bytes_before,
            "database_bytes_after": self.database_bytes_after,
        })

    @property
    def digest(self) -> bytes:
        return hashlib.sha256(self.unsigned() + self.signature).digest()

    def verify(self, key: Ed25519PublicKey) -> bool:
        try:
            key.verify(self.signature, self.unsigned())
            return True
        except InvalidSignature:
            return False


class DefmiFacility:
    def __init__(self, path: Path | str, authorizer: QuorumAuthorizer,
                 receipt_key: Ed25519PrivateKey):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.authorizer = authorizer
        self.receipt_key = receipt_key
        self.receipt_public_key = receipt_key.public_key()
        self._lock = threading.RLock()
        self.db = sqlite3.connect(self.path, isolation_level=None,
                                  check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    def _migrate(self) -> None:
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1):
            raise RuntimeError(f"unsupported DeFMI schema version {version}")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS assets (
                asset_id BLOB PRIMARY KEY CHECK(length(asset_id)=32),
                code TEXT NOT NULL,
                kind TEXT NOT NULL,
                decimals INTEGER NOT NULL,
                terms_digest BLOB NOT NULL CHECK(length(terms_digest)=32),
                active INTEGER NOT NULL DEFAULT 1,
                statement BLOB NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS accounts (
                handle BLOB PRIMARY KEY CHECK(length(handle)=32),
                asset_id BLOB NOT NULL REFERENCES assets(asset_id),
                commitment BLOB NOT NULL CHECK(length(commitment)=32),
                sequence INTEGER NOT NULL,
                opening_statement BLOB NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS nullifiers (
                nullifier BLOB PRIMARY KEY CHECK(length(nullifier)=32),
                deadline INTEGER NOT NULL,
                statement BLOB NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS receipts (
                operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=32),
                nullifier BLOB NOT NULL UNIQUE,
                statement BLOB NOT NULL UNIQUE,
                receipt_json BLOB NOT NULL,
                receipt_digest BLOB NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            PRAGMA user_version=1;
        """)
        self.db.execute("INSERT OR IGNORE INTO metadata(key,value) VALUES('state_root',?)",
                        (ZERO,))
        self.db.execute("INSERT OR IGNORE INTO metadata(key,value) VALUES('last_receipt',?)",
                        (ZERO,))

    def _size(self) -> int:
        page_count = self.db.execute("PRAGMA page_count").fetchone()[0]
        page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
        return page_count * page_size

    def _root(self) -> bytes:
        h = hashlib.sha256(b"QOMM:DEFMI:STATE:v1")
        for row in self.db.execute(
                "SELECT asset_id,code,kind,decimals,terms_digest,active "
                "FROM assets ORDER BY asset_id"):
            h.update(_canonical([row[0].hex(), row[1], row[2], row[3],
                                 row[4].hex(), row[5]]))
        for row in self.db.execute(
                "SELECT handle,asset_id,commitment,sequence FROM accounts ORDER BY handle"):
            h.update(row[0] + row[1] + row[2] + row[3].to_bytes(8, "big"))
        for row in self.db.execute(
                "SELECT nullifier,deadline,statement FROM nullifiers ORDER BY nullifier"):
            h.update(row[0] + row[1].to_bytes(8, "big") + row[2])
        return h.digest()

    def _require_quorum(self, statement: bytes, before_root: bytes,
                        approval: QuorumApproval) -> None:
        if not self.authorizer.verify(statement, before_root, approval):
            raise PermissionError("the transition lacks the configured k-of-n approval")

    def register_asset(self, asset: AssetDefinition,
        approval: QuorumApproval) -> None:
        body = asset.body()
        with self._lock:
            existing = self.db.execute(
                "SELECT statement FROM assets WHERE asset_id=?", (asset.asset_id,)
            ).fetchone()
            if existing is not None:
                if existing[0] == asset.statement:
                    return
                raise ValueError("asset identifier was reused for another definition")
            self._require_quorum(asset.statement, self._root(), approval)
            try:
                self.db.execute(
                    "INSERT INTO assets(asset_id,code,kind,decimals,terms_digest,statement) "
                    "VALUES(?,?,?,?,?,?)",
                    (asset.asset_id, asset.code, asset.kind.value, asset.decimals,
                     asset.terms_digest, asset.statement))
            except sqlite3.IntegrityError as exc:
                raise ValueError("asset or authorization is already registered") from exc

    def open_account(self, opening: AccountOpening,
        approval: QuorumApproval) -> None:
        opening.body()
        with self._lock:
            existing = self.db.execute(
                "SELECT opening_statement FROM accounts WHERE handle=?",
                (opening.handle,),
            ).fetchone()
            if existing is not None:
                if existing[0] == opening.statement:
                    return
                raise ValueError("account handle was reused for another opening")
            self._require_quorum(opening.statement, self._root(), approval)
            active = self.db.execute(
                "SELECT active FROM assets WHERE asset_id=?", (opening.asset_id,)).fetchone()
            if active is None or not active[0]:
                raise ValueError("account asset is unknown or inactive")
            try:
                self.db.execute(
                    "INSERT INTO accounts(handle,asset_id,commitment,sequence,opening_statement) "
                    "VALUES(?,?,?,0,?)",
                    (opening.handle, opening.asset_id, opening.commitment,
                     opening.statement))
            except sqlite3.IntegrityError as exc:
                raise ValueError("account or issuance authorization already exists") from exc

    def _receipt_from_json(self, raw: bytes) -> SettlementReceipt:
        data = json.loads(raw)
        return SettlementReceipt(
            operation_id=bytes.fromhex(data["operation_id"]),
            nullifier=bytes.fromhex(data["nullifier"]),
            statement=bytes.fromhex(data["statement"]),
            before_root=bytes.fromhex(data["before_root"]),
            after_root=bytes.fromhex(data["after_root"]),
            previous_receipt=bytes.fromhex(data["previous_receipt"]),
            committed_at_ns=data["committed_at_ns"], elapsed_ns=data["elapsed_ns"],
            request_bytes=data["request_bytes"], response_bytes=data["response_bytes"],
            database_bytes_before=data["database_bytes_before"],
            database_bytes_after=data["database_bytes_after"],
            signature=bytes.fromhex(data["signature"]))

    @staticmethod
    def _receipt_json(receipt: SettlementReceipt) -> bytes:
        return _canonical({
            "operation_id": receipt.operation_id.hex(),
            "nullifier": receipt.nullifier.hex(),
            "statement": receipt.statement.hex(),
            "before_root": receipt.before_root.hex(),
            "after_root": receipt.after_root.hex(),
            "previous_receipt": receipt.previous_receipt.hex(),
            "committed_at_ns": receipt.committed_at_ns,
            "elapsed_ns": receipt.elapsed_ns,
            "request_bytes": receipt.request_bytes,
            "response_bytes": receipt.response_bytes,
            "database_bytes_before": receipt.database_bytes_before,
            "database_bytes_after": receipt.database_bytes_after,
            "signature": receipt.signature.hex(),
        })

    def settle(self, order: SettlementOrder, approval: QuorumApproval,
               *, now: int) -> SettlementReceipt:
        request = order.body()
        request_bytes = len(_canonical(request))
        started = time.perf_counter_ns()
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                existing = self.db.execute(
                    "SELECT statement,receipt_json FROM receipts WHERE operation_id=?",
                    (order.operation_id,)).fetchone()
                if existing is not None:
                    if existing[0] != order.statement:
                        raise ValueError("operation identifier was reused for another settlement")
                    self.db.execute("ROLLBACK")
                    return self._receipt_from_json(existing[1])
                before_root = self._root()
                self._require_quorum(order.statement, before_root, approval)
                if now > order.deadline:
                    raise TimeoutError("payment instruction has expired")
                seen = self.db.execute(
                    "SELECT statement FROM nullifiers WHERE nullifier=?",
                    (order.nullifier,)).fetchone()
                if seen is not None:
                    raise ValueError("payment nullifier was already settled")
                database_before = self._size()
                for leg in order.legs:
                    row = self.db.execute(
                        "SELECT asset_id,commitment,sequence FROM accounts WHERE handle=?",
                        (leg.handle,)).fetchone()
                    if row is None:
                        raise ValueError("settlement names an unknown account")
                    if row[0] != leg.asset_id:
                        raise ValueError("settlement leg is on the wrong asset rail")
                    if row[1] != leg.before_commitment or row[2] != leg.before_sequence:
                        raise ValueError("settlement was proved against stale account state")
                    active = self.db.execute(
                        "SELECT active FROM assets WHERE asset_id=?",
                        (leg.asset_id,)).fetchone()
                    if active is None or not active[0]:
                        raise ValueError("settlement uses an inactive asset")
                self.db.execute(
                    "INSERT INTO nullifiers(nullifier,deadline,statement) VALUES(?,?,?)",
                    (order.nullifier, order.deadline, order.statement))
                for leg in order.legs:
                    self.db.execute(
                        "UPDATE accounts SET commitment=?,sequence=sequence+1 WHERE handle=?",
                        (leg.after_commitment, leg.handle))
                after_root = self._root()
                database_after = self._size()
                previous = self.db.execute(
                    "SELECT value FROM metadata WHERE key='last_receipt'").fetchone()[0]
                elapsed = time.perf_counter_ns() - started
                candidate = SettlementReceipt(
                    order.operation_id, order.nullifier, order.statement,
                    before_root, after_root, previous, time.time_ns(), elapsed,
                    request_bytes, 0, database_before, database_after, b"")
                # response_bytes is part of the signature. Iterate once because
                # its decimal width can change the encoded receipt length.
                response_bytes = len(self._receipt_json(SettlementReceipt(
                    **{**candidate.__dict__, "signature": bytes(64)})))
                candidate = SettlementReceipt(
                    **{**candidate.__dict__, "response_bytes": response_bytes})
                signed = SettlementReceipt(
                    **{**candidate.__dict__,
                       "signature": self.receipt_key.sign(candidate.unsigned())})
                raw = self._receipt_json(signed)
                self.db.execute(
                    "INSERT INTO receipts(operation_id,nullifier,statement,receipt_json,receipt_digest) "
                    "VALUES(?,?,?,?,?)",
                    (order.operation_id, order.nullifier, order.statement, raw,
                     signed.digest))
                self.db.execute("UPDATE metadata SET value=? WHERE key='state_root'",
                                (after_root,))
                self.db.execute("UPDATE metadata SET value=? WHERE key='last_receipt'",
                                (signed.digest,))
                self.db.execute("COMMIT")
                return signed
            except Exception:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise

    def account(self, handle: bytes) -> tuple[bytes, bytes, int] | None:
        row = self.db.execute(
            "SELECT asset_id,commitment,sequence FROM accounts WHERE handle=?",
            (handle,)).fetchone()
        return None if row is None else (row[0], row[1], row[2])

    def asset_count(self) -> int:
        return self.db.execute("SELECT count(*) FROM assets").fetchone()[0]

    def state_root(self) -> bytes:
        with self._lock:
            calculated = self._root()
            stored = self.db.execute(
                "SELECT value FROM metadata WHERE key='state_root'").fetchone()[0]
            # Registrations/openings deliberately do not update the settlement
            # receipt chain, but the root is still calculable and current.
            return calculated if calculated != stored else stored

    def verify_receipt_chain(self) -> bool:
        previous = ZERO
        rows = self.db.execute(
            "SELECT receipt_json,receipt_digest FROM receipts ORDER BY rowid").fetchall()
        for raw, digest in rows:
            receipt = self._receipt_from_json(raw)
            if receipt.previous_receipt != previous:
                return False
            if not receipt.verify(self.receipt_public_key) or receipt.digest != digest:
                return False
            previous = digest
        stored = self.db.execute(
            "SELECT value FROM metadata WHERE key='last_receipt'").fetchone()[0]
        return previous == stored

    def backup(self, target: Path | str) -> Path:
        target = Path(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, sqlite3.connect(target) as destination:
            self.db.backup(destination)
        return target

    def close(self) -> None:
        with self._lock:
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.db.close()
