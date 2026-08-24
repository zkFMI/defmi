import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from defmi.avalanche import (AcceptedTransition, AvalancheRpcClient,
                             FacilityAvalancheBridge)
from defmi.facility import (AccountOpening, AssetDefinition, AssetKind,
                            DefmiFacility, QuorumAuthorizer, SettlementOrder,
                            StateLeg)


def h(label):
    return hashlib.sha256(label.encode()).digest()


def approved(authorizer, keys, statement, before_root):
    return authorizer.approve(statement, before_root,
                              dict(list(keys.items())[:3]))


class InMemoryAvalanche:
    """Deterministic contract stub; full socket acceptance is a separate test."""

    def __init__(self, mirror):
        self.mirror = mirror
        self.pending = {}
        self.by_statement = {}
        self.height = 0

    def state_root(self):
        return self.mirror.state_root()

    def _accept(self, statement, expected_before_root, apply):
        existing = self.by_statement.get(statement)
        if existing is not None:
            return existing
        before = self.mirror.state_root()
        if before != expected_before_root:
            raise RuntimeError("expected state root does not match")
        apply()
        after = self.mirror.state_root()
        self.height += 1
        tx_id = h(f"tx:{self.height}").hex()
        self.pending[tx_id] = AcceptedTransition(
            tx_id, h(f"block:{self.height}").hex(), self.height,
            statement, before, after)
        self.by_statement[statement] = tx_id
        return tx_id

    def issue_asset(self, asset, approval, expected_before_root):
        return self._accept(asset.statement, expected_before_root,
                            lambda: self.mirror.register_asset(asset, approval))

    def issue_account(self, opening, approval, expected_before_root):
        return self._accept(opening.statement, expected_before_root,
                            lambda: self.mirror.open_account(opening, approval))

    def issue_settlement(self, order, approval, expected_before_root):
        return self._accept(order.statement, expected_before_root,
                            lambda: self.mirror.settle(order, approval, now=100))

    def wait_accepted(self, tx_id):
        return self.pending[tx_id]


def test_bridge_registers_opens_and_settles_without_projection_drift(tmp_path):
    keys = {f"node-{i}": Ed25519PrivateKey.generate() for i in range(7)}
    authorizer = QuorumAuthorizer(
        {node: key.public_key() for node, key in keys.items()}, 3)
    local = DefmiFacility(tmp_path / "local.sqlite3", authorizer,
                          Ed25519PrivateKey.generate())
    mirror = DefmiFacility(tmp_path / "chain.sqlite3", authorizer,
                           Ed25519PrivateKey.generate())
    bridge = FacilityAvalancheBridge(local, InMemoryAvalanche(mirror))
    try:
        asset = AssetDefinition(h("asset:JPY"), "JPY", AssetKind.CASH, 0,
                                h("terms:JPY"))
        bridge.register_asset(
            asset, approved(authorizer, keys, asset.statement, local.state_root()))
        left = AccountOpening(h("left"), asset.asset_id, h("l0"), h("li"))
        right = AccountOpening(h("right"), asset.asset_id, h("r0"), h("ri"))
        bridge.open_account(
            left, approved(authorizer, keys, left.statement, local.state_root()))
        bridge.open_account(
            right, approved(authorizer, keys, right.statement, local.state_root()))
        order = SettlementOrder(
            h("operation"), h("nullifier"), 1000, h("zkpi"), h("proof"),
            h("market"),
            (StateLeg(left.handle, asset.asset_id, h("l0"), h("l1"), 0),
             StateLeg(right.handle, asset.asset_id, h("r0"), h("r1"), 0)),
        )
        receipt, accepted = bridge.settle(
            order,
            approved(authorizer, keys, order.statement, local.state_root()), now=100)
        assert receipt.after_root == accepted.after_root == mirror.state_root()
        assert local.state_root() == mirror.state_root()
    finally:
        local.close()
        mirror.close()


def test_bridge_stops_before_submission_when_roots_differ(tmp_path):
    keys = {f"node-{i}": Ed25519PrivateKey.generate() for i in range(7)}
    authorizer = QuorumAuthorizer(
        {node: key.public_key() for node, key in keys.items()}, 3)
    local = DefmiFacility(tmp_path / "local.sqlite3", authorizer,
                          Ed25519PrivateKey.generate())
    mirror = DefmiFacility(tmp_path / "chain.sqlite3", authorizer,
                           Ed25519PrivateKey.generate())
    client = InMemoryAvalanche(mirror)
    bridge = FacilityAvalancheBridge(local, client)
    try:
        asset = AssetDefinition(h("asset:JPY"), "JPY", AssetKind.CASH, 0,
                                h("terms:JPY"))
        other = AssetDefinition(h("asset:USD"), "USD", AssetKind.CASH, 0,
                                h("terms:USD"))
        mirror.register_asset(
            other, approved(authorizer, keys, other.statement, mirror.state_root()))
        with pytest.raises(RuntimeError, match="expected state root"):
            bridge.register_asset(
                asset, approved(authorizer, keys, asset.statement, local.state_root()))
    finally:
        local.close()
        mirror.close()


def test_bridge_recovers_when_l1_accepted_before_local_projection(tmp_path):
    keys = {f"node-{i}": Ed25519PrivateKey.generate() for i in range(7)}
    authorizer = QuorumAuthorizer(
        {node: key.public_key() for node, key in keys.items()}, 3)
    local = DefmiFacility(tmp_path / "local.sqlite3", authorizer,
                          Ed25519PrivateKey.generate())
    mirror = DefmiFacility(tmp_path / "chain.sqlite3", authorizer,
                           Ed25519PrivateKey.generate())
    client = InMemoryAvalanche(mirror)
    bridge = FacilityAvalancheBridge(local, client)
    try:
        asset = AssetDefinition(h("asset:JPY"), "JPY", AssetKind.CASH, 0,
                                h("terms:JPY"))
        approval = approved(authorizer, keys, asset.statement, local.state_root())
        accepted_tx = client.issue_asset(asset, approval, local.state_root())

        recovered = bridge.register_asset(asset, approval)

        assert recovered.tx_id == accepted_tx
        assert local.state_root() == mirror.state_root()
        assert local.asset_count() == 1
    finally:
        local.close()
        mirror.close()


def test_rpc_requires_tls_except_explicit_local_test():
    with pytest.raises(ValueError, match="plaintext"):
        AvalancheRpcClient("http://example.com/ext/bc/id")
    AvalancheRpcClient("http://127.0.0.1:9650/ext/bc/id",
                       allow_insecure_localhost=True)


def test_wait_accepted_treats_unknown_as_transient_consensus_state():
    client = object.__new__(AvalancheRpcClient)
    statuses = iter([
        {"status": "unknown", "txID": "tx"},
        {"status": "processing", "txID": "tx"},
        {"status": "accepted", "txID": "tx", "blockID": "block",
         "height": 1, "statement": "11" * 32,
         "beforeRoot": "22" * 32, "afterRoot": "33" * 32},
    ])
    client.call = lambda _method, _params: next(statuses)

    accepted = client.wait_accepted("tx", timeout_seconds=1,
                                    poll_seconds=0.001)

    assert accepted.tx_id == "tx"
    assert accepted.height == 1
