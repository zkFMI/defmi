import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from defmi.facility import (AccountOpening, AssetDefinition, AssetKind,
                            DefmiFacility, QuorumAuthorizer, SettlementOrder,
                            StateLeg)


def h(label):
    return hashlib.sha256(label.encode()).digest()


@pytest.fixture
def system(tmp_path):
    keys = {f"node-{i}": Ed25519PrivateKey.generate() for i in range(7)}
    authorizer = QuorumAuthorizer(
        {node: key.public_key() for node, key in keys.items()}, 3)
    facility = DefmiFacility(tmp_path / "defmi.sqlite3", authorizer,
                             Ed25519PrivateKey.generate())
    yield facility, authorizer, keys, tmp_path
    facility.close()


def approve(facility, authorizer, keys, statement, n=3):
    return authorizer.approve(statement, facility.state_root(),
                              dict(list(keys.items())[:n]))


def register(facility, authorizer, keys, label, kind, decimals=0):
    asset = AssetDefinition(h(f"asset:{label}"), label, kind, decimals,
                            h(f"terms:{label}"))
    facility.register_asset(asset, approve(facility, authorizer, keys, asset.statement))
    return asset


def opening(facility, authorizer, keys, label, asset, commitment):
    value = AccountOpening(h(f"account:{label}"), asset.asset_id,
                           commitment, h(f"issuance:{label}"))
    facility.open_account(value, approve(facility, authorizer, keys, value.statement))
    return value


def order(label, legs, deadline=1000):
    return SettlementOrder(
        h(f"operation:{label}"), h(f"nullifier:{label}"), deadline,
        h(f"zkpi:{label}"), h(f"proof:{label}"), h(f"market:{label}"),
        tuple(legs))


def leg(account, asset, before, after, sequence=0):
    return StateLeg(account.handle, asset.asset_id, before, after, sequence)


def test_one_state_machine_settles_security_fx_fund_and_carbon(system):
    facility, authorizer, keys, _ = system
    jpy = register(facility, authorizer, keys, "JPY", AssetKind.CASH)
    usd = register(facility, authorizer, keys, "USD", AssetKind.CASH, 2)
    security = register(facility, authorizer, keys, "JP0000000001", AssetKind.SECURITY)
    fund = register(facility, authorizer, keys, "FUND-A", AssetKind.FUND, 6)
    carbon = register(facility, authorizer, keys, "J-CREDIT", AssetKind.CARBON)
    assert facility.asset_count() == 5

    sec_s = opening(facility, authorizer, keys, "sec-s", security, h("s1"))
    sec_b = opening(facility, authorizer, keys, "sec-b", security, h("s2"))
    jpy_b = opening(facility, authorizer, keys, "jpy-b", jpy, h("j1"))
    jpy_s = opening(facility, authorizer, keys, "jpy-s", jpy, h("j2"))
    dvp = order("dvp", [leg(sec_s, security, h("s1"), h("s11")),
                         leg(sec_b, security, h("s2"), h("s12")),
                         leg(jpy_b, jpy, h("j1"), h("j11")),
                         leg(jpy_s, jpy, h("j2"), h("j12"))])
    receipt = facility.settle(
        dvp, approve(facility, authorizer, keys, dvp.statement), now=100)
    assert receipt.verify(facility.receipt_public_key)

    usd_a = opening(facility, authorizer, keys, "usd-a", usd, h("u1"))
    usd_b = opening(facility, authorizer, keys, "usd-b", usd, h("u2"))
    jpy_a = opening(facility, authorizer, keys, "jpy-a", jpy, h("ja1"))
    jpy_c = opening(facility, authorizer, keys, "jpy-c", jpy, h("ja2"))
    pvp = order("pvp", [leg(usd_a, usd, h("u1"), h("u11")),
                         leg(usd_b, usd, h("u2"), h("u12")),
                         leg(jpy_a, jpy, h("ja1"), h("ja11")),
                         leg(jpy_c, jpy, h("ja2"), h("ja12"))])
    facility.settle(
        pvp, approve(facility, authorizer, keys, pvp.statement), now=101)

    # Fund and carbon rails need no new settlement code.
    for asset, label in ((fund, "fund"), (carbon, "carbon")):
        a = opening(facility, authorizer, keys, f"{label}-a", asset, h(f"{label}1"))
        b = opening(facility, authorizer, keys, f"{label}-b", asset, h(f"{label}2"))
        transfer = order(label, [leg(a, asset, h(f"{label}1"), h(f"{label}11")),
                                 leg(b, asset, h(f"{label}2"), h(f"{label}12"))])
        facility.settle(
            transfer, approve(facility, authorizer, keys, transfer.statement), now=102)
    assert facility.verify_receipt_chain()


def test_stale_later_leg_rolls_back_every_leg_and_nullifier(system):
    facility, authorizer, keys, _ = system
    jpy = register(facility, authorizer, keys, "JPY", AssetKind.CASH)
    a = opening(facility, authorizer, keys, "a", jpy, h("a1"))
    b = opening(facility, authorizer, keys, "b", jpy, h("b1"))
    bad = order("bad", [leg(a, jpy, h("a1"), h("a2")),
                         leg(b, jpy, h("wrong"), h("b2"))])
    before = facility.state_root()
    with pytest.raises(ValueError, match="stale"):
        facility.settle(
            bad, approve(facility, authorizer, keys, bad.statement), now=100)
    assert facility.account(a.handle)[1:] == (h("a1"), 0)
    assert facility.state_root() == before


def test_quorum_replay_expiry_and_wrong_asset_fail_closed(system):
    facility, authorizer, keys, _ = system
    jpy = register(facility, authorizer, keys, "JPY", AssetKind.CASH)
    usd = register(facility, authorizer, keys, "USD", AssetKind.CASH)
    a = opening(facility, authorizer, keys, "a", jpy, h("a1"))
    b = opening(facility, authorizer, keys, "b", jpy, h("b1"))
    good = order("good", [leg(a, jpy, h("a1"), h("a2")),
                           leg(b, jpy, h("b1"), h("b2"))])
    with pytest.raises(PermissionError, match="k-of-n"):
        facility.settle(
            good, approve(facility, authorizer, keys, good.statement, 2), now=100)
    with pytest.raises(TimeoutError, match="expired"):
        facility.settle(
            good, approve(facility, authorizer, keys, good.statement), now=1001)
    receipt = facility.settle(
        good, approve(facility, authorizer, keys, good.statement), now=100)
    assert facility.settle(good, approve(facility, authorizer, keys, good.statement),
                           now=100).digest == receipt.digest
    assert facility.settle(good, approve(facility, authorizer, keys, good.statement),
                           now=1001).digest == receipt.digest

    reused = SettlementOrder(h("operation:other"), good.nullifier, 1000,
                             h("zkpi:other"), h("proof:other"), h("market:other"),
                             (StateLeg(a.handle, usd.asset_id, h("a2"), h("a3"), 1),))
    with pytest.raises(ValueError, match="nullifier|asset"):
        facility.settle(
            reused, approve(facility, authorizer, keys, reused.statement), now=101)


def test_persistence_backup_and_cost_meter_survive_restart(system):
    facility, authorizer, keys, tmp_path = system
    jpy = register(facility, authorizer, keys, "JPY", AssetKind.CASH)
    a = opening(facility, authorizer, keys, "a", jpy, h("a1"))
    b = opening(facility, authorizer, keys, "b", jpy, h("b1"))
    transfer = order("persist", [leg(a, jpy, h("a1"), h("a2")),
                                  leg(b, jpy, h("b1"), h("b2"))])
    receipt = facility.settle(
        transfer, approve(facility, authorizer, keys, transfer.statement), now=100)
    assert receipt.elapsed_ns > 0 and receipt.request_bytes > 0
    assert receipt.database_bytes_after >= receipt.database_bytes_before
    backup = facility.backup(tmp_path / "backup.sqlite3")
    assert backup.exists() and backup.stat().st_size > 0
    facility.close()
    reopened = DefmiFacility(tmp_path / "defmi.sqlite3", authorizer,
                             facility.receipt_key)
    try:
        assert reopened.account(a.handle)[1:] == (h("a2"), 1)
        assert reopened.verify_receipt_chain()
    finally:
        reopened.close()
    # Prevent fixture teardown from closing the already closed handle again.
    facility.close = lambda: None


def test_asset_and_account_retries_are_idempotent_but_conflicts_fail(system):
    facility, authorizer, keys, _ = system
    asset = AssetDefinition(h("asset:JPY"), "JPY", AssetKind.CASH, 0, h("terms:JPY"))
    asset_approval = approve(facility, authorizer, keys, asset.statement)
    facility.register_asset(asset, asset_approval)
    facility.register_asset(asset, asset_approval)
    conflicting_asset = AssetDefinition(asset.asset_id, "USD", AssetKind.CASH, 2,
                                        h("terms:USD"))
    with pytest.raises(ValueError, match="reused"):
        facility.register_asset(
            conflicting_asset,
            approve(facility, authorizer, keys, conflicting_asset.statement))

    account = AccountOpening(h("account:a"), asset.asset_id, h("a1"), h("issuance:a"))
    account_approval = approve(facility, authorizer, keys, account.statement)
    facility.open_account(account, account_approval)
    facility.open_account(account, account_approval)
    conflicting_account = AccountOpening(
        account.handle, asset.asset_id, h("a2"), h("issuance:b"))
    with pytest.raises(ValueError, match="reused"):
        facility.open_account(
            conflicting_account,
            approve(facility, authorizer, keys, conflicting_account.statement),
        )


def test_quorum_is_bound_to_unique_keys_domain_and_before_root(system):
    facility, authorizer, keys, _ = system
    repeated = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="two node identities"):
        QuorumAuthorizer(
            {"node-a": repeated.public_key(), "node-b": repeated.public_key()}, 2)

    pending = AssetDefinition(h("asset:pending"), "PENDING", AssetKind.OTHER,
                              0, h("terms:pending"))
    stale = approve(facility, authorizer, keys, pending.statement)
    register(facility, authorizer, keys, "OTHER", AssetKind.OTHER)
    with pytest.raises(PermissionError, match="k-of-n"):
        facility.register_asset(pending, stale)

    foreign = QuorumAuthorizer(
        {node: key.public_key() for node, key in keys.items()}, 3,
        domain="another-avalanche-chain")
    foreign_approval = foreign.approve(
        pending.statement, facility.state_root(), dict(list(keys.items())[:3]))
    with pytest.raises(PermissionError, match="k-of-n"):
        facility.register_asset(pending, foreign_approval)


def test_zero_identifiers_are_rejected_before_authorization():
    zero = bytes(32)
    with pytest.raises(ValueError, match="all-zero"):
        AssetDefinition(zero, "JPY", AssetKind.CASH, 0, h("terms")).body()
    with pytest.raises(ValueError, match="all-zero"):
        AccountOpening(h("handle"), h("asset"), zero, h("nonce")).body()
    with pytest.raises(ValueError, match="all-zero"):
        SettlementOrder(
            h("operation"), zero, 1000, h("zkpi"), h("proof"), h("market"),
            (StateLeg(h("handle"), h("asset"), h("before"), h("after"), 0),),
        ).body()
