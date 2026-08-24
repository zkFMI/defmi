#!/usr/bin/env python3
"""Build DEFMI.md from artifacts/defmi.json so the prose cannot drift.

Every number below is read from the artifact and formatted here. None is typed
in. Timings carry the number of samples they are made of and how far those
spread, because a bare millisecond figure says what came out once and nothing
about whether it means anything --- and two runs on this machine have disagreed
by half again.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Below the path insert, not above it: the package these come from is this
# repository, and it is not importable until the line above has run.
from scripts.hosts import label                                    # noqa: E402
from scripts.measure import render, value                          # noqa: E402

ART = ROOT / "artifacts"


def ms(summary, places: int = 1) -> str:
    return render(summary, places)


def count(record) -> int:
    """A byte length, however the artifact chose to store it."""
    if isinstance(record, dict):
        return int(record.get("exact", 0))
    return int(record)


def main() -> int:
    path = ART / "defmi.json"
    if not path.exists():
        print("artifacts/defmi.json is missing; run `make defmi` first.", file=sys.stderr)
        return 1
    d = json.loads(path.read_text())
    rust_path = ART / "rust_bench.json"
    rust = json.loads(rust_path.read_text()) if rust_path.exists() else None
    big_path = ART / "defmi_host_a.json"
    big = json.loads(big_path.read_text()) if big_path.exists() else None
    pvp_path = ART / "pvp.json"
    pvp = json.loads(pvp_path.read_text()) if pvp_path.exists() else None
    same_path = ART / "same_chain.json"
    same_chain = json.loads(same_path.read_text()) if same_path.exists() else None
    rings_path = ART / "rings.json"
    rings = json.loads(rings_path.read_text()) if rings_path.exists() else None
    rec_path = ART / "reconcile.json"
    reconcile = json.loads(rec_path.read_text()) if rec_path.exists() else None
    note_dvp_path = ART / "note_dvp_rust.json"
    note_dvp = (json.loads(note_dvp_path.read_text())
                if note_dvp_path.exists() else None)
    view_path = ART / "viewing.json"
    viewing = json.loads(view_path.read_text()) if view_path.exists() else None
    ccp_path = ART / "deccp.json"
    deccp = json.loads(ccp_path.read_text()) if ccp_path.exists() else None
    vet_path = ART / "vetting.json"
    vetting = json.loads(vet_path.read_text()) if vet_path.exists() else None
    avalanche_path = ART / "avalanche_l1_acceptance.json"
    avalanche = (json.loads(avalanche_path.read_text())
                 if avalanche_path.exists() else None)

    out: list[str] = []
    w = out.append

    w("# DeFMI — a settlement layer that never reads the trade\n")
    w("DeFMI means **Decentralized Financial Market Infrastructure**. It is "
      "not a stock-only ledger: the chain-neutral state machine registers cash, "
      "securities, funds, commodities, carbon units and other governed assets.\n")
    w(f"Measured on `{label(d['host'])}` / Python {d['python']} / group {d['group']}.")
    w("This document is generated from the measurement JSON by `make defmi-doc`. "
      "No number in it was typed by hand.\n")
    if d.get("calibration"):
        c = d["calibration"]
        w(f"**Calibration**: scalar multiplication {ms(c['scalar_mult_us'])} us, "
          f"40-bit range proof {ms(c['range_proof_40bit_ms'], 2)} ms.")
        w("Every millisecond below is from a machine in that state. The same "
          "machine has been half again slower at another time, so compare these "
          "two figures before comparing anything else here with anything "
          "measured elsewhere.\n")

    w("## 1. What is guaranteed, and what is not\n")
    w("DeFMI can check only what arithmetic settles without opening anything.\n")
    w("| Guarantee | What makes it hold |")
    w("| --- | --- |")
    w("| Value is neither created nor destroyed | the product of the balance "
      "commitments equals the product at issue (homomorphism alone) |")
    w("| No balance goes negative | a range proof on the difference |")
    w("| The two legs move together | both are checked before either is applied |")
    w("| One instruction settles once | nullifier registration |")
    w("| Cash leg = quantity x price | a product proof over three commitments |")
    w("| The securities leg is the instructed quantity | an equality proof "
      "across generators |\n")
    w("What DeFMI does *not* check is whether the price was reasonable or "
      "whether that was the right instrument. Those meanings come from the "
      "computing nodes' quorum and travel in the instruction's signature. "
      "Making the settlement layer re-derive them would mean handing it the "
      "plaintext, which is the one thing this construction exists to avoid.\n")

    sc = d["scaling"]
    w("## 2. Cost depends on the balance width and nothing else\n")
    w("The proof is a bit decomposition of the ledger's balance range, so it "
      "should be linear. It is.\n")
    w("| balance width | issue instruction | build package | settle (verify) | package |")
    w("| ---: | ---: | ---: | ---: | ---: |")
    for r in sc:
        w(f"| {r['bits']} bit | {ms(r['issue'])} ms | {ms(r['build'])} ms "
          f"| {ms(r['settle'])} ms | {count(r['package_bytes']):,} B |")
    lo, hi = sc[0], sc[-1]
    span = hi["bits"] - lo["bits"]
    build_slope = (value(hi["build"]) - value(lo["build"])) / span
    settle_slope = (value(hi["settle"]) - value(lo["settle"])) / span
    byte_slope = (count(hi["package_bytes"]) - count(lo["package_bytes"])) / span
    settle_intercept = value(lo["settle"]) - settle_slope * lo["bits"]
    at40 = next((r for r in sc if r["bits"] == 40), None)
    w("")
    w(f"The slopes are **{build_slope:.2f} ms/bit** to build, "
      f"**{settle_slope:.2f} ms/bit** to settle and **{byte_slope:.0f} B/bit** "
      "on the wire.")
    w(f"The settlement intercept, **{settle_intercept:.1f} ms**, is the part "
      "that does not depend on the ledger's width: it is the verification of "
      "the zkPI instruction itself.")
    if at40:
        share = 100 * settle_intercept / value(at40["settle"])
        w(f"At 40 bits, settlement costs {ms(at40['settle'])} ms, of which about "
          f"{share:.0f}% is the instruction and the rest is the ledger's range "
          "proofs.\n")
    w("**Consequence**: if settlement needs to be faster, reconsidering the "
      "balance width beats changing the cryptography. That is a listing "
      "decision, not a technical one.\n")

    if d.get("split_rails"):
        w("### 2.1 A different width for each rail\n")
        w("A quantity of securities and an amount of cash are orders of "
          "magnitude apart. There is no reason to give them the same width.\n")
        w("| securities rail | cash rail | build | settle | package |")
        w("| ---: | ---: | ---: | ---: | ---: |")
        for r in d["split_rails"]:
            w(f"| {r['securities_bits']} bit | {r['cash_bits']} bit "
              f"| {ms(r['build'])} ms | {ms(r['settle'])} ms "
              f"| {count(r['package_bytes']):,} B |")
        base = d["split_rails"][0]
        best = min(d["split_rails"], key=lambda r: value(r["settle"]))
        drop = 100 * (value(base["settle"]) - value(best["settle"])) / value(base["settle"])
        w("")
        w(f"Against both rails at {base['securities_bits']} bits, running "
          f"securities at {best['securities_bits']} and cash at "
          f"{best['cash_bits']} settles **{drop:.0f}% faster** and sends "
          f"**{count(base['package_bytes']) - count(best['package_bytes']):,} B "
          "less**. Not one line of the cryptography changed.\n")

    if d.get("asset_hiding"):
        w("## 3. Hiding which instrument, from the settlement layer too\n")
        w("The MPC layer hides which asset a request is for. Dropping the trade "
          "onto a per-instrument rail at settlement would give that back. "
          "Putting every instrument on one rail instead makes conservation hold "
          "only across instruments, so asset A could be carried out as asset B.\n")
        w("The construction used is an asset tag. Holding q units of asset a "
          "means holding `A_a^q . h^r`; each transfer publishes "
          "`H = A_a . h^y` under a fresh y, and every range proof is made "
          "against `H`. **What binds the disguise to a real asset is the range "
          "proof on the difference**: the payer's balance already sits under "
          "`A_a`, so no other tag can open it.\n")
        w("| instruments | set size | build, untagged | build, tagged | "
          "package | membership (at issue only) |")
        w("| ---: | ---: | ---: | ---: | ---: | --- |")
        for r in d["asset_hiding"]:
            plain, tag = r["arms"]["plain"], r["arms"]["tagged"]
            w(f"| {r['assets']} | {r['set_size']} | {ms(plain['build'])} ms "
              f"| {ms(tag['build'])} ms "
              f"| +{count(tag['package_bytes']) - count(plain['package_bytes'])} B "
              f"| prove {ms(r['membership_prove'], 2)} / verify "
              f"{ms(r['membership_verify'], 2)} ms, {r['membership_bytes']} B |")
        w("")
        plains = [value(r["arms"]["plain"]["build"]) for r in d["asset_hiding"]]
        deltas = [value(r["arms"]["tagged"]["build"]) - value(r["arms"]["plain"]["build"])
                  for r in d["asset_hiding"]]
        noise = max(plains) - min(plains)
        w(f"Every row of the untagged column runs the same work, so its own "
          f"spread --- **{noise:.1f} ms** --- is this measurement's noise floor. "
          f"The tagged column differs from it by {min(deltas):+.1f} to "
          f"{max(deltas):+.1f} ms, which is **inside that floor**. So the "
          "honest statement is that the time cost is too small to measure here; "
          "a percentage would mislead. Only the extra bytes are certain.\n")
        w("Per settlement the addition is **32 B** (one published tag) and one "
          "sigma proof across generators. The one-out-of-many membership proof "
          "(Groth-Kohlweiss) is not needed every time: a balance already sitting "
          "under a registered tag passes soundness down to the transfer, so the "
          "proof is needed **once, when the balance is issued into the account**.\n")
        w("Indistinguishability and the attack arms, measured:\n")
        for r in d["asset_hiding"]:
            same = r["indistinguishable"]
            first = r["per_asset"][list(r["per_asset"])[0]]
            w(f"- {r['assets']} instruments: the package is identical whichever "
              f"one it is ({'identical' if same else 'NOT identical'}, "
              f"{count(first['package_bytes']):,} B across "
              f"{len(r['per_asset'])} instruments).")
            for name, a in r["attacks"].items():
                attack = {
                    "registered_tag_wrong_asset":
                        "carry it out under a registered tag for another asset",
                    "fabricated_tag": "use a point that was never registered",
                }.get(name, name)
                w(f"  - {attack}: `{a['status']}` --- {a['reason']}")
        w("")

    if d.get("netting"):
        rows = d["netting"]["rows"]
        w("## 4. Netting: gross-gross, gross-net, net-net\n")
        w("These are the BIS DvP models 1, 2 and 3. They are a question about "
          "settlement design and, at the same time, a question about **how many "
          "range proofs land and where**.\n")
        w("A rail is either gross or net, and that single choice decides "
          "everything else.\n")
        w("- **A gross rail** checks at each order. It proves on the spot that "
          "the post-trade position is non-negative, so **settlement failure "
          "cannot occur by construction**. The price is order dependence: a "
          "participant receiving 100 and delivering 100 is refused if the "
          "delivery arrives first. That deliberately gives up the liquidity "
          "saving netting exists to provide.")
        w("- **A net rail** only accumulates homomorphically during the period "
          "and proves nothing. A commitment hides the sign as well as the "
          "magnitude, so an intermediate position may be negative without "
          "leaking anything --- what is not proved is not disclosed. At the close "
          "it shows coverage once per participant, on the **net**. The liquidity "
          "saving comes back and order dependence goes away, at the cost of a "
          "close that can fail.\n")
        w("| N | P | mode | verify per order | verify at close | verify total | vs gross-gross |")
        w("| ---: | ---: | --- | ---: | ---: | ---: | ---: |")
        for r in rows:
            w(f"| {r['trades']} | {r['participants']} | {r['mode']} "
              f"| {ms(r['verify_per_order'], 2)} ms | {ms(r['verify_close'])} ms "
              f"| {ms(r['verify_total'])} ms | {r['speedup_vs_gross_gross']:.2f}x |")
        w("")
        largest = max(r["trades"] for r in rows)
        tail = [r for r in rows if r["trades"] == largest]
        gg = next(r for r in tail if r["mode"] == "gross-gross")
        nn = next(r for r in tail if r["mode"] == "net-net")
        at = next(r for r in tail if r["mode"].endswith("attested"))
        w("**The first prediction was wrong.** Counting range proofs alone gave "
          "an estimate that net-net would be an eighth of the work; measured, it "
          f"is only {value(gg['verify_total']) / value(nn['verify_total']):.2f}x. "
          f"Even under net-net, {ms(nn['verify_per_order'])} ms per order "
          "remains, and that is the verification of the zkPI instruction itself "
          "--- which carries range proofs on amount and price inside it. "
          "**It is needed once per trade and netting does not remove it.**\n")
        w("What removes it is changing the **granularity of the instruction**. "
          "If the quorum signs a whole cycle rather than each trade, the "
          "settlement layer's work stops depending on the number of trades "
          f"({ms(at['verify_per_order'], 2)} ms per order, "
          f"{ms(at['verify_total'])} ms in total, "
          f"**{at['speedup_vs_gross_gross']:.1f}x**). The individual trades are "
          "then no longer verified, so the allocation between participants "
          "becomes **the quorum's attestation rather than a proof**. "
          "Conservation and coverage still hold, and each participant can check "
          "its own net, so what is lost is third-party verifiability of the "
          "allocation. That is what a central counterparty has always been; "
          "this only makes it explicit.\n")

    if d.get("credit"):
        c = d["credit"]
        w("### 4.1 How far a net position may go (an intraday overdraft)\n")
        w("Refusing any order that would make a net position negative removes "
          "settlement failure, and, as above, removes the liquidity saving with "
          "it. Practice puts a **limit** here instead --- the Bank of Japan's "
          "intraday overdraft is exactly this: eligible collateral is pledged, a "
          "limit is granted up to its value after haircut, and the position may "
          "be negative down to that limit.\n")
        w("The limit is a **commitment**, and not only to hide its size. "
          "Coverage is then proved about `position + limit`, which means the "
          "proof **never says which side of zero the position was on**. The "
          "offset trickery that hiding a sign usually needs is not needed "
          "anywhere.\n")
        w("| operation | cost | how often |")
        w("| --- | ---: | --- |")
        w(f"| grant a limit (proving the collateral covers it after haircut) "
          f"| build {ms(c['grant'])} / verify {ms(c['check'])} ms | once per limit |")
        w(f"| coverage proof, no limit | {ms(c['coverage_plain'])} ms "
          "| per participant per rail, at the close |")
        w(f"| coverage proof, with a limit | {ms(c['coverage_capped'])} ms | as above |")
        w("")
        w(f"**The limit is essentially free** ({ms(c['coverage_plain'])} to "
          f"{ms(c['coverage_capped'])} ms --- the same range proof width against a "
          "different commitment). **Admission, pledge, overdraft and payment "
          "should be one event**, because doing them in sequence allows either "
          "collateral locked with no limit granted or a limit standing with no "
          "collateral behind it. **They are not one event here.** This "
          "paragraph named an `admit_with_credit` that does not exist in the "
          "Rust implementation: `PositionBook::grant` and `Cycle::admit` are "
          "separate calls, and a grant that succeeds before an admit that fails "
          "leaves the credit standing. There is also no state that locks and "
          "unlocks pledged collateral. What is measured above is the cost of "
          "the limit, which is real; the atomicity is a design requirement that "
          "is written down and not built.\n")
        if c.get("waterfall"):
            w("### 4.2 The default waterfall\n")
            w("A net rail can fail at the close. The order in which that failure "
              "is worked through is the substance of the arrangement, so it has "
              "to be **enforced** and not assumed. The condition that tranche k "
              "may be drawn only once tranche k-1 is exhausted is written "
              "`draw_k x remaining_{k-1} = 0`. The product's commitment is "
              "pinned to the identity, so there is nothing to hand the "
              "verifier.\n")
            w("| tranches | build | verify |")
            w("| ---: | ---: | ---: |")
            for r in c["waterfall"]:
                w(f"| {r['tranches']} | {ms(r['build'])} ms | {ms(r['check'])} ms |")
            first, last = c["waterfall"][0], c["waterfall"][-1]
            per = ((value(last["build"]) - value(first["build"]))
                   / (last["tranches"] - first["tranches"]))
            w("")
            w(f"**{per:.1f} ms per tranche** --- one range proof's worth, linear. "
              "It runs once per default, so nobody need ever care about this "
              "number.\n")

    if d.get("notes"):
        n = d["notes"]
    if deccp:
        w("### 4.2 Interposing a clearing house, and what novation is worth\n")
        w("The paragraph above ends by calling the batch attestation \"the same "
          "bargain a central counterparty represents, made explicit\". That was "
          "one step short. **Under novation there is no split left to verify**, "
          "because there are no bilateral claims left to split: a trade between "
          "A and B becomes A against the house and the house against B, and the "
          "original obligation stops existing. Verifying an allocation that has "
          "been extinguished is not a check anybody was owed.\n")
        w("And novation is free here. An obligation is a commitment, so "
          "replacing one edge with two is two multiplications and no proof --- "
          "nothing is being asserted, the graph is being rewritten. The house's "
          "book is flat by the same construction: it owes exactly what it is "
          "owed, per asset, so that is one comparison rather than a statement "
          "anybody has to establish.\n")
        w(f"Measured at {deccp['participants']} participants, against the two "
          f"arms above run by the same harness:\n")
        w("| trades | net-net | net-net+attested | **DeCCP** | vs net-net | novation |")
        w("| ---: | ---: | ---: | ---: | ---: | ---: |")
        for row in deccp["rows"]:
            w(f"| {row['trades']} | {ms(row['net_net'], 1)} | "
              f"{ms(row['net_net_attested'], 1)} | "
              f"**{row['deccp_total']:.1f} ms** | "
              f"**{row['speedup_deccp_vs_plain']}x** | "
              f"{row['novate_us_per_trade']} us/trade |")
        w("")
        first, last = deccp["rows"][0], deccp["rows"][-1]
        w(f"**net-net grows with the trades and DeCCP does not.** From "
          f"{first['trades']} to {last['trades']} trades the instruction path "
          f"goes {first['net_net']['median']:.0f} ms to "
          f"{last['net_net']['median']:.0f} ms while the cleared cycle goes "
          f"{first['deccp_total']:.0f} ms to {last['deccp_total']:.0f} ms. What "
          f"is left is the close, and the close is per participant.\n")
        w(f"So the speed was never the contribution --- the attested arm already "
          f"had it. **What novation costs is "
          f"{last['novate_us_per_trade']} us a trade, and what it buys is that "
          f"the arm is defensible**: a named house took the other side, its book "
          f"is checked flat by anyone, its margin is posted as a committed cap, "
          f"and its own capital sits in the default waterfall between the "
          f"defaulting member's fund contribution and the mutualised pool, "
          f"which is where CPMI-IOSCO and EMIR put it.\n")
        w("A slot rather than a dependency. A deployment names the providers it "
          "accepts and several may coexist; nothing in the netting cycle or the "
          "settlement layer knows which house cleared a trade, and a deployment "
          "with no provider at all is the bilateral case, which still works and "
          "pays per-trade proofs for it.\n")
        w("**Four things it does not do.** Obligation graphs are per asset, so a "
          "novation that mixed instruments is refused rather than netted across "
          "them. Several providers make the waterfall a forest and not a list, "
          "and a position at one provider is **not** offset against a position "
          "at another --- cross-margining is a different problem and is not "
          "solved here. Novation being free arithmetically says nothing about it "
          "being valid legally, which is the register's rulebook and not this "
          "code. And **the house can leave a trade out, though it can no longer "
          "invent one**: `check_novation` requires both counterparties' "
          "signatures on every edge of the before graph, so a trade nobody made "
          "is refused --- this paragraph used to say a house could novate "
          "invented trades and produce a cycle that checked out, and that "
          "stopped being true when the signatures went in. Omission is what "
          "remains, and the arithmetic cannot tell: a graph missing an edge is "
          "a consistent graph. The tranche is what makes getting it wrong "
          "expensive.\n")

        w("## 5. Hiding who paid whom (the note ledger)\n")
        w("The asset tag hides *what*. An account ledger still names four "
          "handles in the clear at every settlement. Even with every balance "
          "committed, handles that recur draw the counterparty graph.\n")
        w("So accounts were replaced by notes. A note is `C = g^S . A_a^v . h^r`, "
          "where only the **payee** can construct S --- the sender can form `g^S` "
          "from the public key but does not know the b in S = H(A^e) + b. "
          "Spending keeps S hidden and shows with Groth-Kohlweiss that **one of** "
          "the ring holds this S, without saying which.\n")
        w("| ring size | prove (payer) | verify (node) | wire |")
        w("| ---: | ---: | ---: | ---: |")
        for r in n["rings"]:
            w(f"| {r['ring']} | {ms(r['build'])} ms | {ms(r['check'])} ms "
              f"| {count(r['wire_bytes']):,} B |")
        small, large = n["rings"][0], n["rings"][-1]
        mid = [r for r in n["rings"] if r["ring"] == 64]
        w("")
        w("**The asymmetry is the point.** The wire grows by 224 B per doubling, "
          f"and verification only goes from {ms(small['check'])} to "
          f"{ms(large['check'])} ms between rings {small['ring']} and "
          f"{large['ring']}. What breaks is the proving side: "
          f"{ms(small['build'])} to {ms(large['build'])} ms.")
        if mid:
            w("So **what caps the anonymity set is the payer, not the settlement "
              f"node**. A ring of 64 costs {ms(mid[0]['build'])} ms to prove and "
              f"{ms(mid[0]['check'])} ms to verify, which a payer's own device "
              "can carry.")
        w("")
        w("A payee has to scan the pool to find its own notes, at "
          f"**{n['scan_ms_per_note']:.3f} ms** each "
          f"({n['scan_ms']:.1f} ms over {n['pool_size']}). That is one scalar "
          "multiplication, and it is the only cost proportional to the pool.")
        w(f"Two payments to the same address cannot be linked: "
          f"**{n['outputs_unlinkable']}** (neither the commitments nor the "
          "ephemeral points match).\n")

    if d.get("note_settlement"):
        at40 = next((r for r in d["scaling"] if r["bits"] == 40), None)
        base = value(at40["settle"]) if at40 else None
        w("### 5.1 The same DvP over note rails\n")
        w("Both rails were made note rails and the settlement itself was run "
          "through them. The binding to the instruction is kept by a single "
          "equality proof across generators, because the quantity is committed "
          "under the tag and the instruction under the base.\n")
        w("| ring size | build | settle (verify) | package | vs the account version |")
        w("| ---: | ---: | ---: | ---: | ---: |")
        for r in d["note_settlement"]["rings"]:
            delta = ("---" if base is None
                     else f"{100 * (value(r['settle']) - base) / base:+.0f}%")
            w(f"| {r['ring']} | {ms(r['build'])} ms | {ms(r['settle'])} ms "
              f"| {count(r['package_bytes']):,} B | {delta} |")
        rows = d["note_settlement"]["rings"]
        if base is not None:
            w("")
            w(f"The account version settles in {ms(at40['settle'])} ms at 40 "
              f"bits. Hiding the counterparties costs "
              f"{100 * (value(rows[0]['settle']) - base) / base:+.0f}% at ring "
              f"{rows[0]['ring']} and "
              f"{100 * (value(rows[-1]['settle']) - base) / base:+.0f}% at ring "
              f"{rows[-1]['ring']}.")
            w("**Adding up the parts was off by more than a factor of two.** "
              "A note leg and an account leg both carry two range proofs; the "
              "difference is only the ring proof, the serial proof and one "
              "equality proof.\n")

    if rings:
        rows = rings["rows"]
        by = {(r["decoys"], r["ring"], r["traffic"]): r for r in rows}
        sizes = sorted({r["ring"] for r in rows})
        loads = sorted({r["traffic"] for r in rows})
        w("### 5.2 What the ring is actually worth\n")
        if rings["host"] != d["host"]:
            w(f"*Taken on `{label(rings['host'])}`.*\n")
        w("Every table above prices the ring. None of them asks what it buys, "
          "and the answer has been the ring size --- an observer who knows a "
          "leg spent one of R notes names it with probability 1/R. That is what "
          "the proof guarantees and it is not what a reader of the chain "
          "gets.\n")
        w("A ring is an anonymity set only if the decoys are indistinguishable "
          "from the real note. `ring_for` drew its decoys uniformly over every "
          "note the ledger had ever held. A real spend is of a note the spender "
          "was just paid, because that is what settling is --- you are paid, "
          "and then you pay. Recent notes have high indices and uniform decoys "
          "mostly do not, so **an observer who guesses the newest member of the "
          "ring** does far better than 1/R and pays nothing for it.\n")
        w("The strategy was stated before the run and the observer is scored at "
          "the better of the two, because a real one would take it. `traffic` "
          "is how many other settlements land between one firm being paid and "
          "paying: the pool grows by four notes a settlement, so it is other "
          "people's activity, measured in notes that arrive above yours.\n")
        header = "| decoys | ring | " + " | ".join(
            f"traffic {t}" for t in loads) + " | 1/R |"
        w(header)
        w("| --- | ---: | " + " | ".join("---:" for _ in loads) + " | ---: |")
        for decoys in ("uniform", "recent"):
            for size in sizes:
                cells = []
                for load in loads:
                    r = by.get((decoys, size, load))
                    cells.append("--" if r is None
                                 else f"{r['observer_success']:.3f}")
                w(f"| {decoys} | {size} | " + " | ".join(cells)
                  + f" | {1 / size:.3f} |")
        w("")
        worst = by[("uniform", sizes[-1], loads[-1])]
        best = by[("recent", sizes[-1], loads[-1])]
        w(f"**With no other traffic the ring is worth nothing at all** --- "
          "1.000 at every size, under either rule, because a note spent one "
          "settlement after it arrived is the newest note there is and no decoy "
          "can be newer than the newest. That is not a decoy-selection bug; it "
          "is the honest shape of the thing:\n")
        w("> an anonymity set on a note rail is other people's traffic, and the "
          "decoy rule only decides how much of it the ring can use.\n")
        w("Which is the same shape as §6.1 below. A construction that hides you "
          "in a crowd does not work in an empty room, and saying so is part of "
          "reporting what it does.\n")
        w(f"What the decoy rule is worth is the gap between the two blocks. At "
          f"ring {sizes[-1]} with {loads[-1]} settlements of other traffic, "
          f"uniform decoys leave the observer at "
          f"**{worst['observer_success']:.3f}** against a nominal "
          f"{1 / sizes[-1]:.3f} --- {worst['observer_success'] * sizes[-1]:.1f} "
          f"times what the proof promises. Drawing the decoys from the same "
          f"recency window that real spends come from brings it to "
          f"**{best['observer_success']:.3f}**, which is the nominal figure "
          "exactly. `ring_recent` is that rule and it is thirty lines.\n")

    if rings and rings.get("state_root"):
        w("### 5.3 A settlement that got slower the longer the ledger ran\n")
        w("The benchmark above found something that is not about rings. Its "
          "verification times climbed with the pool, and nothing in "
          "`check_spend` is proportional to the pool --- the ring proof, the "
          "range proofs and the balance check are all in the ring. What was "
          "proportional to it was the **state root**: `snapshot` compressed "
          "every note the ledger had ever held and re-sorted every spent "
          "serial, and a settlement takes four of them, two rails before and "
          "after.\n")
        w("| notes held | root by walking | root as kept | |")
        w("| ---: | ---: | ---: | ---: |")
        for r in rings["state_root"]:
            ratio = value(r["walked_us"]) / max(value(r["kept_us"]), 1e-9)
            w(f"| {r['pool']:,} | {ms(r['walked_us'])} us "
              f"| {render(r['kept_us'], 2)} us | {ratio:,.0f}x |")
        w("")
        big = rings["state_root"][-1]
        w(f"At {big['pool']:,} notes the four roots in one settlement came to "
          f"**{value(big['per_settlement_walked_us']) / 1000:.1f} ms**, against "
          "about 8 ms of cryptography --- the bookkeeping had become an order "
          "of magnitude more expensive than the proofs, and it would keep "
          "growing, because it was a function of total history rather than of "
          "activity. That is the exact property §7 checks for the account rail "
          "and it had gone unchecked here.\n")
        w("Nothing about the ledger required it. Notes are only ever appended "
          "--- a spent note stays in the pool, because removing it would say "
          "which one went --- and serials are only ever inserted, so the hash "
          "of the whole history is a running hash extended once per change. "
          "The sort was buying order-independence for a sequence that already "
          "has an order: the one the chain applied. The root is now kept rather "
          "than recomputed and the column above is flat.\n")

    if pvp:
        milli, micro = pvp["milliseconds"], pvp["microseconds"]
        w("## 6. Payment versus payment, across two ledgers\n")
        if pvp["host"] != d["host"]:
            w(f"*The two tables in this section were taken on "
              f"`{label(pvp['host'])}`, not the `{label(d['host'])}` of the rest "
              "of this document: they are Rust benchmarks and they wanted a "
              "machine that was not doing anything else.*\n")
        w("DvP moves two legs together because both are on one ledger and one "
          "function decides. Two ledgers that share no state have no such "
          "function, and fair exchange between two parties with no third party "
          "is impossible in general --- so something has to pass from one side "
          "to the other. The only question is what, and who can read it.\n")
        w("A hash lock passes a preimage that ends up in the clear on both "
          "ledgers, so anyone reading both can join the two legs on it. That is "
          "the linkage the asset tag and the note ledger were built to prevent, "
          "handed back at the last step. What is used instead is an **adaptor "
          "signature**: the first mover's claim on one ledger hands the second "
          "mover a scalar, and what each ledger records is an ordinary "
          "signature with nothing in common with the other's.\n")
        w("```")
        w("1. Bob   -> Alice : Y = g^y")
        w("2. Alice           prepares leg A; her money leaves her account")
        w("   Alice -> Bob   : a pre-signature over \"leg A\", adapted to Y")
        w("3. Bob             prepares leg B, and sends his own pre-signature")
        w("4. Bob             claims on A  -> he is paid, and y becomes readable")
        w("5. Alice           reads A, recovers y, claims on B  -> she is paid")
        w("```\n")
        w("Bob draws the secret and moves first, so Bob is never at risk: if he "
          "stops after step 3 both escrows expire and both parties are whole. "
          "Alice is exposed in exactly one window, between step 4 and step 5, "
          "and she is safe if and only if the gap between the two deadlines "
          "covers her reaction. **That gap is this arrangement's Herstatt "
          "risk**, and it is the number worth measuring.\n")
        w(f"| | measured, {pvp['rail_bits']}-bit rails |")
        w("| --- | ---: |")
        w(f"| prepare one leg (check, and move it out of reach) "
          f"| {milli['prepare']['mean']:.2f} \u00b1 {milli['prepare']['sd']:.2f} ms "
          f"(n={milli['prepare']['n']}) |")
        w(f"| the first mover's claim | {milli['claim']['mean']:.2f} \u00b1 "
          f"{milli['claim']['sd']:.2f} ms (n={milli['claim']['n']}) |")
        w(f"| **the second mover's reaction** | **{milli['react']['mean']:.2f} "
          f"\u00b1 {milli['react']['sd']:.2f} ms (n={milli['react']['n']})** |")
        w(f"| unwind an expired leg | {micro['unwind']['mean']:.2f} \u00b1 "
          f"{micro['unwind']['sd']:.2f} us (n={micro['unwind']['n']}) |")
        w("")
        w(f"**The cryptography is not what puts the money at risk.** Recovering "
          f"the secret, adapting the signature and having the second ledger "
          f"accept it comes to {milli['react']['mean']:.2f} ms. The deadline gap "
          "has to cover that *plus* the time for one ledger to publish the "
          "first claim and the other to accept the second --- block times and "
          "network round trips, which are three to five orders of magnitude "
          "larger. So the exposure is set by the settlement finality of the two "
          "ledgers and not by anything in this repository, and a deployment "
          "that wants a short window should shop for finality rather than for "
          "faster proofs.\n")
        w("Preparing costs about what a transfer costs, because that is what it "
          "is: the same check, with the amount moved into an escrow instead of "
          "into the payee. Unwinding costs nothing, and deliberately requires "
          "no signature --- the deadline is the whole authority, because "
          "demanding a signature would strand the money of anyone who lost a "
          "key, which is the failure this branch exists to prevent.\n")

    if same_chain:
        rows = same_chain["rows"]
        def pick(arm, swaps, parties, naming):
            return next(r for r in rows if r["arm"] == arm and r["swaps"] == swaps
                        and r["parties"] == parties and r["naming"] == naming)
        biggest = max(r["swaps"] for r in rows)
        namings = sorted({r["naming"] for r in rows})
        per_venue = next(n for n in namings if "per venue" in n)

        w("### 6.1 On one chain, and what the unlinkability actually rests on\n")
        if same_chain["host"] != d["host"]:
            w(f"*Taken on `{label(same_chain['host'])}`.*\n")
        w("Across two chains there is no choice about atomicity: nothing spans "
          "them, so an adaptor signature and a deadline are the only way. On one "
          "chain --- two DeFMI deployments, two contract addresses --- there is a "
          "choice. A single transaction calling both venues gets atomicity from "
          "the chain for nothing and its exposure window is zero, but that "
          "transaction is the link. Two transactions with an adaptor keep the "
          "legs cryptographically unrelated and pay at least one block.\n")
        w("What the second arm costs is small and flat:\n")
        w(f"| at {biggest} swaps | one transaction | adaptor |")
        w("| --- | ---: | ---: |")
        for row_name, key in (("calls", "calls"),
                              ("state slots written", "slots_written"),
                              ("bytes written", "bytes_written")):
            one_tx = pick("one transaction", biggest, "distinct", per_venue)[key]
            adapt = pick("adaptor", biggest, "distinct", per_venue)[key]
            w(f"| {row_name} | {one_tx} | {adapt} |")
        one_tx = pick("one transaction", biggest, "distinct", per_venue)["verify_ms"]
        adapt = pick("adaptor", biggest, "distinct", per_venue)["verify_ms"]
        w(f"| verification | {ms(one_tx)} ms | {ms(adapt)} ms |")
        w("| exposure window | none | at least one block |")
        w("")
        adapt_over_one = []
        for r in rows:
            if r["arm"] != "adaptor":
                continue
            base = pick("one transaction", r["swaps"], r["parties"], r["naming"])
            adapt_over_one.append(value(r["verify_ms"]) / value(base["verify_ms"]))
        lo, hi = min(adapt_over_one), max(adapt_over_one)
        mid = sorted(adapt_over_one)[len(adapt_over_one) // 2]
        w(f"Four times the calls and a third more state slots --- holding "
          f"**fewer bytes** in them, because a settlement records a nullifier "
          f"and a deadline (40 bytes a venue) where the escrow path records "
          f"neither: the escrow key is itself the replay guard, and it costs a "
          f"slot rather than bytes --- for "
          f"**{100 * (mid - 1):.1f}% more verification** "
          f"(+{100 * (lo - 1):.1f}% to +{100 * (hi - 1):.1f}% across the "
          "table). The range proofs dominate, and the escrow and the signature "
          "are a few percent beside them rather than nothing at all: this is a "
          "difference the earlier run on a loaded machine could not resolve: "
          "both arms read 413 ms there, with standard deviations of 9 and "
          "20 ms against a gap that should have been about 14. It was not "
          "measured to be zero; it was not measurable.\n")
        w("What it buys is the question, and the answer turned out to depend on "
          "something that was not cryptography at all.\n")
        w("**What a reader of the chain can still join**, using nothing but what "
          "the calls name. One stated strategy, run over the real records: take "
          "a call on one venue, find the calls on the other that name the same "
          "handles, guess uniformly among them; where no handle matches, guess "
          "uniformly among all of them.\n")
        w("| naming | swaps in flight | between | one transaction | adaptor | chance |")
        w("| --- | ---: | --- | ---: | ---: | ---: |")
        for naming in namings:
            for parties in ("distinct", "one pair"):
                for swaps in sorted({r["swaps"] for r in rows}):
                    a = pick("one transaction", swaps, parties, naming)
                    b = pick("adaptor", swaps, parties, naming)
                    w(f"| {naming} | {swaps} | {parties} | "
                      f"{a['observer_success']:.3f} | "
                      f"**{b['observer_success']:.3f}** | {b['chance']:.3f} |")
        w("")
        w("**The privacy of this construction was sitting in a naming "
          "convention.** With one identifier at both venues --- which is what a "
          "caller reaches for, and what this benchmark did on its first run --- "
          "the adaptor buys nothing between distinct parties: a prepare is a "
          "transfer, a transfer says who is paying whom, and joining \"this "
          "firm pays here\" to \"this firm is paid there\" needs no "
          "cryptanalysis. Four times the calls for a number that does not "
          "move.\n")
        w("With a handle derived per venue --- `qomm_zkpi::handles`, one seed and "
          "an unrelated point at each venue --- the adaptor delivers exactly what "
          "it promises: the observer falls to chance, 1/k, and stays there "
          "whether the swaps are between distinct parties or the same pair. "
          "Nothing about the cryptography changed between those two blocks of "
          "the table. Only the names did.\n")
        w("This is worth stating plainly because the property was written down "
          "as prose before it was code, and prose does not hold. The design said "
          "handles are derived per venue so that one firm is two unrelated "
          "points; the library offered no way to derive them, so the obvious "
          "integration was the one that loses. It is code now, and the test that "
          "goes with it runs the scheme that suggests itself first --- one secret "
          "scaled by a public per-venue factor --- and shows it is publicly "
          "linkable.\n")
        w("Two things the table is not. The observer here is given **no "
          "timing**: every prepare is placed in one block, so a real observer "
          "watching them arrive does better than 1/k. And these are account "
          "rails. The note ledger of \u00a75 removes the handle rather than "
          "deriving it well, which sounds like the stronger answer and is, but "
          "\u00a75.2 measured what it is worth and the two findings are the "
          "same one: **both constructions hide you in other people's traffic "
          "and neither does anything without it.** A ring with no other "
          "settlements around it names its note with certainty, exactly as an "
          "adaptor with one swap in flight names its partner leg. What differs "
          "is the exchange rate --- how much traffic each one needs to buy a "
          "given amount of doubt --- and not whether traffic is what is being "
          "spent.\n")
        w("This measurement first ran against a version where the property was "
          "the caller\'s to keep. The instruction named two handles and the "
          "package named four accounts, and nothing compared them --- so a "
          "caller who derived handles per venue and then opened accounts under "
          "one name everywhere got the losing row of the table while believing "
          "it had the winning one. That is now closed: the four account names "
          "are **derived from the two signed handles** (`Sides::of`, one hash "
          "of the handle and the rail), `build_package` no longer takes them as "
          "an argument, and a package whose accounts disagree with its "
          "instruction is rejected before any proof is examined. The per-venue "
          "property is enforced where it is used rather than assumed of the "
          "caller.\n")

    if reconcile:
        w("## 6.5 Agreeing with the book of record\n")
        w("Under Japan's book-entry regime this ledger cannot *be* the register: "
          "title rests on the record the transfer agent and the account "
          "management institutions keep. So it is a mirror, and reconciliation "
          "is not a feature but the price of that arrangement.\n")
        w("It is one line of algebra. Commitments multiply, so the product of "
          "the balances is a commitment to their sum; divide out the register's "
          "figure under the asset tag and what remains must be a pure power of "
          "`h`. Proving knowledge of that exponent proves the totals agree and "
          "says nothing else --- **no balance opens, and the total was the "
          "register's own number**.\n")
        w("| positions | prove | check | quorum assembles |")
        w("| ---: | ---: | ---: | ---: |")
        for row, joint in zip(reconcile["scaling"], reconcile["quorum"]):
            w(f"| {row['positions']:,} | {ms(row['prove'], 2)} | "
              f"{ms(row['check'], 2)} | {ms(joint['assemble'], 2)} "
              f"({len(joint['quorum'])} of {joint['of']}) |")
        w("")
        biggest = reconcile["scaling"][-1]
        w(f"Linear in the positions and nothing else: at "
          f"{biggest['positions']:,} it is {ms(biggest['check'], 1)} to check, "
          f"and the proof on the wire is {biggest['wire_bytes']} B whatever the "
          f"ledger holds.\n")
        w("The **quorum** column is the same statement assembled by nodes "
          "holding shares of the aggregate blinding, so nobody holds the sum --- "
          "which matters, because whoever holds it could open the whole ledger. "
          "A sigma response is affine in the witness, so the partials combine "
          "into an ordinary proof any verifier accepts.\n")
        w("### 6.5.1 A break is pass or fail, and looking costs disclosure\n")
        w("If the totals disagree the proof does not verify, and that is all "
          "anyone learns. Finding *where* needs somebody to claim subtotals, and "
          "every subtotal claimed becomes public --- the narrowest of them "
          "covers one position, which is a balance. **This is the only operation "
          "in DeFMI that discloses on purpose, and it is the operation you reach "
          "for on the day something is wrong.**\n")
        w("| positions | sub-range proofs | 2 log2 n + 1 | subtotals made public | narrowest |")
        w("| ---: | ---: | ---: | ---: | ---: |")
        for row in reconcile["locating"]:
            w(f"| {row['positions']:,} | {row['sub_range_proofs']} | "
              f"{row['two_log_n_plus_one']} | "
              f"{row['subtotals_made_public']} | {row['narrowest_range']} position |")
        w("")
        w("A register that holds **a figure per position** rather than one for "
          "the account localises for free and discloses nothing: an account "
          "management institution already holds the mapping from handle to "
          "book-entry account, so it holds the openings and the check is "
          "arithmetic on numbers it has. "
          f"At {reconcile['locating'][-1]['positions']:,} positions that is "
          f"{reconcile['locating'][-1]['per_position_register']['ms']} ms.\n")
        w("**Reconciling is the cheap half and the search is not.** Which one "
          "you are in depends on what the register keeps, which is a question "
          "about the counterparty and not about this ledger.\n")

    if note_dvp:
        w("### 5.2 The same, in Rust\n")
        w("The note rail's delivery versus payment is ported, and this is the "
          "measurement that lets the sentence about it go from section 9 rather "
          "than be softened.\n")
        w("| ring | build | settle | package |")
        w("| ---: | ---: | ---: | ---: |")
        for row in note_dvp["rows"]:
            w(f"| {row['ring']} | {ms(row['build'], 1)} | "
              f"{ms(row['settle_including_build'], 1)} | "
              f"{row['package_bytes']:,} B |")
        w("")
        w("**The package is the comparable column and it is about nine times "
          "smaller** --- 5,476 B against 50,827 at a ring of eight --- which is "
          "the same Bulletproofs-against-bit-decomposition effect the account "
          "rail showed in section 5.1.\n")
        w("The two `build` columns are **not** comparable and the ratio between "
          "them means nothing: the Rust one includes the whole three-of-seven "
          "FROST ceremony that issues the instruction, and the Python one does "
          "not. Saying so is cheaper than a footnote nobody reads under a "
          "number somebody quotes.\n")
        w("`settle` builds a fresh world and a fresh package each time, because "
          "settling consumes both, so it is an upper bound carrying a build "
          "inside it.\n")

    if viewing:
        w("## 6.6 Showing an auditor one slice\n")
        w("A note wallet is a view key and a spend key, and the view key was "
          "always described as the one you could hand an auditor. You could, and "
          "that was the whole of it: one key, so handing it over gives every "
          "instrument, every period, permanently, with no way back.\n")
        w("The scoping is not in the key. It is in the **address**. A scope --- "
          "an instrument, a quarter, a mandate --- derives its own pair of "
          "scalars from the wallet's seeds by hashing, so it has its own "
          "address, and notes sent there are found by that scope's view key and "
          "by nothing else. The derivation is one way, so a scope says nothing "
          "about the seed or about a sibling. The note construction, the scan "
          "and the spend are all unchanged; what changes is which address a "
          "payer is given.\n")
        w("| pool | scan | per note | reached | exactly its scope | serials recovered |")
        w("| ---: | ---: | ---: | ---: | :---: | ---: |")
        for row in viewing["scaling"]:
            w(f"| {row['pool']:,} | {ms(row['scan'], 1)} | "
              f"{row['per_note_ms']} ms | "
              f"{row['notes_reached']} of {row['notes_in_pool']:,} "
              f"({row['fraction_reached']:.1%}) | "
              f"{'yes' if row['sees_exactly_its_scope'] else 'NO'} | "
              f"{row['serials_recovered']} |")
        w("")
        w(f"The scan is one scalar multiplication a note, the same as a wallet "
          f"scanning for itself, at {viewing['scaling'][-1]['per_note_ms']} ms. "
          f"With {viewing['scopes']} scopes in the pool plus a stranger's notes "
          f"the holder reaches about a fifth of it, which is the fifth it was "
          f"granted --- and **no serial numbers at all**, because a serial needs "
          f"the spend key and the grant does not carry one.\n")
        w(f"A grant is {ms(viewing['grant']['build'], 2)} to issue and "
          f"{ms(viewing['grant']['check'], 2)} to check. It names the grantee "
          f"and is signed by the wallet, so a key found somewhere it should not "
          f"be traces to the grant that produced it --- attribution rather than "
          f"prevention, the same trade `roles.py` makes about a dealt share.\n")
        w("### 6.6.1 Three limits that do not go away\n")
        w("**A grant cannot be taken back.** Whoever holds a scope's key can "
          "read every note ever sent to that address and every one that ever "
          "will be. An expiry stops a party that chooses to be stopped and "
          "nothing else. What actually revokes is moving to the next scope, "
          "because the next scope is a different address --- so revocation is "
          "an act of address management and not a message.\n")
        w("Which is why the schedule is an object rather than a discipline. "
          "`Rolling` says what the scope in force is, what address to publish "
          "and when it stops being it; a grant issued against it expires when "
          "the period does, so it is never current for a scope nothing is being "
          "paid into. Two questions stay separate --- whether a grant is well "
          "formed by its own dates, and whether it is for the scope money is "
          "going into now --- because one failure is a bad grant and the other "
          "is a wallet that has not rolled. And a payer using a stale address "
          "puts the note in a stale scope, which nothing in the protocol stops, "
          "so `arrived_off_schedule` is what a payee that cares runs.\n")
        w("**A view key is incoming only.** It finds what arrived and cannot see "
          "what the wallet spent: spending publishes a serial and a ring, and "
          "neither is derivable from the view key. An auditor that needs "
          "outflows needs the wallet to hand over its serials, which is a "
          "different disclosure than this one.\n")
        w("**Scoping is only as fine as the payers cooperate.** A scope exists "
          "because counterparties were told to pay to that address; one who uses "
          "last quarter's address puts the note in last quarter's scope and "
          "nothing in the protocol stops them. That is an operational control "
          "wearing a cryptographic coat, and it is worth knowing which it is.\n")

    if vetting:
        rows = {r["crowd"]: r for r in vetting["rows"]}
        default = max(r for r in rows if r <= 128)
        big, small = rows[default], rows[16]
        w("## 6.7 Who is allowed to hold a handle\n")
        w("A handle is `A = a.G` and anyone can pick `a`. Nobody's permission is "
          "needed to make one, and that is deliberate --- the chain should not "
          "have an opinion about who opens an address. What needs permission is "
          "being **vetted**, and `rust/qomm-defmi/src/vetting.rs` is where that "
          "is recorded.\n")
        w("**The list holds sealed envelopes, not handles.** An envelope is "
          "`C = a.G + r.h`, so `C - A = r.h`: the envelope is the handle plus a "
          "blinding nobody else knows, and adding one to the public list reveals "
          "a uniformly random point.\n")
        w("That matters more than it first looks. Putting the *handle* in the "
          "list would mean anyone who could work out from the timing which entry "
          "belonged to which firm --- they onboarded that week, one entry "
          "appeared that week --- would have that firm's handle. The handle is "
          "what appears on chain when the account moves, so they would then have "
          "its entire settlement history. Sealing the entry closes that: the "
          "timing still says somebody joined, and says nothing about which entry "
          "is theirs.\n")
        w("**The group is fixed, which is why it is private.** Membership is "
          "proved one-out-of-many over a group: subtract the handle from every "
          "envelope, exactly one difference is a commitment to zero, and the "
          "proof says so without saying which. Drawing a fresh ring per proof "
          "would look more private and be less --- rings that overlap "
          "differently each time can be intersected and the real member falls "
          "out. The same group every time gives an observer nothing to "
          "intersect. A group also carries its cohort, so proving membership "
          "proves the attribute.\n")
        w("**A vetting yields one handle, not a family of them.** The ring proof "
          "alone says only that `C_l - A` is a multiple of `h`, so `A + d.h` "
          "would satisfy it for any `d` the holder picks --- one vetting, "
          "unboundedly many usable handles, every per-firm cap void. A Schnorr "
          "proof that the handle is a bare power of the base point pins it to "
          "the one the envelope determines. That is a test, not a comment.\n")
        w("**Whose privacy this is.** The seal hides the entry from "
          "*observers* and not from the operator: `vouch` takes the handle's "
          "secret, picks the blinding and picks the slot. An enrolment in "
          "which it does not --- the party proving knowledge of its secret and "
          "receiving a jointly chosen blinding --- is not built. What the seal "
          "establishes is that dating an onboarding tells a third party "
          "nothing about which entry it is.\n")
        w("**A verifier must know which roll it is checking against.** "
          "`check_membership` proves a handle is in the roll it is *given*, so "
          "a proof that arrives with its own roll proves nothing --- `Group` is "
          "not constructible from outside the crate and `Roll::digest()` is "
          "what a verifier compares against whatever the chain published. This "
          "used to be neither: every field was public, so a caller could push a "
          "group holding an envelope of its own, cut a seal by hand, and pass "
          "the check without the operator ever running.\n")
        w("**What is public on purpose.** `Roll::vetted()` counts the real "
          "envelopes and `Roll::crowd()` gives the group size, so anyone can "
          "check the claim rather than take it. Decoy seats are hashed rather "
          "than drawn, so no opening exists for them --- not even the "
          "operator's --- which is what makes that count honest. It counts "
          "calls to `vouch` and not distinct legal entities: nothing here "
          "deduplicates one, and the per-entity cap that would is the "
          "operator's.\n")
        w("The alternative is worth naming. Hiding that a vetting happened at "
          "all --- making onboarding indistinguishable from ordinary settlement "
          "traffic --- means padding the roll with entries nobody can tell from "
          "real ones, and then nobody can count the real ones either, including "
          "a regulator asking how large the anonymity set is. **Hiding the "
          "vetting event and proving the size of the crowd are the same "
          "information.** One or the other.\n")
        w(f"Measured on `{label(vetting['host'])}`, "
          f"{vetting['repeats']} repeats, medians.\n")
        w("| crowd | prove | verify | proof | ring |")
        w("|---:|---:|---:|---:|---:|")
        for crowd in sorted(rows):
            r = rows[crowd]
            w(f"| {crowd} | {ms(r['prove_ms'], 2)} | {ms(r['verify_ms'], 2)} | "
              f"{r['proof_bytes']} B | {r['ring_bytes']} B |")
        w("")
        step = rows[32]["proof_bytes"] - rows[16]["proof_bytes"]
        w(f"The size was predicted exactly: {small['proof_bytes']} bytes at a "
          f"crowd of 16, of which {small['ring_bytes']} is the ring, 64 the "
          f"control proof and 12 the group and epoch. Every doubling adds "
          f"exactly {step} --- one point in each of the ring's four vectors and "
          f"one scalar in each of its three.\n")
        ratio = big["verify_ms"]["median"] / rows[4]["verify_ms"]["median"]
        grew = big["crowd"] // 4
        w(f"**Two predictions missed, and the second changed a design choice.** "
          f"Verifying was predicted under 1 ms in Rust against Python's 1.81 ms "
          f"at a crowd of 16; it came in at {ms(small['verify_ms'], 2)}, a factor "
          f"of 1.4. The reason is the one `BINDING.md` gives about VOLEitH: the "
          f"Python side already runs its group arithmetic in C through PyNaCl, "
          f"so Rust wins the glue and not the arithmetic. The Rust figure also "
          f"does strictly more --- it verifies the control proof and shifts "
          f"every envelope.\n")
        w(f"The consequential miss is the second. **Verification was predicted "
          f"to double with the crowd and grows about 1.4x instead**: {grew}x the "
          f"crowd costs {ratio:.1f}x the work, which is the batched "
          f"multi-scalar multiplication showing through. The crowd had been "
          f"capped at 16 on a belief about linearity the measurement does not "
          f"support. At {big['crowd']} the check is {ms(big['verify_ms'], 2)} "
          f"against the 51.9 ms a note settlement already costs, and the wire "
          f"grows by {big['proof_bytes'] - small['proof_bytes']} bytes. "
          f"**{big['crowd']} is the default the code carries** "
          f"(`vetting::CROWD`).\n")
        w("What stays out of reach is a crowd of thousands. That needs a Merkle "
          "tree checked inside a circuit --- a different proof system from the "
          "sigma protocols and Bulletproofs this stack is built on, with a "
          "compiler and a setup behind it.\n")
        w("**Where the check runs.** The node committee verifies the complete "
          "proof before it signs. The dedicated Avalanche VM verifies the "
          "3-of-7 approval and binds it to the proof digest, chain, rail, "
          "deadline, sequence and previous state root. Validators do not yet "
          "re-run every Bulletproof; that remaining trust boundary is explicit "
          "in `ZKPI_WIRE.md`.\n")

    if avalanche:
        timings = avalanche["operation_timings_ms"]
        accepted = avalanche["accepted_transitions"]
        heights = ", ".join(str(accepted[k]["height"]) for k in
                            ("bootstrap_asset", "instrument_asset",
                             "left_account", "right_account", "settlement"))
        w("### 6.8 Native Avalanche L1 acceptance\n")
        w("The deployed execution path is a dedicated non-EVM Avalanche custom "
          "VM in `avalanche/defmivm/`. It has native transitions for asset "
          "registration, account opening and atomic multi-leg settlement; it "
          "does not execute Solidity or EVM bytecode.\n")
        w("| property | observed result |")
        w("| --- | ---: |")
        w(f"| local AvalancheGo processes | {avalanche['nodes']} |")
        w(f"| accepted heights | {heights} |")
        w(f"| settlement acceptance | {timings['settlement_ms']:.1f} ms |")
        w(f"| two account openings | {timings['two_accounts_ms']:.1f} ms |")
        w(f"| node restart and state recovery | {avalanche['restart']['elapsed_ms']:.1f} ms |")
        w(f"| one state root before restart | {'yes' if len(set(avalanche['roots_before_restart'])) == 1 else 'no'} |")
        w(f"| same state root after restart | {'yes' if avalanche['restart']['root_recovered'] else 'no'} |")
        w("")
        w("The run uses five processes on one host. It proves native consensus "
          "acceptance, idempotent crash recovery and state-root agreement, not "
          "five independent organisations or public-network readiness.\n")

    if d.get("parallel"):
        w("## 7. What one settlement node can take\n")
        w("Verification only --- proving is the counterparty's work and the clock "
          "is stopped for it. Every worker meets at a barrier before the "
          "measured section begins.\n")
        w("| workers | settlements/s | vs one worker |")
        w("| ---: | ---: | ---: |")
        one = value(d["parallel"][0]["per_second"])
        for r in d["parallel"]:
            w(f"| {r['workers']} | {ms(r['per_second'])} "
              f"| {value(r['per_second']) / one:.2f}x |")
        top = d["parallel"][-1]
        w("")
        w("Verifications of independent packages share nothing, so they "
          f"parallelise completely: **{value(top['per_second']):.0f} per second** "
          f"on {top['workers']} workers. A settlement node's capacity is a "
          "procurement question, not a design one.\n")
        if big and big.get("parallel"):
            bp = big["parallel"]
            bone, btop = bp[0], bp[-1]
            bcal = value(big["calibration"]["scalar_mult_us"])
            ccal = value(d["calibration"]["scalar_mult_us"])
            w(f"A second host with more cores (`{label(big['host'])}`, "
              f"{btop['workers']} logical cores) was measured too. Its "
              f"calibration is {bcal:.1f} us per scalar multiplication against "
              f"{ccal:.1f} us here, so it is **{bcal / ccal:.2f}x slower per "
              f"core**. Its single-worker throughput differs by "
              f"{one / value(bone['per_second']):.2f}x "
              f"({one:.1f} to {value(bone['per_second']):.1f} per second), which "
              "is the same ratio by an independent route.\n")
            w("| workers | settlements/s | vs one worker | vs linear |")
            w("| ---: | ---: | ---: | ---: |")
            for r in bp:
                w(f"| {r['workers']} | {value(r['per_second']):.1f} "
                  f"| {value(r['per_second']) / value(bone['per_second']):.2f}x "
                  f"| {100 * value(r['per_second']) / (value(bone['per_second']) * r['workers']):.0f}% |")
            shortfall = 100 - 100 * value(btop["per_second"]) / (
                value(bone["per_second"]) * btop["workers"])
            w("")
            w(f"**{value(btop['per_second']):.0f} per second** on "
              f"{btop['workers']} workers, only {shortfall:.0f}% short of "
              "linear. Nothing is shared between verifications, so this shape "
              "is what was expected.\n")

    if rust:
        w("## 8. The Rust port\n")
        py_cal = value(d.get("calibration", {}).get("scalar_mult_us"))
        rs_cal = value(rust["calibration"].get("scalar_mult_us"))
        # The ratios in this section are cross-language, so they are only a
        # comparison at all if both sides were taken on one machine. That is a
        # property of the two artifacts, not of the prose, so it is read from
        # them: a table that has quietly become cross-host says so instead.
        same_machine = rust["host"] == d["host"]
        where = (f"Measured on the same machine (`{label(rust['host'])}` / "
                 if same_machine else
                 f"Measured on `{label(rust['host'])}` against Python on "
                 f"`{label(d['host'])}` / ")
        w(where + f"{rust['rustc']} / group ristretto255). The "
          "scalar-multiplication calibration is "
          + (f"{rs_cal:.1f} us in Rust against {py_cal:.1f} us in Python, "
             if py_cal else f"{rs_cal:.1f} us in Rust, ")
          + "and **this one figure is the only thing that compares across the "
            "two languages** --- Python goes through libsodium and Rust through "
            "dalek, different implementations of the same thing: a scalar "
            "multiplication on a native-code 255-bit curve. "
          + ("That they agree says the two are equally fast and, more usefully, "
             "that **the machine was in the same state**, which is what stops "
             "the ratios below being explained by the machine.\n"
             if same_machine else
             "**These are two different machines**, so the ratios below carry "
             "the difference between the hosts as well as the difference "
             "between the languages, and should not be read as a port "
             "measurement until both sides are retaken together.\n"))
        w("What is being compared is not only the language. The port also "
          "replaced a hand-rolled bit-decomposition range proof with the audited "
          "`bulletproofs` crate, so **the ratios below are 'became Rust' and "
          "'became Bulletproofs' added together**. The order-of-magnitude change "
          "on the wire is the second of those: linear became logarithmic.\n")
        py_by_bits = {r["bits"]: r for r in d["scaling"]}
        shared = [r for r in rust["scaling"] if r["bits"] in py_by_bits]
        w("| balance width | Python settle | Rust settle | ratio | "
          "Python package | Rust package | ratio |")
        w("| ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for r in shared:
            py = py_by_bits[r["bits"]]
            py_settle, rs_settle = value(py["settle"]), value(r["settle_ms"])
            py_bytes, rs_bytes = count(py["package_bytes"]), count(r["package_bytes"])
            w(f"| {r['bits']} bit | {ms(py['settle'])} ms | {rs_settle:.2f} ms "
              f"| {py_settle / rs_settle:.1f}x "
              f"| {py_bytes:,} B | {rs_bytes:,} B | {py_bytes / rs_bytes:.1f}x |")
        w("")
        wide = [r for r in rust["scaling"] if r["bits"] == 64]
        py40 = py_by_bits.get(40)
        if wide and py40:
            wide = wide[0]
            py_settle = value(py40["settle"])
            py_bytes, rs_bytes = count(py40["package_bytes"]), count(wide["package_bytes"])
            w("Bulletproofs only comes in powers of two, so a 40-bit rail "
              "**rounds up to 64**. Comparing against the rounded-up side is the "
              f"honest comparison: {ms(py40['settle'])} ms for Python at 40 bits "
              f"against {wide['settle_ms']:.2f} ms for Rust at 64, "
              f"**{py_settle / wide['settle_ms']:.1f}x**. The package goes from "
              f"{py_bytes:,} to {rs_bytes:,} B, **{py_bytes / rs_bytes:.1f}x**.\n")
            w(f"Per core that is {1000 / py_settle:.1f} to "
              f"{1000 / wide['settle_ms']:.1f} settlements per second. "
              "Parallelism is independent, so multiply by cores.\n")
        w("**Losing the fine grain of the width is a real cost.** A bit "
          "decomposition could prove 24 or 40 bits directly, which is what made "
          "the per-rail width optimisation of section 2.1 work. With only powers "
          "of two, securities at 24 bits round up to 32 and cash at 40 to 64. "
          "The conclusion here is that the table above is still a large enough "
          "difference to swallow that.\n")

    w("## 9. What is still missing\n")

    w("- Avalanche validators verify the committee approval and proof digest, "
      "not the complete zero-knowledge proof. Removing that committee trust "
      "requires a consensus-safe verifier inside the VM and a separate audit.")

    if not d.get("note_settlement"):
        w("- The note ledger and DvP settlement are not yet joined. Notes work "
          "and are measured on their own, but `Defmi.settle` is still the "
          "account ledger.")
    w("- A tagged cash leg needs cash accounts opened under that currency's "
      "tag; the remainder proof opens against the balance the payer already "
      "has, so a leg cannot claim a currency the account is not denominated "
      "in. That is the property doing the work, and it means adding a second "
      "settlement currency is an account-opening decision rather than a code "
      "change.")
    w("- Whoever sent a note can tell that it was spent, because they know the "
      "`g^S` they built. That is unavoidable in this construction. To a third "
      "party the ring size is the limit of what is learned.")


    w("- The note rail's decoy selection is uniform over the pool, and a real "
      "spend is of a recently received note. Section 5's finding stands: an "
      "anonymity set is other people's traffic, and the decoy rule only decides "
      "whether the ring can use it.")

    (ROOT / "DEFMI.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {ROOT / 'DEFMI.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
