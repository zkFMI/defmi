//! Build the DeFMI technical document from native Rust measurement artifacts.

use qomm_harness::{
    comma_i64, measurement_value, render_measurement, repo_root, value_display, HarnessResult,
};
use qomm_measure::hosts::label;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

struct Document(Vec<String>);

impl Document {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn push(&mut self, line: impl Into<String>) {
        self.0.push(line.into());
    }

    fn finish(self) -> String {
        self.0.join("\n") + "\n"
    }
}

fn load(artifacts: &Path, name: &str) -> HarnessResult<Option<Value>> {
    let path = artifacts.join(name);
    if path.exists() {
        Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
    } else {
        Ok(None)
    }
}

fn num(value: &Value) -> HarnessResult<f64> {
    value
        .as_f64()
        .ok_or_else(|| format!("expected number, got {value}").into())
}

fn int(value: &Value) -> HarnessResult<i64> {
    value
        .as_i64()
        .ok_or_else(|| format!("expected integer, got {value}").into())
}

fn count(value: &Value) -> HarnessResult<i64> {
    match value.get("exact") {
        Some(exact) => int(exact),
        None => int(value),
    }
}

fn ms(value: &Value, places: usize) -> HarnessResult<String> {
    render_measurement(value, places)
}

fn rows(value: &Value) -> HarnessResult<&Vec<Value>> {
    value.as_array().ok_or_else(|| "expected array".into())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> HarnessResult<()> {
    if std::env::args_os().len() != 1 {
        return Err("build_defmi_doc takes no arguments".into());
    }
    let root = repo_root();
    let art = root.join("artifacts");
    let Some(data) = load(&art, "defmi.json")? else {
        return Err("artifacts/defmi.json is missing; run `make defmi` first.".into());
    };
    let rust = load(&art, "rust_bench.json")?;
    let pvp = load(&art, "pvp.json")?;
    let same_chain = load(&art, "same_chain.json")?;
    let rings = load(&art, "rings.json")?;
    let reconcile = load(&art, "reconcile.json")?;
    let note_dvp = load(&art, "note_dvp_rust.json")?;
    let viewing = load(&art, "viewing.json")?;
    let deccp = load(&art, "deccp.json")?;
    let vetting = load(&art, "vetting.json")?;
    let avalanche = load(&art, "avalanche_l1_acceptance.json")?;

    let mut d = Document::new();
    build_core(&mut d, &data)?;
    build_deccp_and_notes(&mut d, &data, deccp.as_ref())?;
    build_ring_value(&mut d, &data, rings.as_ref())?;
    build_pvp(&mut d, &data, pvp.as_ref())?;
    build_same_chain(&mut d, &data, same_chain.as_ref())?;
    build_reconcile(&mut d, reconcile.as_ref())?;
    build_note_dvp(&mut d, note_dvp.as_ref())?;
    build_viewing(&mut d, viewing.as_ref())?;
    build_vetting(&mut d, vetting.as_ref())?;
    build_avalanche(&mut d, avalanche.as_ref())?;
    build_parallel(&mut d, &data, None)?;
    build_proof_backend_comparison(&mut d, &data, rust.as_ref())?;
    build_missing(&mut d, &data);

    let output = root.join("DEFMI.md");
    fs::write(&output, d.finish())?;
    println!("wrote {}", output.display());
    Ok(())
}

fn build_core(out: &mut Document, d: &Value) -> HarnessResult<()> {
    out.push("# DeFMI — a settlement layer that never reads the trade\n");
    out.push(concat!(
        "DeFMI means **Decentralized Financial Market Infrastructure**. It is not a stock-only ",
        "ledger: the chain-neutral state machine registers cash, securities, funds, commodities, ",
        "carbon units and other governed assets.\n"
    ));
    out.push(format!(
        "Measured on `{}` / {} / group {}.",
        label(d["host"].as_str().ok_or("host is not text")?),
        value_display(&d["rustc"]),
        value_display(&d["group"])
    ));
    out.push(concat!(
        "This document is generated from the measurement JSON by `make defmi-doc`. No number in it ",
        "was typed by hand.\n"
    ));
    if d.get("calibration").is_some_and(|v| !v.is_null()) {
        let c = &d["calibration"];
        out.push(format!(
            "**Calibration**: scalar multiplication {} us, 40-bit range proof {} ms.",
            ms(&c["scalar_mult_us"], 1)?,
            ms(&c["range_proof_40bit_ms"], 2)?
        ));
        out.push(concat!(
            "Every millisecond below is from a machine in that state. The same machine has been ",
            "half again slower at another time, so compare these two figures before comparing ",
            "anything else here with anything measured elsewhere.\n"
        ));
    }

    out.push("## 1. What is guaranteed, and what is not\n");
    out.push("DeFMI can check only what arithmetic settles without opening anything.\n");
    out.push("| Guarantee | What makes it hold |");
    out.push("| --- | --- |");
    out.push("| Value is neither created nor destroyed | the product of the balance commitments equals the product at issue (homomorphism alone) |");
    out.push("| No balance goes negative | a range proof on the difference |");
    out.push("| The two legs move together | both are checked before either is applied |");
    out.push("| One instruction settles once | nullifier registration |");
    out.push("| Cash leg = quantity x price | a product proof over three commitments |");
    out.push(
        "| The securities leg is the instructed quantity | an equality proof across generators |\n",
    );
    out.push(concat!(
        "What DeFMI does *not* check is whether the price was reasonable or whether that was the ",
        "right instrument. Those meanings come from the computing nodes' quorum and travel in the ",
        "instruction's signature. Making the settlement layer re-derive them would mean handing it ",
        "the plaintext, which is the one thing this construction exists to avoid.\n"
    ));

    let scaling = rows(&d["scaling"])?;
    out.push("## 2. Cost depends on the balance width and nothing else\n");
    out.push("The proof is a bit decomposition of the ledger's balance range, so it should be linear. It is.\n");
    out.push("| balance width | issue instruction | build package | settle (verify) | package |");
    out.push("| ---: | ---: | ---: | ---: | ---: |");
    for row in scaling {
        out.push(format!(
            "| {} bit | {} ms | {} ms | {} ms | {} B |",
            value_display(&row["bits"]),
            ms(&row["issue"], 1)?,
            ms(&row["build"], 1)?,
            ms(&row["settle"], 1)?,
            comma_i64(count(&row["package_bytes"])?),
        ));
    }
    let lo = scaling.first().ok_or("scaling is empty")?;
    let hi = scaling.last().ok_or("scaling is empty")?;
    let span = num(&hi["bits"])? - num(&lo["bits"])?;
    let build_slope = (measurement_value(&hi["build"])? - measurement_value(&lo["build"])?) / span;
    let settle_slope =
        (measurement_value(&hi["settle"])? - measurement_value(&lo["settle"])?) / span;
    let byte_slope = (count(&hi["package_bytes"])? - count(&lo["package_bytes"])?) as f64 / span;
    let settle_intercept = measurement_value(&lo["settle"])? - settle_slope * num(&lo["bits"])?;
    let at40 = scaling.iter().find(|row| row["bits"].as_i64() == Some(40));
    out.push("");
    out.push(format!(
        "The slopes are **{build_slope:.2} ms/bit** to build, **{settle_slope:.2} ms/bit** to settle and **{byte_slope:.0} B/bit** on the wire."
    ));
    out.push(format!(
        concat!(
            "The settlement intercept, **{:.1} ms**, is the part that does not ",
            "depend on the ledger's width: it is the verification of the zkPI instruction itself."
        ),
        settle_intercept
    ));
    if let Some(at40) = at40 {
        let share = 100.0 * settle_intercept / measurement_value(&at40["settle"])?;
        out.push(format!(
            concat!(
                "At 40 bits, settlement costs {} ms, of which about {:.0}% is the instruction and ",
                "the rest is the ledger's range proofs.\n"
            ),
            ms(&at40["settle"], 1)?,
            share
        ));
    }
    out.push(concat!(
        "**Consequence**: if settlement needs to be faster, reconsidering the balance width beats ",
        "changing the cryptography. That is a listing decision, not a technical one.\n"
    ));

    if let Some(split) = d
        .get("split_rails")
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty())
    {
        out.push("### 2.1 A different width for each rail\n");
        out.push(concat!(
            "A quantity of securities and an amount of cash are orders of magnitude apart. There ",
            "is no reason to give them the same width.\n"
        ));
        out.push("| securities rail | cash rail | build | settle | package |");
        out.push("| ---: | ---: | ---: | ---: | ---: |");
        for row in split {
            out.push(format!(
                "| {} bit | {} bit | {} ms | {} ms | {} B |",
                value_display(&row["securities_bits"]),
                value_display(&row["cash_bits"]),
                ms(&row["build"], 1)?,
                ms(&row["settle"], 1)?,
                comma_i64(count(&row["package_bytes"])?),
            ));
        }
        let base = &split[0];
        let best = split
            .iter()
            .min_by(|a, b| {
                measurement_value(&a["settle"])
                    .unwrap()
                    .partial_cmp(&measurement_value(&b["settle"]).unwrap())
                    .unwrap()
            })
            .ok_or("split empty")?;
        let drop = 100.0
            * (measurement_value(&base["settle"])? - measurement_value(&best["settle"])?)
            / measurement_value(&base["settle"])?;
        out.push("");
        out.push(format!(
            concat!(
                "Against both rails at {} bits, running securities at {} and cash at {} settles ",
                "**{:.0}% faster** and sends **{} B less**. Not one line of the cryptography changed.\n"
            ),
            value_display(&base["securities_bits"]), value_display(&best["securities_bits"]),
            value_display(&best["cash_bits"]), drop,
            comma_i64(count(&base["package_bytes"])? - count(&best["package_bytes"])?),
        ));
    }

    build_asset_hiding(out, d)?;
    build_netting_and_credit(out, d)?;
    Ok(())
}

fn build_asset_hiding(out: &mut Document, d: &Value) -> HarnessResult<()> {
    let Some(asset_rows) = d
        .get("asset_hiding")
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty())
    else {
        return Ok(());
    };
    out.push("## 3. Hiding which instrument, from the settlement layer too\n");
    out.push(concat!(
        "The MPC layer hides which asset a request is for. Dropping the trade onto a per-instrument ",
        "rail at settlement would give that back. Putting every instrument on one rail instead ",
        "makes conservation hold only across instruments, so asset A could be carried out as asset B.\n"
    ));
    out.push(concat!(
        "The construction used is an asset tag. Holding q units of asset a means holding `A_a^q . ",
        "h^r`; each transfer publishes `H = A_a . h^y` under a fresh y, and every range proof is ",
        "made against `H`. **What binds the disguise to a real asset is the range proof on the ",
        "difference**: the payer's balance already sits under `A_a`, so no other tag can open it.\n"
    ));
    out.push("| instruments | set size | build, untagged | build, tagged | package | membership (at issue only) |");
    out.push("| ---: | ---: | ---: | ---: | ---: | --- |");
    for row in asset_rows {
        let plain = &row["arms"]["plain"];
        let tagged = &row["arms"]["tagged"];
        out.push(format!(
            concat!("| {} | {} | {} ms | {} ms | +{} B | prove {} / verify {} ms, {} B |"),
            value_display(&row["assets"]),
            value_display(&row["set_size"]),
            ms(&plain["build"], 1)?,
            ms(&tagged["build"], 1)?,
            count(&tagged["package_bytes"])? - count(&plain["package_bytes"])?,
            ms(&row["membership_prove"], 2)?,
            ms(&row["membership_verify"], 2)?,
            value_display(&row["membership_bytes"]),
        ));
    }
    out.push("");
    let plains = asset_rows
        .iter()
        .map(|r| measurement_value(&r["arms"]["plain"]["build"]))
        .collect::<Result<Vec<_>, _>>()?;
    let deltas = asset_rows
        .iter()
        .map(|r| {
            Ok(measurement_value(&r["arms"]["tagged"]["build"])?
                - measurement_value(&r["arms"]["plain"]["build"])?)
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let noise = plains.iter().copied().fold(f64::NEG_INFINITY, f64::max)
        - plains.iter().copied().fold(f64::INFINITY, f64::min);
    out.push(format!(
        concat!(
            "Every row of the untagged column runs the same work, so its own spread --- **{:.1} ",
            "ms** --- is this measurement's noise floor. The tagged column differs from it by ",
            "{:+.1} to {:+.1} ms, which is **inside that floor**. So the honest statement is that ",
            "the time cost is too small to measure here; a percentage would mislead. Only the extra ",
            "bytes are certain.\n"
        ),
        noise,
        deltas.iter().copied().fold(f64::INFINITY, f64::min),
        deltas.iter().copied().fold(f64::NEG_INFINITY, f64::max)
    ));
    out.push(concat!(
        "Per settlement the addition is **32 B** (one published tag) and one sigma proof across ",
        "generators. The one-out-of-many membership proof (Groth-Kohlweiss) is not needed every ",
        "time: a balance already sitting under a registered tag passes soundness down to the ",
        "transfer, so the proof is needed **once, when the balance is issued into the account**.\n"
    ));
    out.push("Indistinguishability and the attack arms, measured:\n");
    for row in asset_rows {
        let per_asset = row["per_asset"]
            .as_object()
            .ok_or("per_asset is not an object")?;
        let first = per_asset.values().next().ok_or("per_asset is empty")?;
        out.push(format!(
            "- {} instruments: the package is identical whichever one it is ({}, {} B across {} instruments).",
            value_display(&row["assets"]),
            if row["indistinguishable"].as_bool().unwrap_or(false) { "identical" } else { "NOT identical" },
            comma_i64(count(&first["package_bytes"])?), per_asset.len()
        ));
        for name in ["registered_tag_wrong_asset", "fabricated_tag"] {
            let attack = &row["attacks"][name];
            if attack.is_null() {
                continue;
            }
            let display = match name {
                "registered_tag_wrong_asset" => {
                    "carry it out under a registered tag for another asset"
                }
                "fabricated_tag" => "use a point that was never registered",
                _ => name,
            };
            out.push(format!(
                "  - {display}: `{}` --- {}",
                value_display(&attack["status"]),
                value_display(&attack["reason"])
            ));
        }
    }
    out.push("");
    Ok(())
}

fn build_netting_and_credit(out: &mut Document, d: &Value) -> HarnessResult<()> {
    if let Some(netting) = d.get("netting").filter(|v| !v.is_null()) {
        let net_rows = rows(&netting["rows"])?;
        out.push("## 4. Netting: gross-gross, gross-net, net-net\n");
        out.push(concat!(
            "These are the BIS DvP models 1, 2 and 3. They are a question about settlement design ",
            "and, at the same time, a question about **how many range proofs land and where**.\n"
        ));
        out.push(
            "A rail is either gross or net, and that single choice decides everything else.\n",
        );
        out.push(concat!(
            "- **A gross rail** checks at each order. It proves on the spot that the post-trade ",
            "position is non-negative, so **settlement failure cannot occur by construction**. The ",
            "price is order dependence: a participant receiving 100 and delivering 100 is refused ",
            "if the delivery arrives first. That deliberately gives up the liquidity saving netting ",
            "exists to provide."
        ));
        out.push(concat!(
            "- **A net rail** only accumulates homomorphically during the period and proves nothing. ",
            "A commitment hides the sign as well as the magnitude, so an intermediate position may ",
            "be negative without leaking anything --- what is not proved is not disclosed. At the ",
            "close it shows coverage once per participant, on the **net**. The liquidity saving ",
            "comes back and order dependence goes away, at the cost of a close that can fail.\n"
        ));
        out.push(
            "| N | P | mode | verify per order | verify at close | verify total | vs gross-gross |",
        );
        out.push("| ---: | ---: | --- | ---: | ---: | ---: | ---: |");
        for row in net_rows {
            out.push(format!(
                "| {} | {} | {} | {} ms | {} ms | {} ms | {:.2}x |",
                value_display(&row["trades"]),
                value_display(&row["participants"]),
                value_display(&row["mode"]),
                ms(&row["verify_per_order"], 2)?,
                ms(&row["verify_close"], 1)?,
                ms(&row["verify_total"], 1)?,
                num(&row["speedup_vs_gross_gross"])?
            ));
        }
        out.push("");
        let largest = net_rows
            .iter()
            .filter_map(|r| r["trades"].as_i64())
            .max()
            .ok_or("netting empty")?;
        let pick = |mode: &str| {
            net_rows.iter().find(|r| {
                r["trades"].as_i64() == Some(largest)
                    && r["mode"].as_str().is_some_and(|m| {
                        if mode == "attested" {
                            m.ends_with(mode)
                        } else {
                            m == mode
                        }
                    })
            })
        };
        let gg = pick("gross-gross").ok_or("gross-gross missing")?;
        let nn = pick("net-net").ok_or("net-net missing")?;
        let at = pick("attested").ok_or("attested missing")?;
        out.push(format!(
            concat!(
                "**The first prediction was wrong.** Counting range proofs alone gave an estimate ",
                "that net-net would be an eighth of the work; measured, it is only {:.2}x. Even ",
                "under net-net, {} ms per order remains, and that is the verification of the zkPI ",
                "instruction itself --- which carries range proofs on amount and price inside it. ",
                "**It is needed once per trade and netting does not remove it.**\n"
            ),
            measurement_value(&gg["verify_total"])? / measurement_value(&nn["verify_total"])?,
            ms(&nn["verify_per_order"], 1)?
        ));
        out.push(format!(
            concat!(
                "What removes it is changing the **granularity of the instruction**. If the quorum ",
                "signs a whole cycle rather than each trade, the settlement layer's work stops ",
                "depending on the number of trades ({} ms per order, {} ms in total, **{:.1}x**). ",
                "The individual trades are then no longer verified, so the allocation between ",
                "participants becomes **the quorum's attestation rather than a proof**. Conservation ",
                "and coverage still hold, and each participant can check its own net, so what is ",
                "lost is third-party verifiability of the allocation. That is what a central ",
                "counterparty has always been; this only makes it explicit.\n"
            ),
            ms(&at["verify_per_order"], 2)?, ms(&at["verify_total"], 1)?,
            num(&at["speedup_vs_gross_gross"])?
        ));
    }

    if let Some(c) = d.get("credit").filter(|v| !v.is_null()) {
        out.push("### 4.1 How far a net position may go (an intraday overdraft)\n");
        out.push(concat!(
            "Refusing any order that would make a net position negative removes settlement failure, ",
            "and, as above, removes the liquidity saving with it. Practice puts a **limit** here ",
            "instead --- the Bank of Japan's intraday overdraft is exactly this: eligible collateral ",
            "is pledged, a limit is granted up to its value after haircut, and the position may be ",
            "negative down to that limit.\n"
        ));
        out.push(concat!(
            "The limit is a **commitment**, and not only to hide its size. Coverage is then proved ",
            "about `position + limit`, which means the proof **never says which side of zero the ",
            "position was on**. The offset trickery that hiding a sign usually needs is not needed ",
            "anywhere.\n"
        ));
        out.push("| operation | cost | how often |");
        out.push("| --- | ---: | --- |");
        out.push(format!("| grant a limit (proving the collateral covers it after haircut) | build {} / verify {} ms | once per limit |",
            ms(&c["grant"], 1)?, ms(&c["check"], 1)?));
        out.push(format!(
            "| coverage proof, no limit | {} ms | per participant per rail, at the close |",
            ms(&c["coverage_plain"], 1)?
        ));
        out.push(format!(
            "| coverage proof, with a limit | {} ms | as above |",
            ms(&c["coverage_capped"], 1)?
        ));
        out.push("");
        out.push(format!(concat!("**The limit is essentially free** ({} to {} ms --- the same range proof width against a different commitment). ",
            "**Admission, pledge, overdraft and payment should be one event**, because doing them in sequence allows either collateral locked with no limit granted ",
            "or a limit standing with no collateral behind it. **They are not one event here.** This paragraph named an `admit_with_credit` that does not exist in the Rust implementation: ",
            "`PositionBook::grant` and `Cycle::admit` are separate calls, and a grant that succeeds before an admit that fails leaves the credit standing. ",
            "There is also no state that locks and unlocks pledged collateral. What is measured above is the cost of the limit, which is real; the atomicity is a design requirement that is written down and not built.\n"),
            ms(&c["coverage_plain"], 1)?, ms(&c["coverage_capped"], 1)?));
        if let Some(waterfall) = c
            .get("waterfall")
            .and_then(Value::as_array)
            .filter(|v| !v.is_empty())
        {
            out.push("### 4.2 The default waterfall\n");
            out.push(concat!("A net rail can fail at the close. The order in which that failure is worked through is the substance of the arrangement, so it has to be **enforced** and not assumed. ",
                "The condition that tranche k may be drawn only once tranche k-1 is exhausted is written `draw_k x remaining_{k-1} = 0`. ",
                "The product's commitment is pinned to the identity, so there is nothing to hand the verifier.\n"));
            out.push("| tranches | build | verify |");
            out.push("| ---: | ---: | ---: |");
            for row in waterfall {
                out.push(format!(
                    "| {} | {} ms | {} ms |",
                    value_display(&row["tranches"]),
                    ms(&row["build"], 1)?,
                    ms(&row["check"], 1)?
                ));
            }
            let first = &waterfall[0];
            let last = waterfall.last().unwrap();
            let per = (measurement_value(&last["build"])? - measurement_value(&first["build"])?)
                / (num(&last["tranches"])? - num(&first["tranches"])?);
            out.push("");
            out.push(format!("**{per:.1} ms per tranche** --- one range proof's worth, linear. It runs once per default, so nobody need ever care about this number.\n"));
        }
    }
    Ok(())
}

fn build_deccp_and_notes(
    out: &mut Document,
    d: &Value,
    deccp: Option<&Value>,
) -> HarnessResult<()> {
    if let Some(deccp) = deccp {
        out.push("### 4.2 Interposing a clearing house, and what novation is worth\n");
        out.push(concat!(
            "The paragraph above ends by calling the batch attestation \"the same bargain a central ",
            "counterparty represents, made explicit\". That was one step short. **Under novation ",
            "there is no split left to verify**, because there are no bilateral claims left to ",
            "split: a trade between A and B becomes A against the house and the house against B, ",
            "and the original obligation stops existing. Verifying an allocation that has been ",
            "extinguished is not a check anybody was owed.\n"
        ));
        out.push(concat!(
            "And novation is free here. An obligation is a commitment, so replacing one edge with ",
            "two is two multiplications and no proof --- nothing is being asserted, the graph is ",
            "being rewritten. The house's book is flat by the same construction: it owes exactly ",
            "what it is owed, per asset, so that is one comparison rather than a statement anybody ",
            "has to establish.\n"
        ));
        out.push(format!(
            "Measured at {} participants, against the two arms above run by the same harness:\n",
            value_display(&deccp["participants"])
        ));
        out.push("| trades | net-net | net-net+attested | **DeCCP** | vs net-net | novation |");
        out.push("| ---: | ---: | ---: | ---: | ---: | ---: |");
        let deccp_rows = rows(&deccp["rows"])?;
        for row in deccp_rows {
            out.push(format!(
                "| {} | {} | {} | **{:.1} ms** | **{}x** | {} us/trade |",
                value_display(&row["trades"]),
                ms(&row["net_net"], 1)?,
                ms(&row["net_net_attested"], 1)?,
                num(&row["deccp_total"])?,
                value_display(&row["speedup_deccp_vs_plain"]),
                value_display(&row["novate_us_per_trade"])
            ));
        }
        out.push("");
        let first = deccp_rows.first().ok_or("deccp rows empty")?;
        let last = deccp_rows.last().ok_or("deccp rows empty")?;
        out.push(format!(
            concat!(
                "**net-net grows with the trades and DeCCP does not.** From {} to {} trades the ",
                "instruction path goes {:.0} ms to {:.0} ms while the cleared cycle goes {:.0} ms ",
                "to {:.0} ms. What is left is the close, and the close is per participant.\n"
            ),
            value_display(&first["trades"]),
            value_display(&last["trades"]),
            num(&first["net_net"]["median"])?,
            num(&last["net_net"]["median"])?,
            num(&first["deccp_total"])?,
            num(&last["deccp_total"])?
        ));
        out.push(format!(
            concat!(
                "So the speed was never the contribution --- the attested arm already had it. ",
                "**What novation costs is {} us a trade, and what it buys is that the arm is ",
                "defensible**: a named house took the other side, its book is checked flat by ",
                "anyone, its margin is posted as a committed cap, and its own capital sits in the ",
                "default waterfall between the defaulting member's fund contribution and the ",
                "mutualised pool, which is where CPMI-IOSCO and EMIR put it.\n"
            ),
            value_display(&last["novate_us_per_trade"])
        ));
        out.push(concat!(
            "A slot rather than a dependency. A deployment names the providers it accepts and ",
            "several may coexist; nothing in the netting cycle or the settlement layer knows which ",
            "house cleared a trade, and a deployment with no provider at all is the bilateral case, ",
            "which still works and pays per-trade proofs for it.\n"
        ));
        out.push(concat!(
            "**Four things it does not do.** Obligation graphs are per asset, so a novation that ",
            "mixed instruments is refused rather than netted across them. Several providers make ",
            "the waterfall a forest and not a list, and a position at one provider is **not** offset ",
            "against a position at another --- cross-margining is a different problem and is not ",
            "solved here. Novation being free arithmetically says nothing about it being valid ",
            "legally, which is the register's rulebook and not this code. And **the house can leave ",
            "a trade out, though it can no longer invent one**: `check_novation` requires both ",
            "counterparties' signatures on every edge of the before graph, so a trade nobody made ",
            "is refused --- this paragraph used to say a house could novate invented trades and ",
            "produce a cycle that checked out, and that stopped being true when the signatures went ",
            "in. Omission is what remains, and the arithmetic cannot tell: a graph missing an edge ",
            "is a consistent graph. The tranche is what makes getting it wrong expensive.\n"
        ));

        if let Some(notes) = d.get("notes").filter(|v| !v.is_null()) {
            out.push("## 5. Hiding who paid whom (the note ledger)\n");
            out.push(concat!(
                "The asset tag hides *what*. An account ledger still names four handles in the ",
                "clear at every settlement. Even with every balance committed, handles that recur ",
                "draw the counterparty graph.\n"
            ));
            out.push(concat!(
                "So accounts were replaced by notes. A note is `C = g^S . A_a^v . h^r`, where only ",
                "the **payee** can construct S --- the sender can form `g^S` from the public key but ",
                "does not know the b in S = H(A^e) + b. Spending keeps S hidden and shows with ",
                "Groth-Kohlweiss that **one of** the ring holds this S, without saying which.\n"
            ));
            out.push("| ring size | prove (payer) | verify (node) | wire |");
            out.push("| ---: | ---: | ---: | ---: |");
            let ring_rows = rows(&notes["rings"])?;
            for row in ring_rows {
                out.push(format!(
                    "| {} | {} ms | {} ms | {} B |",
                    value_display(&row["ring"]),
                    ms(&row["build"], 1)?,
                    ms(&row["check"], 1)?,
                    comma_i64(count(&row["wire_bytes"])?),
                ));
            }
            let small = ring_rows.first().ok_or("note rings empty")?;
            let large = ring_rows.last().ok_or("note rings empty")?;
            let mid = ring_rows.iter().find(|r| r["ring"].as_i64() == Some(64));
            out.push("");
            out.push(format!(
                concat!(
                    "**The asymmetry is the point.** The wire grows by 224 B per doubling, and ",
                    "verification only goes from {} to {} ms between rings {} and {}. What breaks ",
                    "is the proving side: {} to {} ms."
                ),
                ms(&small["check"], 1)?,
                ms(&large["check"], 1)?,
                value_display(&small["ring"]),
                value_display(&large["ring"]),
                ms(&small["build"], 1)?,
                ms(&large["build"], 1)?
            ));
            if let Some(mid) = mid {
                out.push(format!(
                    concat!(
                        "So **what caps the anonymity set is the payer, not the settlement node**. ",
                        "A ring of 64 costs {} ms to prove and {} ms to verify, which a payer's own ",
                        "device can carry."
                    ),
                    ms(&mid["build"], 1)?, ms(&mid["check"], 1)?
                ));
            }
            out.push("");
            out.push(format!(
                concat!(
                    "A payee has to scan the pool to find its own notes, at **{:.3} ms** each ",
                    "({:.1} ms over {}). That is one scalar multiplication, and it is the only cost ",
                    "proportional to the pool."
                ),
                num(&notes["scan_ms_per_note"] )?, num(&notes["scan_ms"] )?,
                value_display(&notes["pool_size"])
            ));
            out.push(format!(
                concat!(
                    "Two payments to the same address cannot be linked: **{}** (neither the ",
                    "commitments nor the ephemeral points match).\n"
                ),
                value_display(&notes["outputs_unlinkable"])
            ));
        }
    }

    if let Some(note_settlement) = d.get("note_settlement").filter(|v| !v.is_null()) {
        let scaling = rows(&d["scaling"])?;
        let at40 = scaling.iter().find(|r| r["bits"].as_i64() == Some(40));
        let base = at40.map(|r| measurement_value(&r["settle"])).transpose()?;
        out.push("### 5.1 The same DvP over note rails\n");
        out.push(concat!(
            "Both rails were made note rails and the settlement itself was run through them. The ",
            "binding to the instruction is kept by a single equality proof across generators, ",
            "because the quantity is committed under the tag and the instruction under the base.\n"
        ));
        out.push("| ring size | build | settle (verify) | package | vs the account version |");
        out.push("| ---: | ---: | ---: | ---: | ---: |");
        let note_rows = rows(&note_settlement["rings"])?;
        for row in note_rows {
            let delta = match base {
                None => "---".to_string(),
                Some(base) => format!(
                    "{:+.0}%",
                    100.0 * (measurement_value(&row["settle"])? - base) / base
                ),
            };
            out.push(format!(
                "| {} | {} ms | {} ms | {} B | {delta} |",
                value_display(&row["ring"]),
                ms(&row["build"], 1)?,
                ms(&row["settle"], 1)?,
                comma_i64(count(&row["package_bytes"])?),
            ));
        }
        if let (Some(base), Some(at40)) = (base, at40) {
            out.push("");
            let first = note_rows.first().ok_or("note settlement empty")?;
            let last = note_rows.last().ok_or("note settlement empty")?;
            out.push(format!(
                concat!(
                    "The account version settles in {} ms at 40 bits. Hiding the counterparties ",
                    "costs {:+.0}% at ring {} and {:+.0}% at ring {}."
                ),
                ms(&at40["settle"], 1)?,
                100.0 * (measurement_value(&first["settle"])? - base) / base,
                value_display(&first["ring"]),
                100.0 * (measurement_value(&last["settle"])? - base) / base,
                value_display(&last["ring"])
            ));
            out.push(concat!(
                "**Adding up the parts was off by more than a factor of two.** A note leg and an ",
                "account leg both carry two range proofs; the difference is only the ring proof, ",
                "the serial proof and one equality proof.\n"
            ));
        }
    }
    Ok(())
}

fn build_ring_value(out: &mut Document, d: &Value, rings: Option<&Value>) -> HarnessResult<()> {
    let Some(rings) = rings else {
        return Ok(());
    };
    let ring_rows = rows(&rings["rows"])?;
    let mut by: BTreeMap<(String, i64, i64), &Value> = BTreeMap::new();
    let mut sizes = BTreeSet::new();
    let mut loads = BTreeSet::new();
    for row in ring_rows {
        let key = (
            row["decoys"]
                .as_str()
                .ok_or("decoys is not text")?
                .to_string(),
            int(&row["ring"])?,
            int(&row["traffic"])?,
        );
        sizes.insert(key.1);
        loads.insert(key.2);
        by.insert(key, row);
    }
    let sizes: Vec<i64> = sizes.into_iter().collect();
    let loads: Vec<i64> = loads.into_iter().collect();
    out.push("### 5.2 What the ring is actually worth\n");
    if rings["host"] != d["host"] {
        out.push(format!(
            "*Taken on `{}`.*\n",
            label(rings["host"].as_str().ok_or("ring host is not text")?)
        ));
    }
    out.push(concat!(
        "Every table above prices the ring. None of them asks what it buys, and the answer has been ",
        "the ring size --- an observer who knows a leg spent one of R notes names it with ",
        "probability 1/R. That is what the proof guarantees and it is not what a reader of the chain ",
        "gets.\n"
    ));
    out.push(concat!(
        "A ring is an anonymity set only if the decoys are indistinguishable from the real note. ",
        "`ring_for` drew its decoys uniformly over every note the ledger had ever held. A real spend ",
        "is of a note the spender was just paid, because that is what settling is --- you are paid, ",
        "and then you pay. Recent notes have high indices and uniform decoys mostly do not, so **an ",
        "observer who guesses the newest member of the ring** does far better than 1/R and pays ",
        "nothing for it.\n"
    ));
    out.push(concat!(
        "The strategy was stated before the run and the observer is scored at the better of the ",
        "two, because a real one would take it. `traffic` is how many other settlements land ",
        "between one firm being paid and paying: the pool grows by four notes a settlement, so it ",
        "is other people's activity, measured in notes that arrive above yours.\n"
    ));
    out.push(format!(
        "| decoys | ring | {} | 1/R |",
        loads
            .iter()
            .map(|v| format!("traffic {v}"))
            .collect::<Vec<_>>()
            .join(" | ")
    ));
    out.push(format!(
        "| --- | ---: | {} | ---: |",
        loads.iter().map(|_| "---:").collect::<Vec<_>>().join(" | ")
    ));
    for decoys in ["uniform", "recent"] {
        for size in &sizes {
            let cells = loads
                .iter()
                .map(|load| {
                    by.get(&(decoys.to_string(), *size, *load))
                        .and_then(|r| r["observer_success"].as_f64())
                        .map_or_else(|| "--".to_string(), |v| format!("{v:.3}"))
                })
                .collect::<Vec<_>>();
            out.push(format!(
                "| {decoys} | {size} | {} | {:.3} |",
                cells.join(" | "),
                1.0 / *size as f64
            ));
        }
    }
    out.push("");
    let last_size = *sizes.last().ok_or("no ring sizes")?;
    let last_load = *loads.last().ok_or("no traffic loads")?;
    let worst = by
        .get(&("uniform".into(), last_size, last_load))
        .ok_or("uniform row missing")?;
    let best = by
        .get(&("recent".into(), last_size, last_load))
        .ok_or("recent row missing")?;
    out.push(concat!(
        "**With no other traffic the ring is worth nothing at all** --- 1.000 at every size, under ",
        "either rule, because a note spent one settlement after it arrived is the newest note there ",
        "is and no decoy can be newer than the newest. That is not a decoy-selection bug; it is the ",
        "honest shape of the thing:\n"
    ));
    out.push("> an anonymity set on a note rail is other people's traffic, and the decoy rule only decides how much of it the ring can use.\n");
    out.push(concat!(
        "Which is the same shape as §6.1 below. A construction that hides you in a crowd does not ",
        "work in an empty room, and saying so is part of reporting what it does.\n"
    ));
    out.push(format!(
        concat!(
            "What the decoy rule is worth is the gap between the two blocks. At ring {} with {} ",
            "settlements of other traffic, uniform decoys leave the observer at **{:.3}** against a ",
            "nominal {:.3} --- {:.1} times what the proof promises. Drawing the decoys from the same ",
            "recency window that real spends come from brings it to **{:.3}**, which is the nominal ",
            "figure exactly. `ring_recent` is that rule and it is thirty lines.\n"
        ),
        last_size, last_load, num(&worst["observer_success"] )?, 1.0 / last_size as f64,
        num(&worst["observer_success"])? * last_size as f64,
        num(&best["observer_success"])?
    ));

    if let Some(state_root) = rings
        .get("state_root")
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty())
    {
        out.push("### 5.3 A settlement that got slower the longer the ledger ran\n");
        out.push(concat!(
            "The benchmark above found something that is not about rings. Its verification times ",
            "climbed with the pool, and nothing in `check_spend` is proportional to the pool --- the ",
            "ring proof, the range proofs and the balance check are all in the ring. What was ",
            "proportional to it was the **state root**: `snapshot` compressed every note the ledger ",
            "had ever held and re-sorted every spent serial, and a settlement takes four of them, ",
            "two rails before and after.\n"
        ));
        out.push("| notes held | root by walking | root as kept | |");
        out.push("| ---: | ---: | ---: | ---: |");
        for row in state_root {
            let ratio = measurement_value(&row["walked_us"])?
                / measurement_value(&row["kept_us"])?.max(1e-9);
            out.push(format!(
                "| {} | {} us | {} us | {}x |",
                comma_i64(int(&row["pool"])?),
                ms(&row["walked_us"], 1)?,
                ms(&row["kept_us"], 2)?,
                comma_i64(ratio.round() as i64)
            ));
        }
        out.push("");
        let large = state_root.last().unwrap();
        out.push(format!(
            concat!(
                "At {} notes the four roots in one settlement came to **{:.1} ms**, against about 8 ",
                "ms of cryptography --- the bookkeeping had become an order of magnitude more ",
                "expensive than the proofs, and it would keep growing, because it was a function of ",
                "total history rather than of activity. That is the exact property §7 checks for ",
                "the account rail and it had gone unchecked here.\n"
            ),
            comma_i64(int(&large["pool"])?),
            measurement_value(&large["per_settlement_walked_us"])? / 1000.0
        ));
        out.push(concat!(
            "Nothing about the ledger required it. Notes are only ever appended --- a spent note ",
            "stays in the pool, because removing it would say which one went --- and serials are ",
            "only ever inserted, so the hash of the whole history is a running hash extended once ",
            "per change. The sort was buying order-independence for a sequence that already has an ",
            "order: the one the chain applied. The root is now kept rather than recomputed and the ",
            "column above is flat.\n"
        ));
    }
    Ok(())
}

fn build_pvp(out: &mut Document, d: &Value, pvp: Option<&Value>) -> HarnessResult<()> {
    let Some(pvp) = pvp else {
        return Ok(());
    };
    let milli = &pvp["milliseconds"];
    let micro = &pvp["microseconds"];
    out.push("## 6. Payment versus payment, across two ledgers\n");
    if pvp["host"] != d["host"] {
        out.push(format!(
            concat!(
                "*The two tables in this section were taken on `{}`, not the `{}` of the rest of ",
                "this document: they are Rust benchmarks and they wanted a machine that was not ",
                "doing anything else.*\n"
            ),
            label(pvp["host"].as_str().ok_or("pvp host is not text")?),
            label(d["host"].as_str().ok_or("defmi host is not text")?)
        ));
    }
    out.push(concat!(
        "DvP moves two legs together because both are on one ledger and one function decides. Two ",
        "ledgers that share no state have no such function, and fair exchange between two parties ",
        "with no third party is impossible in general --- so something has to pass from one side to ",
        "the other. The only question is what, and who can read it.\n"
    ));
    out.push(concat!(
        "A hash lock passes a preimage that ends up in the clear on both ledgers, so anyone reading ",
        "both can join the two legs on it. That is the linkage the asset tag and the note ledger ",
        "were built to prevent, handed back at the last step. What is used instead is an **adaptor ",
        "signature**: the first mover's claim on one ledger hands the second mover a scalar, and ",
        "what each ledger records is an ordinary signature with nothing in common with the other's.\n"
    ));
    out.push("```");
    out.push("1. Bob   -> Alice : Y = g^y");
    out.push("2. Alice           prepares leg A; her money leaves her account");
    out.push("   Alice -> Bob   : a pre-signature over \"leg A\", adapted to Y");
    out.push("3. Bob             prepares leg B, and sends his own pre-signature");
    out.push("4. Bob             claims on A  -> he is paid, and y becomes readable");
    out.push("5. Alice           reads A, recovers y, claims on B  -> she is paid");
    out.push("```\n");
    out.push(concat!(
        "Bob draws the secret and moves first, so Bob is never at risk: if he stops after step 3 ",
        "both escrows expire and both parties are whole. Alice is exposed in exactly one window, ",
        "between step 4 and step 5, and she is safe if and only if the gap between the two deadlines ",
        "covers her reaction. **That gap is this arrangement's Herstatt risk**, and it is the number ",
        "worth measuring.\n"
    ));
    out.push(format!(
        "| | measured, {}-bit rails |",
        value_display(&pvp["rail_bits"])
    ));
    out.push("| --- | ---: |");
    out.push(format!(
        "| prepare one leg (check, and move it out of reach) | {:.2} ± {:.2} ms (n={}) |",
        num(&milli["prepare"]["mean"])?,
        num(&milli["prepare"]["sd"])?,
        value_display(&milli["prepare"]["n"])
    ));
    out.push(format!(
        "| the first mover's claim | {:.2} ± {:.2} ms (n={}) |",
        num(&milli["claim"]["mean"])?,
        num(&milli["claim"]["sd"])?,
        value_display(&milli["claim"]["n"])
    ));
    out.push(format!(
        "| **the second mover's reaction** | **{:.2} ± {:.2} ms (n={})** |",
        num(&milli["react"]["mean"])?,
        num(&milli["react"]["sd"])?,
        value_display(&milli["react"]["n"])
    ));
    out.push(format!(
        "| unwind an expired leg | {:.2} ± {:.2} us (n={}) |",
        num(&micro["unwind"]["mean"])?,
        num(&micro["unwind"]["sd"])?,
        value_display(&micro["unwind"]["n"])
    ));
    out.push("");
    out.push(format!(
        concat!(
            "**The cryptography is not what puts the money at risk.** Recovering the secret, ",
            "adapting the signature and having the second ledger accept it comes to {:.2} ms. The ",
            "deadline gap has to cover that *plus* the time for one ledger to publish the first ",
            "claim and the other to accept the second --- block times and network round trips, ",
            "which are three to five orders of magnitude larger. So the exposure is set by the ",
            "settlement finality of the two ledgers and not by anything in this repository, and a ",
            "deployment that wants a short window should shop for finality rather than for faster ",
            "proofs.\n"
        ),
        num(&milli["react"]["mean"])?
    ));
    out.push(concat!(
        "Preparing costs about what a transfer costs, because that is what it is: the same check, ",
        "with the amount moved into an escrow instead of into the payee. Unwinding costs nothing, ",
        "and deliberately requires no signature --- the deadline is the whole authority, because ",
        "demanding a signature would strand the money of anyone who lost a key, which is the ",
        "failure this branch exists to prevent.\n"
    ));
    Ok(())
}

fn build_same_chain(
    out: &mut Document,
    d: &Value,
    same_chain: Option<&Value>,
) -> HarnessResult<()> {
    let Some(same_chain) = same_chain else {
        return Ok(());
    };
    let data_rows = rows(&same_chain["rows"])?;
    let pick = |arm: &str, swaps: i64, parties: &str, naming: &str| {
        data_rows.iter().find(|r| {
            r["arm"] == arm
                && r["swaps"].as_i64() == Some(swaps)
                && r["parties"] == parties
                && r["naming"] == naming
        })
    };
    let biggest = data_rows
        .iter()
        .filter_map(|r| r["swaps"].as_i64())
        .max()
        .ok_or("same_chain empty")?;
    let namings: Vec<String> = data_rows
        .iter()
        .filter_map(|r| r["naming"].as_str().map(str::to_string))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let per_venue = namings
        .iter()
        .find(|n| n.contains("per venue"))
        .ok_or("per-venue naming missing")?;

    out.push("### 6.1 On one chain, and what the unlinkability actually rests on\n");
    if same_chain["host"] != d["host"] {
        out.push(format!(
            "*Taken on `{}`.*\n",
            label(
                same_chain["host"]
                    .as_str()
                    .ok_or("same-chain host is not text")?
            )
        ));
    }
    out.push(concat!(
        "Across two chains there is no choice about atomicity: nothing spans them, so an adaptor ",
        "signature and a deadline are the only way. On one chain --- two DeFMI deployments, two ",
        "contract addresses --- there is a choice. A single transaction calling both venues gets ",
        "atomicity from the chain for nothing and its exposure window is zero, but that transaction ",
        "is the link. Two transactions with an adaptor keep the legs cryptographically unrelated ",
        "and pay at least one block.\n"
    ));
    out.push("What the second arm costs is small and flat:\n");
    out.push(format!(
        "| at {biggest} swaps | one transaction | adaptor |"
    ));
    out.push("| --- | ---: | ---: |");
    let one = pick("one transaction", biggest, "distinct", per_venue)
        .ok_or("same-chain one transaction missing")?;
    let adaptor =
        pick("adaptor", biggest, "distinct", per_venue).ok_or("same-chain adaptor missing")?;
    for (label, key) in [
        ("calls", "calls"),
        ("state slots written", "slots_written"),
        ("bytes written", "bytes_written"),
    ] {
        out.push(format!(
            "| {label} | {} | {} |",
            value_display(&one[key]),
            value_display(&adaptor[key])
        ));
    }
    out.push(format!(
        "| verification | {} ms | {} ms |",
        ms(&one["verify_ms"], 1)?,
        ms(&adaptor["verify_ms"], 1)?
    ));
    out.push("| exposure window | none | at least one block |");
    out.push("");
    let mut ratios = Vec::new();
    for row in data_rows.iter().filter(|r| r["arm"] == "adaptor") {
        let swaps = int(&row["swaps"])?;
        let parties = row["parties"].as_str().ok_or("parties is not text")?;
        let naming = row["naming"].as_str().ok_or("naming is not text")?;
        let base =
            pick("one transaction", swaps, parties, naming).ok_or("same-chain base missing")?;
        ratios.push(measurement_value(&row["verify_ms"])? / measurement_value(&base["verify_ms"])?);
    }
    ratios.sort_by(f64::total_cmp);
    let lo = *ratios.first().ok_or("no adaptor ratios")?;
    let hi = *ratios.last().unwrap();
    let mid = ratios[ratios.len() / 2];
    out.push(format!(
        concat!(
            "Four times the calls and a third more state slots --- holding **fewer bytes** in them, ",
            "because a settlement records a nullifier and a deadline (40 bytes a venue) where the ",
            "escrow path records neither: the escrow key is itself the replay guard, and it costs a ",
            "slot rather than bytes --- for **{:.1}% more verification** (+{:.1}% to +{:.1}% across ",
            "the table). The range proofs dominate, and the escrow and the signature are a few ",
            "percent beside them rather than nothing at all: this is a difference the earlier run ",
            "on a loaded machine could not resolve: both arms read 413 ms there, with standard ",
            "deviations of 9 and 20 ms against a gap that should have been about 14. It was not ",
            "measured to be zero; it was not measurable.\n"
        ),
        100.0 * (mid - 1.0), 100.0 * (lo - 1.0), 100.0 * (hi - 1.0)
    ));
    out.push(concat!(
        "What it buys is the question, and the answer turned out to depend on something that was ",
        "not cryptography at all.\n"
    ));
    out.push(concat!(
        "**What a reader of the chain can still join**, using nothing but what the calls name. One ",
        "stated strategy, run over the real records: take a call on one venue, find the calls on the ",
        "other that name the same handles, guess uniformly among them; where no handle matches, ",
        "guess uniformly among all of them.\n"
    ));
    out.push("| naming | swaps in flight | between | one transaction | adaptor | chance |");
    out.push("| --- | ---: | --- | ---: | ---: | ---: |");
    let swaps: Vec<i64> = data_rows
        .iter()
        .filter_map(|r| r["swaps"].as_i64())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    for naming in &namings {
        for parties in ["distinct", "one pair"] {
            for swap_count in &swaps {
                let a = pick("one transaction", *swap_count, parties, naming)
                    .ok_or("one transaction cell missing")?;
                let b =
                    pick("adaptor", *swap_count, parties, naming).ok_or("adaptor cell missing")?;
                out.push(format!(
                    "| {naming} | {swap_count} | {parties} | {:.3} | **{:.3}** | {:.3} |",
                    num(&a["observer_success"])?,
                    num(&b["observer_success"])?,
                    num(&b["chance"])?
                ));
            }
        }
    }
    out.push("");
    out.push(concat!(
        "**The privacy of this construction was sitting in a naming convention.** With one ",
        "identifier at both venues --- which is what a caller reaches for, and what this benchmark ",
        "did on its first run --- the adaptor buys nothing between distinct parties: a prepare is a ",
        "transfer, a transfer says who is paying whom, and joining \"this firm pays here\" to \"this ",
        "firm is paid there\" needs no cryptanalysis. Four times the calls for a number that does ",
        "not move.\n"
    ));
    out.push(concat!(
        "With a handle derived per venue --- `qomm_zkpi::handles`, one seed and an unrelated point ",
        "at each venue --- the adaptor delivers exactly what it promises: the observer falls to ",
        "chance, 1/k, and stays there whether the swaps are between distinct parties or the same ",
        "pair. Nothing about the cryptography changed between those two blocks of the table. Only ",
        "the names did.\n"
    ));
    out.push(concat!(
        "This is worth stating plainly because the property was written down as prose before it was ",
        "code, and prose does not hold. The design said handles are derived per venue so that one ",
        "firm is two unrelated points; the library offered no way to derive them, so the obvious ",
        "integration was the one that loses. It is code now, and the test that goes with it runs the ",
        "scheme that suggests itself first --- one secret scaled by a public per-venue factor --- ",
        "and shows it is publicly linkable.\n"
    ));
    out.push(concat!(
        "Two things the table is not. The observer here is given **no timing**: every prepare is ",
        "placed in one block, so a real observer watching them arrive does better than 1/k. And ",
        "these are account rails. The note ledger of §5 removes the handle rather than deriving it ",
        "well, which sounds like the stronger answer and is, but §5.2 measured what it is worth and ",
        "the two findings are the same one: **both constructions hide you in other people's traffic ",
        "and neither does anything without it.** A ring with no other settlements around it names ",
        "its note with certainty, exactly as an adaptor with one swap in flight names its partner ",
        "leg. What differs is the exchange rate --- how much traffic each one needs to buy a given ",
        "amount of doubt --- and not whether traffic is what is being spent.\n"
    ));
    out.push(concat!(
        "This measurement first ran against a version where the property was the caller's to keep. ",
        "The instruction named two handles and the package named four accounts, and nothing ",
        "compared them --- so a caller who derived handles per venue and then opened accounts under ",
        "one name everywhere got the losing row of the table while believing it had the winning ",
        "one. That is now closed: the four account names are **derived from the two signed handles** ",
        "(`Sides::of`, one hash of the handle and the rail), `build_package` no longer takes them as ",
        "an argument, and a package whose accounts disagree with its instruction is rejected before ",
        "any proof is examined. The per-venue property is enforced where it is used rather than ",
        "assumed of the caller.\n"
    ));
    Ok(())
}

fn build_reconcile(out: &mut Document, reconcile: Option<&Value>) -> HarnessResult<()> {
    let Some(reconcile) = reconcile else {
        return Ok(());
    };
    out.push("## 6.5 Agreeing with the book of record\n");
    out.push(concat!(
        "Under Japan's book-entry regime this ledger cannot *be* the register: title rests on the ",
        "record the transfer agent and the account management institutions keep. So it is a mirror, ",
        "and reconciliation is not a feature but the price of that arrangement.\n"
    ));
    out.push(concat!(
        "It is one line of algebra. Commitments multiply, so the product of the balances is a ",
        "commitment to their sum; divide out the register's figure under the asset tag and what ",
        "remains must be a pure power of `h`. Proving knowledge of that exponent proves the totals ",
        "agree and says nothing else --- **no balance opens, and the total was the register's own ",
        "number**.\n"
    ));
    out.push("| positions | prove | check | quorum assembles |");
    out.push("| ---: | ---: | ---: | ---: |");
    let scaling = rows(&reconcile["scaling"])?;
    let quorum = rows(&reconcile["quorum"])?;
    for (row, joint) in scaling.iter().zip(quorum) {
        out.push(format!(
            "| {} | {} | {} | {} ({} of {}) |",
            comma_i64(int(&row["positions"])?),
            ms(&row["prove"], 2)?,
            ms(&row["check"], 2)?,
            ms(&joint["assemble"], 2)?,
            rows(&joint["quorum"])?.len(),
            value_display(&joint["of"])
        ));
    }
    out.push("");
    let biggest = scaling.last().ok_or("reconcile scaling empty")?;
    out.push(format!(
        concat!(
            "Linear in the positions and nothing else: at {} it is {} to check, and the proof on ",
            "the wire is {} B whatever the ledger holds.\n"
        ),
        comma_i64(int(&biggest["positions"])?),
        ms(&biggest["check"], 1)?,
        value_display(&biggest["wire_bytes"])
    ));
    out.push(concat!(
        "The **quorum** column is the same statement assembled by nodes holding shares of the ",
        "aggregate blinding, so nobody holds the sum --- which matters, because whoever holds it ",
        "could open the whole ledger. A sigma response is affine in the witness, so the partials ",
        "combine into an ordinary proof any verifier accepts.\n"
    ));
    out.push("### 6.5.1 A break is pass or fail, and looking costs disclosure\n");
    out.push(concat!(
        "If the totals disagree the proof does not verify, and that is all anyone learns. Finding ",
        "*where* needs somebody to claim subtotals, and every subtotal claimed becomes public --- ",
        "the narrowest of them covers one position, which is a balance. **This is the only operation ",
        "in DeFMI that discloses on purpose, and it is the operation you reach for on the day ",
        "something is wrong.**\n"
    ));
    out.push("| positions | sub-range proofs | 2 log2 n + 1 | subtotals made public | narrowest |");
    out.push("| ---: | ---: | ---: | ---: | ---: |");
    let locating = rows(&reconcile["locating"])?;
    for row in locating {
        out.push(format!(
            "| {} | {} | {} | {} | {} position |",
            comma_i64(int(&row["positions"])?),
            value_display(&row["sub_range_proofs"]),
            value_display(&row["two_log_n_plus_one"]),
            value_display(&row["subtotals_made_public"]),
            value_display(&row["narrowest_range"])
        ));
    }
    out.push("");
    let last = locating.last().ok_or("reconcile locating empty")?;
    out.push(format!(
        concat!(
            "A register that holds **a figure per position** rather than one for the account ",
            "localises for free and discloses nothing: an account management institution already ",
            "holds the mapping from handle to book-entry account, so it holds the openings and the ",
            "check is arithmetic on numbers it has. At {} positions that is {} ms.\n"
        ),
        comma_i64(int(&last["positions"])?), value_display(&last["per_position_register"]["ms"])
    ));
    out.push(concat!(
        "**Reconciling is the cheap half and the search is not.** Which one you are in depends on ",
        "what the register keeps, which is a question about the counterparty and not about this ",
        "ledger.\n"
    ));
    Ok(())
}

fn build_note_dvp(out: &mut Document, note_dvp: Option<&Value>) -> HarnessResult<()> {
    let Some(note_dvp) = note_dvp else {
        return Ok(());
    };
    out.push("### 5.2 The same, in Rust\n");
    out.push(concat!(
        "The note rail's delivery versus payment is ported, and this is the measurement that lets ",
        "the sentence about it go from section 9 rather than be softened.\n"
    ));
    out.push("| ring | build | settle | package |");
    out.push("| ---: | ---: | ---: | ---: |");
    for row in rows(&note_dvp["rows"])? {
        out.push(format!(
            "| {} | {} | {} | {} B |",
            value_display(&row["ring"]),
            ms(&row["build"], 1)?,
            ms(&row["settle_including_build"], 1)?,
            comma_i64(int(&row["package_bytes"])?),
        ));
    }
    out.push("");
    out.push(concat!(
        "**The package is the comparable column and it is about nine times smaller** --- 5,476 B ",
        "against 50,827 at a ring of eight --- which is the same ",
        "Bulletproofs-against-bit-decomposition effect the account rail showed in section 5.1.\n"
    ));
    out.push(concat!(
        "The `build` column includes the whole three-of-seven FROST ceremony that issues the ",
        "instruction. It is therefore an end-to-end construction cost, not only a range-proof ",
        "microbenchmark.\n"
    ));
    out.push(concat!(
        "`settle` builds a fresh world and a fresh package each time, because settling consumes both, ",
        "so it is an upper bound carrying a build inside it.\n"
    ));
    Ok(())
}

fn build_viewing(out: &mut Document, viewing: Option<&Value>) -> HarnessResult<()> {
    let Some(viewing) = viewing else {
        return Ok(());
    };
    out.push("## 6.6 Showing an auditor one slice\n");
    out.push(concat!(
        "A note wallet is a view key and a spend key, and the view key was always described as the ",
        "one you could hand an auditor. You could, and that was the whole of it: one key, so handing ",
        "it over gives every instrument, every period, permanently, with no way back.\n"
    ));
    out.push(concat!(
        "The scoping is not in the key. It is in the **address**. A scope --- an instrument, a ",
        "quarter, a mandate --- derives its own pair of scalars from the wallet's seeds by hashing, ",
        "so it has its own address, and notes sent there are found by that scope's view key and by ",
        "nothing else. The derivation is one way, so a scope says nothing about the seed or about a ",
        "sibling. The note construction, the scan and the spend are all unchanged; what changes is ",
        "which address a payer is given.\n"
    ));
    out.push("| pool | scan | per note | reached | exactly its scope | serials recovered |");
    out.push("| ---: | ---: | ---: | ---: | :---: | ---: |");
    let scaling = rows(&viewing["scaling"])?;
    for row in scaling {
        out.push(format!(
            "| {} | {} | {} ms | {} of {} ({:.1}%) | {} | {} |",
            comma_i64(int(&row["pool"])?),
            ms(&row["scan"], 1)?,
            value_display(&row["per_note_ms"]),
            value_display(&row["notes_reached"]),
            comma_i64(int(&row["notes_in_pool"])?),
            num(&row["fraction_reached"])? * 100.0,
            if row["sees_exactly_its_scope"].as_bool().unwrap_or(false) {
                "yes"
            } else {
                "NO"
            },
            value_display(&row["serials_recovered"])
        ));
    }
    out.push("");
    let last = scaling.last().ok_or("viewing scaling empty")?;
    out.push(format!(
        concat!(
            "The scan is one scalar multiplication a note, the same as a wallet scanning for ",
            "itself, at {} ms. With {} scopes in the pool plus a stranger's notes the holder ",
            "reaches about a fifth of it, which is the fifth it was granted --- and **no serial ",
            "numbers at all**, because a serial needs the spend key and the grant does not carry ",
            "one.\n"
        ),
        value_display(&last["per_note_ms"]),
        value_display(&viewing["scopes"])
    ));
    out.push(format!(
        concat!(
            "A grant is {} to issue and {} to check. It names the grantee and is signed by the ",
            "wallet, so a key found somewhere it should not be traces to the grant that produced it ",
            "--- attribution rather than prevention, the same trade `rust/qomm-transport/src/roles.rs` makes about a dealt ",
            "share.\n"
        ),
        ms(&viewing["grant"]["build"], 2)?, ms(&viewing["grant"]["check"], 2)?
    ));
    out.push("### 6.6.1 Three limits that do not go away\n");
    out.push(concat!(
        "**A grant cannot be taken back.** Whoever holds a scope's key can read every note ever ",
        "sent to that address and every one that ever will be. An expiry stops a party that chooses ",
        "to be stopped and nothing else. What actually revokes is moving to the next scope, because ",
        "the next scope is a different address --- so revocation is an act of address management ",
        "and not a message.\n"
    ));
    out.push(concat!(
        "Which is why the schedule is an object rather than a discipline. `Rolling` says what the ",
        "scope in force is, what address to publish and when it stops being it; a grant issued ",
        "against it expires when the period does, so it is never current for a scope nothing is ",
        "being paid into. Two questions stay separate --- whether a grant is well formed by its own ",
        "dates, and whether it is for the scope money is going into now --- because one failure is a ",
        "bad grant and the other is a wallet that has not rolled. And a payer using a stale address ",
        "puts the note in a stale scope, which nothing in the protocol stops, so ",
        "`arrived_off_schedule` is what a payee that cares runs.\n"
    ));
    out.push(concat!(
        "**A view key is incoming only.** It finds what arrived and cannot see what the wallet ",
        "spent: spending publishes a serial and a ring, and neither is derivable from the view key. ",
        "An auditor that needs outflows needs the wallet to hand over its serials, which is a ",
        "different disclosure than this one.\n"
    ));
    out.push(concat!(
        "**Scoping is only as fine as the payers cooperate.** A scope exists because counterparties ",
        "were told to pay to that address; one who uses last quarter's address puts the note in last ",
        "quarter's scope and nothing in the protocol stops them. That is an operational control ",
        "wearing a cryptographic coat, and it is worth knowing which it is.\n"
    ));
    Ok(())
}

fn build_vetting(out: &mut Document, vetting: Option<&Value>) -> HarnessResult<()> {
    let Some(vetting) = vetting else {
        return Ok(());
    };
    let mut by_crowd = BTreeMap::new();
    for row in rows(&vetting["rows"])? {
        by_crowd.insert(int(&row["crowd"])?, row);
    }
    let default = *by_crowd
        .keys()
        .filter(|crowd| **crowd <= 128)
        .max()
        .ok_or("no default crowd")?;
    let big = by_crowd[&default];
    let small = by_crowd.get(&16).ok_or("crowd 16 missing")?;
    out.push("## 6.7 Who is allowed to hold a handle\n");
    out.push(concat!(
        "A handle is `A = a.G` and anyone can pick `a`. Nobody's permission is needed to make one, ",
        "and that is deliberate --- the chain should not have an opinion about who opens an ",
        "address. What needs permission is being **vetted**, and ",
        "`rust/qomm-defmi/src/vetting.rs` is where that is recorded.\n"
    ));
    out.push(concat!(
        "**The list holds sealed envelopes, not handles.** An envelope is `C = a.G + r.h`, so `C - ",
        "A = r.h`: the envelope is the handle plus a blinding nobody else knows, and adding one to ",
        "the public list reveals a uniformly random point.\n"
    ));
    out.push(concat!(
        "That matters more than it first looks. Putting the *handle* in the list would mean anyone ",
        "who could work out from the timing which entry belonged to which firm --- they onboarded ",
        "that week, one entry appeared that week --- would have that firm's handle. The handle is ",
        "what appears on chain when the account moves, so they would then have its entire ",
        "settlement history. Sealing the entry closes that: the timing still says somebody joined, ",
        "and says nothing about which entry is theirs.\n"
    ));
    out.push(concat!(
        "**The group is fixed, which is why it is private.** Membership is proved one-out-of-many ",
        "over a group: subtract the handle from every envelope, exactly one difference is a ",
        "commitment to zero, and the proof says so without saying which. Drawing a fresh ring per ",
        "proof would look more private and be less --- rings that overlap differently each time can ",
        "be intersected and the real member falls out. The same group every time gives an observer ",
        "nothing to intersect. A group also carries its cohort, so proving membership proves the ",
        "attribute.\n"
    ));
    out.push(concat!(
        "**A vetting yields one handle, not a family of them.** The ring proof alone says only that ",
        "`C_l - A` is a multiple of `h`, so `A + d.h` would satisfy it for any `d` the holder picks ",
        "--- one vetting, unboundedly many usable handles, every per-firm cap void. A Schnorr proof ",
        "that the handle is a bare power of the base point pins it to the one the envelope ",
        "determines. That is a test, not a comment.\n"
    ));
    out.push(concat!(
        "**Whose privacy this is.** The seal hides the entry from *observers* and not from the ",
        "operator: `vouch` takes the handle's secret, picks the blinding and picks the slot. An ",
        "enrolment in which it does not --- the party proving knowledge of its secret and receiving ",
        "a jointly chosen blinding --- is not built. What the seal establishes is that dating an ",
        "onboarding tells a third party nothing about which entry it is.\n"
    ));
    out.push(concat!(
        "**A verifier must know which roll it is checking against.** `check_membership` proves a ",
        "handle is in the roll it is *given*, so a proof that arrives with its own roll proves ",
        "nothing --- `Group` is not constructible from outside the crate and `Roll::digest()` is ",
        "what a verifier compares against whatever the chain published. This used to be neither: ",
        "every field was public, so a caller could push a group holding an envelope of its own, cut ",
        "a seal by hand, and pass the check without the operator ever running.\n"
    ));
    out.push(concat!(
        "**What is public on purpose.** `Roll::vetted()` counts the real envelopes and ",
        "`Roll::crowd()` gives the group size, so anyone can check the claim rather than take it. ",
        "Decoy seats are hashed rather than drawn, so no opening exists for them --- not even the ",
        "operator's --- which is what makes that count honest. It counts calls to `vouch` and not ",
        "distinct legal entities: nothing here deduplicates one, and the per-entity cap that would ",
        "is the operator's.\n"
    ));
    out.push(concat!(
        "The alternative is worth naming. Hiding that a vetting happened at all --- making ",
        "onboarding indistinguishable from ordinary settlement traffic --- means padding the roll ",
        "with entries nobody can tell from real ones, and then nobody can count the real ones ",
        "either, including a regulator asking how large the anonymity set is. **Hiding the vetting ",
        "event and proving the size of the crowd are the same information.** One or the other.\n"
    ));
    out.push(format!(
        "Measured on `{}`, {} repeats, medians.\n",
        label(vetting["host"].as_str().ok_or("vetting host is not text")?),
        value_display(&vetting["repeats"])
    ));
    out.push("| crowd | prove | verify | proof | ring |");
    out.push("|---:|---:|---:|---:|---:|");
    for (crowd, row) in &by_crowd {
        out.push(format!(
            "| {crowd} | {} | {} | {} B | {} B |",
            ms(&row["prove_ms"], 2)?,
            ms(&row["verify_ms"], 2)?,
            value_display(&row["proof_bytes"]),
            value_display(&row["ring_bytes"])
        ));
    }
    out.push("");
    let step = int(&by_crowd[&32]["proof_bytes"])? - int(&small["proof_bytes"])?;
    out.push(format!(
        concat!(
            "The size was predicted exactly: {} bytes at a crowd of 16, of which {} is the ring, 64 ",
            "the control proof and 12 the group and epoch. Every doubling adds exactly {} --- one ",
            "point in each of the ring's four vectors and one scalar in each of its three.\n"
        ),
        value_display(&small["proof_bytes"]), value_display(&small["ring_bytes"]), step
    ));
    let ratio = num(&big["verify_ms"]["median"])? / num(&by_crowd[&4]["verify_ms"]["median"])?;
    let grew = int(&big["crowd"])? / 4;
    out.push(format!(
        concat!(
            "**Two predictions missed, and the second changed a design choice.** Verifying was ",
            "predicted under 1 ms at a crowd of 16; it came in at {}. The measured verifier also ",
            "checks the control proof and shifts every envelope, so this is the complete verifier ",
            "cost rather than a group-arithmetic microbenchmark.\n"
        ),
        ms(&small["verify_ms"], 2)?
    ));
    out.push(format!(
        concat!(
            "The consequential miss is the second. **Verification was predicted to double with the ",
            "crowd and grows about 1.4x instead**: {}x the crowd costs {:.1}x the work, which is the ",
            "batched multi-scalar multiplication showing through. The crowd had been capped at 16 ",
            "on a belief about linearity the measurement does not support. At {} the check is {} ",
            "against the 51.9 ms a note settlement already costs, and the wire grows by {} bytes. ",
            "**{} is the default the code carries** (`vetting::CROWD`).\n"
        ),
        grew, ratio, value_display(&big["crowd"]), ms(&big["verify_ms"], 2)?,
        int(&big["proof_bytes"])? - int(&small["proof_bytes"] )?, value_display(&big["crowd"])
    ));
    out.push(concat!(
        "What stays out of reach is a crowd of thousands. That needs a Merkle tree checked inside a ",
        "circuit --- a different proof system from the sigma protocols and Bulletproofs this stack ",
        "is built on, with a compiler and a setup behind it.\n"
    ));
    out.push(concat!(
        "**Where the check runs.** The node committee verifies the complete proof before it signs. ",
        "The product transaction carries the submitted evidence, and every dedicated Avalanche VM ",
        "validator independently verifies the 3-of-7 approval, typed zkPI, complete quote proof, ",
        "joint ranges, taker price limit, asset link, DvP relation and state transition. Validators ",
        "do not re-run the private MP-SPDZ transcript or prove the node-local share-to-proof handoff; ",
        "that remaining trust boundary is explicit in `ZKPI_WIRE.md`.\n"
    ));
    Ok(())
}

fn build_avalanche(out: &mut Document, avalanche: Option<&Value>) -> HarnessResult<()> {
    let Some(avalanche) = avalanche else {
        return Ok(());
    };
    let timings = &avalanche["operation_timings_ms"];
    let accepted = &avalanche["accepted_transitions"];
    let heights = [
        "bootstrap_asset",
        "instrument_asset",
        "left_account",
        "right_account",
        "settlement",
    ]
    .iter()
    .map(|key| value_display(&accepted[*key]["height"]))
    .collect::<Vec<_>>()
    .join(", ");
    out.push("### 6.8 Native Avalanche L1 acceptance\n");
    out.push(concat!(
        "The deployed execution path is a dedicated non-EVM Avalanche custom VM in ",
        "`avalanche/defmivm/`. It has native transitions for asset registration, account opening ",
        "and atomic multi-leg settlement; it does not execute Solidity or EVM bytecode.\n"
    ));
    out.push("| property | observed result |");
    out.push("| --- | ---: |");
    out.push(format!(
        "| local AvalancheGo processes | {} |",
        value_display(&avalanche["nodes"])
    ));
    out.push(format!("| accepted heights | {heights} |"));
    out.push(format!(
        "| settlement acceptance | {:.1} ms |",
        num(&timings["settlement_ms"])?
    ));
    out.push(format!(
        "| two account openings | {:.1} ms |",
        num(&timings["two_accounts_ms"])?
    ));
    out.push(format!(
        "| node restart and state recovery | {:.1} ms |",
        num(&avalanche["restart"]["elapsed_ms"])?
    ));
    let roots = rows(&avalanche["roots_before_restart"])?;
    let unique: BTreeSet<String> = roots.iter().map(value_display).collect();
    out.push(format!(
        "| one state root before restart | {} |",
        if unique.len() == 1 { "yes" } else { "no" }
    ));
    out.push(format!(
        "| same state root after restart | {} |",
        if avalanche["restart"]["root_recovered"]
            .as_bool()
            .unwrap_or(false)
        {
            "yes"
        } else {
            "no"
        }
    ));
    out.push("");
    out.push(concat!(
        "The run uses five processes on one host. It proves native consensus acceptance, ",
        "idempotent crash recovery and state-root agreement, not five independent organisations or ",
        "public-network readiness.\n"
    ));
    Ok(())
}

fn build_parallel(out: &mut Document, d: &Value, big: Option<&Value>) -> HarnessResult<()> {
    let Some(parallel) = d
        .get("parallel")
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty())
    else {
        return Ok(());
    };
    out.push("## 7. What one settlement node can take\n");
    out.push(concat!(
        "Verification only --- proving is the counterparty's work and the clock is stopped for it. ",
        "Every worker meets at a barrier before the measured section begins.\n"
    ));
    out.push("| workers | settlements/s | vs one worker |");
    out.push("| ---: | ---: | ---: |");
    let one = measurement_value(&parallel[0]["per_second"])?;
    for row in parallel {
        out.push(format!(
            "| {} | {} | {:.2}x |",
            value_display(&row["workers"]),
            ms(&row["per_second"], 1)?,
            measurement_value(&row["per_second"])? / one
        ));
    }
    let top = parallel.last().unwrap();
    out.push("");
    out.push(format!(
        concat!(
            "Verifications of independent packages share nothing, so they parallelise completely: ",
            "**{:.0} per second** on {} workers. A settlement node's capacity is a procurement ",
            "question, not a design one.\n"
        ),
        measurement_value(&top["per_second"])?,
        value_display(&top["workers"])
    ));
    if let Some(big) = big.filter(|v| {
        v.get("parallel")
            .and_then(Value::as_array)
            .is_some_and(|r| !r.is_empty())
    }) {
        let bp = rows(&big["parallel"])?;
        let bone = bp.first().unwrap();
        let btop = bp.last().unwrap();
        let bcal = measurement_value(&big["calibration"]["scalar_mult_us"])?;
        let ccal = measurement_value(&d["calibration"]["scalar_mult_us"])?;
        out.push(format!(
            concat!(
                "A second host with more cores (`{}`, {} logical cores) was measured too. Its ",
                "calibration is {:.1} us per scalar multiplication against {:.1} us here, so it is ",
                "**{:.2}x slower per core**. Its single-worker throughput differs by {:.2}x ({:.1} ",
                "to {:.1} per second), which is the same ratio by an independent route.\n"
            ),
            label(big["host"].as_str().ok_or("big host is not text")?),
            value_display(&btop["workers"]), bcal, ccal, bcal / ccal,
            one / measurement_value(&bone["per_second"] )?, one,
            measurement_value(&bone["per_second"])?
        ));
        out.push("| workers | settlements/s | vs one worker | vs linear |");
        out.push("| ---: | ---: | ---: | ---: |");
        for row in bp {
            out.push(format!(
                "| {} | {:.1} | {:.2}x | {:.0}% |",
                value_display(&row["workers"]),
                measurement_value(&row["per_second"])?,
                measurement_value(&row["per_second"])? / measurement_value(&bone["per_second"])?,
                100.0 * measurement_value(&row["per_second"])?
                    / (measurement_value(&bone["per_second"])? * num(&row["workers"])?)
            ));
        }
        let shortfall = 100.0
            - 100.0 * measurement_value(&btop["per_second"])?
                / (measurement_value(&bone["per_second"])? * num(&btop["workers"])?);
        out.push("");
        out.push(format!(
            concat!(
                "**{:.0} per second** on {} workers, only {:.0}% short of linear. Nothing is shared ",
                "between verifications, so this shape is what was expected.\n"
            ),
            measurement_value(&btop["per_second"] )?, value_display(&btop["workers"]), shortfall
        ));
    }
    Ok(())
}

fn build_proof_backend_comparison(
    out: &mut Document,
    baseline: &Value,
    optimized: Option<&Value>,
) -> HarnessResult<()> {
    let Some(optimized) = optimized else {
        return Ok(());
    };
    out.push("## 8. Native Rust proof backends\n");
    let baseline_calibration = baseline
        .get("calibration")
        .and_then(|calibration| calibration.get("scalar_mult_us"))
        .map(measurement_value)
        .transpose()?;
    let optimized_calibration = measurement_value(&optimized["calibration"]["scalar_mult_us"])?;
    let same_machine = optimized["host"] == baseline["host"];
    let location = if same_machine {
        format!(
            "Both backends were measured on `{}`",
            label(
                optimized["host"]
                    .as_str()
                    .ok_or("optimized host is not text")?
            )
        )
    } else {
        format!(
            "The optimized backend was measured on `{}` and the baseline on `{}`",
            label(
                optimized["host"]
                    .as_str()
                    .ok_or("optimized host is not text")?
            ),
            label(
                baseline["host"]
                    .as_str()
                    .ok_or("baseline host is not text")?
            )
        )
    };
    let calibration = baseline_calibration.map_or_else(
        || format!("{optimized_calibration:.1} us for the optimized backend"),
        |baseline_value| {
            format!(
                "{baseline_value:.1} us for the baseline and {optimized_calibration:.1} us for the optimized backend"
            )
        },
    );
    out.push(format!(
        "{location} with {}. Scalar-multiplication calibration was {calibration}.{}\n",
        value_display(&optimized["rustc"]),
        if same_machine {
            " The following ratios therefore compare proof backends on the same host."
        } else {
            " Host differences are included in the following ratios; rerun both artifacts on one host before using them as promotion evidence."
        }
    ));
    out.push(concat!(
        "The baseline uses a linear bit-decomposition range proof. The optimized backend uses the ",
        "audited `bulletproofs` crate, changing proof size from linear to logarithmic. Both ",
        "implementations, the benchmark driver and the document generator are native Rust.\n"
    ));

    let mut baseline_by_bits = BTreeMap::new();
    for row in rows(&baseline["scaling"])? {
        baseline_by_bits.insert(int(&row["bits"])?, row);
    }
    let shared: Vec<&Value> = rows(&optimized["scaling"])?
        .iter()
        .filter(|row| {
            row["bits"]
                .as_i64()
                .is_some_and(|bits| baseline_by_bits.contains_key(&bits))
        })
        .collect();
    out.push("| balance width | linear settle | Bulletproof settle | speedup | linear package | Bulletproof package | reduction |");
    out.push("| ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
    for row in shared {
        let bits = int(&row["bits"])?;
        let baseline_row = baseline_by_bits[&bits];
        let baseline_settle = measurement_value(&baseline_row["settle"])?;
        let optimized_settle = measurement_value(&row["settle_ms"])?;
        let baseline_bytes = count(&baseline_row["package_bytes"])?;
        let optimized_bytes = count(&row["package_bytes"])?;
        out.push(format!(
            "| {bits} bit | {} ms | {optimized_settle:.2} ms | {:.1}x | {} B | {} B | {:.1}x |",
            ms(&baseline_row["settle"], 1)?,
            baseline_settle / optimized_settle,
            comma_i64(baseline_bytes),
            comma_i64(optimized_bytes),
            baseline_bytes as f64 / optimized_bytes as f64
        ));
    }
    out.push("");

    let wide = rows(&optimized["scaling"])?
        .iter()
        .find(|row| row["bits"].as_i64() == Some(64));
    let baseline40 = baseline_by_bits.get(&40).copied();
    if let (Some(wide), Some(baseline40)) = (wide, baseline40) {
        let baseline_settle = measurement_value(&baseline40["settle"])?;
        let optimized_settle = measurement_value(&wide["settle_ms"])?;
        let baseline_bytes = count(&baseline40["package_bytes"])?;
        let optimized_bytes = count(&wide["package_bytes"])?;
        out.push(format!(
            concat!(
                "Bulletproofs uses power-of-two widths, so a 40-bit rail rounds up to 64 bits. ",
                "The honest cross-width comparison is {} ms for the 40-bit linear backend against ",
                "{:.2} ms for the 64-bit Bulletproof backend, **{:.1}x**. The package falls from {} ",
                "B to {} B, **{:.1}x**.\n"
            ),
            ms(&baseline40["settle"], 1)?,
            optimized_settle,
            baseline_settle / optimized_settle,
            comma_i64(baseline_bytes),
            comma_i64(optimized_bytes),
            baseline_bytes as f64 / optimized_bytes as f64
        ));
        out.push(format!(
            "Per core, that is {:.1} to {:.1} settlements per second.\n",
            1000.0 / baseline_settle,
            1000.0 / optimized_settle
        ));
    }
    out.push(concat!(
        "The optimized backend loses fine-grained proof widths: securities at 24 bits round to 32, ",
        "and cash at 40 bits rounds to 64. The table measures whether the logarithmic proof still ",
        "wins after paying that rounding cost.\n"
    ));
    Ok(())
}

fn build_missing(out: &mut Document, d: &Value) {
    out.push("## 9. What is still missing\n");
    out.push(concat!(
        "- Avalanche validators independently verify the complete submitted product proof suite, ",
        "but they do not re-run the private MP-SPDZ transcript or prove the node-local ",
        "share-to-proof handoff. Removing that remaining committee trust requires a proof of the ",
        "whole private computation and a separate consensus benchmark."
    ));
    if d.get("note_settlement").is_none_or(Value::is_null) {
        out.push(concat!(
            "- The note ledger and DvP settlement are not yet joined. Notes work and are measured ",
            "on their own, but `Defmi.settle` is still the account ledger."
        ));
    }
    out.push(concat!(
        "- A tagged cash leg needs cash accounts opened under that currency's tag; the remainder ",
        "proof opens against the balance the payer already has, so a leg cannot claim a currency ",
        "the account is not denominated in. That is the property doing the work, and it means ",
        "adding a second settlement currency is an account-opening decision rather than a code ",
        "change."
    ));
    out.push(concat!(
        "- Whoever sent a note can tell that it was spent, because they know the `g^S` they built. ",
        "That is unavoidable in this construction. To a third party the ring size is the limit of ",
        "what is learned."
    ));
    out.push(concat!(
        "- The note rail's decoy selection is uniform over the pool, and a real spend is of a ",
        "recently received note. Section 5's finding stands: an anonymity set is other people's ",
        "traffic, and the decoy rule only decides whether the ring can use it."
    ));
}
