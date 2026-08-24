//! Reading what a register actually sends, and what a reconciliation run says
//! to do about a break.
//!
//! The parsing tests are about refusing rather than about accepting. A file
//! that ran out halfway is the failure that matters here: parsed leniently it
//! reconciles to a smaller total and looks like a break in the ledger, and the
//! operations team spends the morning looking in the wrong place.

use std::collections::BTreeMap;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use qomm_defmi::register::*;
use qomm_zk::pedersen::{asset_tag, Pedersen};
use rand::rngs::OsRng;

const FILE: &str = "\
# register, account, asset, as-of
JASDEC,customer-omnibus-001,JP3633400001,2026-08-22
p0,1200
p1,4500
p2,0
end,3,5700
";

fn key() -> Pedersen {
    Pedersen::new(b"qomm:defmi:v1").with_value_generator(asset_tag(7))
}

fn ledger_for(quantities: &[u64]) -> (Vec<RistrettoPoint>, Vec<Scalar>) {
    let mut rng = OsRng;
    let k = key();
    let blindings: Vec<Scalar> = quantities
        .iter()
        .map(|_| Scalar::random(&mut rng))
        .collect();
    let commitments = quantities
        .iter()
        .zip(&blindings)
        .map(|(q, r)| k.commit_u64(*q, r))
        .collect();
    (commitments, blindings)
}

// --- the file -------------------------------------------------------------

#[test]
fn a_position_file_reads_as_it_was_sent() {
    let statement = parse(FILE).unwrap();
    assert_eq!(statement.register, "JASDEC");
    assert_eq!(statement.account, "customer-omnibus-001");
    assert_eq!(statement.asset, "JP3633400001");
    assert_eq!(statement.as_of, "2026-08-22");
    assert_eq!(statement.handles(), vec!["p0", "p1", "p2"]);
    assert_eq!(statement.quantities(), vec![1200, 4500, 0]);
    assert_eq!(statement.total(), 5700);
}

#[test]
fn a_line_with_no_quantity_is_a_refusal_and_not_a_zero() {
    // The failure this exists for: a truncated download reconciles to a smaller
    // total and looks like a break in the ledger.
    let truncated = FILE.replace("p2,0", "p2");
    let why = parse(&truncated).unwrap_err();
    assert!(why.to_string().contains("means zero says zero"), "{why}");
}

/// A file that lost whole rows off the end is refused, not reconciled.
///
/// The mid-row case above was handled; this one was not, and it is the likelier
/// of the two --- a file is written a line at a time, so an interrupted write
/// ends at a row boundary far more often than inside a row. Parsed leniently it
/// is a perfectly well-formed statement of a smaller holding, and reconciliation
/// reports a break against a ledger that is correct.
///
/// Nothing in the content can distinguish it, so the file has to say how long
/// it is. The last line does, and losing rows loses the last line with them.
#[test]
fn a_file_that_lost_its_last_rows_is_refused_rather_than_reconciled() {
    let lines: Vec<&str> = FILE.lines().collect();
    for dropped in 1..=3 {
        let short = lines[..lines.len() - dropped].join("\n") + "\n";
        let why = parse(&short)
            .err()
            .unwrap_or_else(|| panic!("a file missing its last {dropped} line(s) parsed"));
        assert!(why.to_string().contains("end"), "dropped {dropped}: {why}");
    }
}

/// The count and the total both have to agree, or the line is not a check.
#[test]
fn an_end_line_that_disagrees_with_the_rows_is_refused() {
    let wrong_count = FILE.replace("end,3,5700", "end,2,5700");
    let why = parse(&wrong_count).unwrap_err();
    assert!(
        why.to_string()
            .contains("declares 2 row(s) and the file has 3"),
        "{why}"
    );

    let wrong_total = FILE.replace("end,3,5700", "end,3,5699");
    let why = parse(&wrong_total).unwrap_err();
    assert!(why.to_string().contains("5700"), "{why}");
}

/// A row after the end line is not a row.
#[test]
fn nothing_follows_the_end_line() {
    let after = FILE.to_string() + "p3,999\n";
    assert!(parse(&after).is_err());
}

#[test]
fn a_quantity_that_is_not_a_number_is_refused() {
    assert!(parse(&FILE.replace("4500", "4,500")).is_err());
    assert!(parse(&FILE.replace("4500", "n/a")).is_err());
}

#[test]
fn an_empty_file_is_not_a_statement_of_zero_holdings() {
    assert_eq!(parse("").unwrap_err(), FileError::Empty);
    assert_eq!(parse("# only a comment\n").unwrap_err(), FileError::Empty);
    let header_only = FILE.lines().take(2).collect::<Vec<_>>().join("\n");
    assert_eq!(parse(&header_only).unwrap_err(), FileError::Empty);
}

#[test]
fn a_header_that_is_not_four_fields_is_refused() {
    let short = FILE.replace(
        "JASDEC,customer-omnibus-001,JP3633400001,2026-08-22",
        "JASDEC,customer-omnibus-001",
    );
    assert!(matches!(parse(&short).unwrap_err(), FileError::Header(_)));
}

// --- the run --------------------------------------------------------------

#[test]
fn a_ledger_that_agrees_says_so_and_opens_nothing() {
    let mut rng = OsRng;
    let register = FileRegister::read(FILE).unwrap();
    let (commitments, blindings) = ledger_for(&register.statement.quantities());
    let report = run(&key(), &register, &commitments, &blindings, None, &mut rng);
    assert!(report.agrees, "{}", report.reason);
    assert!(
        report.text().contains("no balance was opened")
            || report.text().contains("No balance was opened")
    );
}

#[test]
fn a_signed_statement_is_checked_against_the_registrar() {
    let mut rng = OsRng;
    let registrar = SigningKey::generate(&mut rng);
    let statement = parse(FILE).unwrap();
    let signed = statement.signed_by(&registrar);
    let mut register = FileRegister::read(FILE).unwrap();
    register.signature = signed.signature;
    let (commitments, blindings) = ledger_for(&statement.quantities());
    let report = run(
        &key(),
        &register,
        &commitments,
        &blindings,
        Some(&registrar.verifying_key()),
        &mut rng,
    );
    assert!(report.agrees, "{}", report.reason);

    let other = SigningKey::generate(&mut rng);
    let report = run(
        &key(),
        &register,
        &commitments,
        &blindings,
        Some(&other.verifying_key()),
        &mut rng,
    );
    assert!(!report.agrees);
}

#[test]
fn a_register_that_sends_positions_names_the_ones_that_break() {
    let mut rng = OsRng;
    let register = FileRegister::read(FILE).unwrap();
    let mut held = register.statement.quantities();
    held[1] += 7; // the ledger holds more than the register says
    let (commitments, blindings) = ledger_for(&held);
    let report = run(&key(), &register, &commitments, &blindings, None, &mut rng);
    assert!(!report.agrees);
    assert_eq!(report.broken, vec![("p1".to_string(), 4500)]);
    assert!(report.text().contains("p1"));
}

#[test]
fn a_register_that_sends_only_a_total_cannot_say_where() {
    let mut rng = OsRng;
    let register = TotalOnly {
        statement: parse(FILE).unwrap(),
    };
    let mut held = register.statement.quantities();
    held[0] += 3;
    let (commitments, blindings) = ledger_for(&held);
    let report = run(&key(), &register, &commitments, &blindings, None, &mut rng);
    assert!(!report.agrees);
    assert!(report.broken.is_empty());
    assert!(report.text().contains("nothing here that can say where"));
}

#[test]
fn a_different_number_of_positions_is_a_break_before_any_arithmetic() {
    let mut rng = OsRng;
    let register = FileRegister::read(FILE).unwrap();
    let (commitments, blindings) = ledger_for(&[1200, 4500]);
    let report = run(&key(), &register, &commitments, &blindings, None, &mut rng);
    assert!(!report.agrees);
    assert!(report
        .reason
        .contains("3 position(s) and the ledger offered 2"));
}

#[test]
fn a_total_is_blind_to_reordering_and_the_positions_are_not() {
    // The finding this test was written to assert the opposite of. Swapping two
    // balances leaves the sum where it was, so a register that sends a total
    // reconciles clean --- and one that sends positions does not. That is a
    // larger difference between the two kinds of register than "where a break
    // is", and it is why the positions are checked whenever they are sent.
    let mut rng = OsRng;
    let mut held = parse(FILE).unwrap().quantities();
    held.swap(0, 1);
    let (commitments, blindings) = ledger_for(&held);

    let total_only = TotalOnly {
        statement: parse(FILE).unwrap(),
    };
    let report = run(
        &key(),
        &total_only,
        &commitments,
        &blindings,
        None,
        &mut rng,
    );
    assert!(report.agrees, "a sum cannot see a reordering");

    let with_positions = FileRegister::read(FILE).unwrap();
    let report = run(
        &key(),
        &with_positions,
        &commitments,
        &blindings,
        None,
        &mut rng,
    );
    assert!(!report.agrees);
    assert_eq!(report.broken.len(), 2);
    assert!(
        report.reason.contains("a sum cannot see"),
        "{}",
        report.reason
    );
}

#[test]
fn two_errors_that_cancel_are_caught_by_the_positions_and_not_the_total() {
    let mut rng = OsRng;
    let mut held = parse(FILE).unwrap().quantities();
    held[0] += 50;
    held[1] -= 50;
    let (commitments, blindings) = ledger_for(&held);
    let register = FileRegister::read(FILE).unwrap();
    let report = run(&key(), &register, &commitments, &blindings, None, &mut rng);
    assert!(!report.agrees);
    assert_eq!(report.broken.len(), 2);
}

#[test]
fn a_break_can_be_localised_when_the_register_answers_sub_ranges() {
    let mut rng = OsRng;
    let quantities: Vec<u64> = (0..16).map(|i| 100 + i as u64).collect();
    let mut held = quantities.clone();
    held[5] += 9;
    let (commitments, blindings) = ledger_for(&held);
    let mut subtotals = BTreeMap::new();
    for low in 0..=16 {
        for high in low..=16 {
            subtotals.insert((low, high), quantities[low..high].iter().sum());
        }
    }
    let search = localise(
        &key(),
        &commitments,
        &blindings,
        &subtotals,
        quantities.iter().sum(),
        &mut rng,
    )
    .unwrap();
    assert_eq!(search.found, vec![5]);
    assert_eq!(
        search.narrowest(),
        1,
        "and a sub-total over one position is a balance"
    );
}

#[test]
fn a_register_that_cannot_answer_a_sub_range_says_so_rather_than_guessing() {
    let mut rng = OsRng;
    let quantities: Vec<u64> = (0..8).map(|i| 100 + i as u64).collect();
    let mut held = quantities.clone();
    held[3] += 1;
    let (commitments, blindings) = ledger_for(&held);
    let mut subtotals = BTreeMap::new();
    subtotals.insert((0usize, 8usize), quantities.iter().sum::<u64>());
    let why = localise(
        &key(),
        &commitments,
        &blindings,
        &subtotals,
        quantities.iter().sum(),
        &mut rng,
    )
    .unwrap_err();
    assert!(why.contains("stays pass-or-fail"), "{why}");
}

/// A register cannot make a break disappear by splitting it unevenly.
///
/// The bisection asks the register what each half should total and checks each
/// half against its commitments. It did not check that the two halves add up to
/// the half they came from. So a register that answers with subtotals matching
/// what the ledger actually holds --- rather than what it claimed the account
/// holds --- has both children pass while the parent fails, and the search
/// returns having found nothing.
///
/// That is worse than the pass-or-fail it replaced: pass-or-fail at least says
/// there is a break. This said the break was nowhere.
#[test]
fn a_break_cannot_be_hidden_by_halves_that_do_not_add_up() {
    let mut rng = OsRng;
    let held: Vec<u64> = vec![10, 20, 30, 41]; // what the ledger holds: 101
    let claimed_total: u64 = 100; // what the register attested
    let (commitments, blindings) = ledger_for(&held);

    // Every sub-range answered with what the ledger holds, so each half checks
    // out on its own. Only the top disagrees, and only with the attested total.
    let mut subtotals = BTreeMap::new();
    for low in 0..=4usize {
        for high in low..=4usize {
            subtotals.insert((low, high), held[low..high].iter().sum::<u64>());
        }
    }

    let outcome = localise(
        &key(),
        &commitments,
        &blindings,
        &subtotals,
        claimed_total,
        &mut rng,
    );
    match outcome {
        Err(why) => assert!(
            why.contains("add up") || why.contains("come to"),
            "refused, but not for the right reason: {why}"
        ),
        Ok(search) => panic!(
            "the search reported found={:?} after the top failed and both \
             halves passed --- a break that is nowhere",
            search.found
        ),
    }
}
