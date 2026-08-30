//! One party of one run, reporting what it cost rather than printing a log.
//!
//! This stands where `./malicious-shamir-party.x` stood. It takes the same
//! arguments, runs the same machine, and differs only in what comes out: the
//! engine's own counters instead of a page of text that a regular expression
//! then has to survive.
//!
//! The output is deliberately flat --- one record per line, the name last so it
//! may contain spaces --- because the caller is another program in this crate
//! and a format that needs no parser needs no parser to be right. The JSON the
//! artifacts are made of is assembled once, by the orchestrator.
//!
//! It runs with the working directory set to the MP-SPDZ checkout, for the same
//! reason the party binary does: `Programs/` and `Player-Data/` are resolved
//! relative to it.

use qomm_mpc::Protocol;

fn main() {
    let mut args = std::env::args();
    let me = args.next().unwrap_or_else(|| "qomm-party".into());
    let rest: Vec<String> = args.collect();

    let (protocol, party_args) = match rest.split_first() {
        Some((first, tail)) => match Protocol::parse(first) {
            Some(protocol) => (protocol, tail),
            None => usage(&me),
        },
        None => usage(&me),
    };

    // argv[0] is not a party argument, but MP-SPDZ's option parser expects the
    // slot to be there, so the program name is passed back in.
    let mut argv: Vec<&str> = vec![&me];
    argv.extend(party_args.iter().map(String::as_str));

    match qomm_mpc::run(protocol, &argv) {
        Ok(run) => {
            println!(
                "QOMM total {} {} {} {} {:.6}",
                run.rounds, run.raw_rounds, run.sent, run.payload, run.seconds
            );
            for channel in &run.channels {
                println!(
                    "QOMM channel {} {} {}",
                    channel.rounds, channel.bytes, channel.name
                );
            }
        }
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(1);
        }
    }
}

fn usage(me: &str) -> ! {
    eprintln!(
        "usage: {me} <malicious-shamir|semi-honest-shamir> \
               <party> <program> -N <n> -T <t> -ip <hosts>"
    );
    std::process::exit(2);
}
