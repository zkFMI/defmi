//! Print this machine's published label, the one every artifact records.
//!
//! The Makefile needs it before any measurement runs, and it used to get it by
//! starting a Python interpreter and importing `scripts.hosts`. That was the
//! last thing in the build that needed Python for a value rather than for work.

fn main() {
    println!("{}", qomm_measure::hosts::this_host());
}
