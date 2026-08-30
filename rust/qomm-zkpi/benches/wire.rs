//! Native zkPI encoding and verification benchmark used by the Avalanche VM.

use qomm_measure::{hosts, time_us};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::wire::{decode, encode};
use qomm_zkpi::{wire_vectors, Bounds, Venue};

fn rustc_version() -> String {
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn main() {
    let (instruction, package) = wire_vectors::sample_with_quorum();
    let bytes = encode(&instruction);
    let mut venue = Venue::new(Pedersen::new(b"qomm:defmi:v1"), &Bounds::default(), package);
    venue.domain = qomm_zkpi::DEFAULT_DOMAIN.to_vec();
    let now = instruction.deadline - 1;

    let encoding = time_us(200, || {
        encode(&instruction);
    });
    let decoding = time_us(200, || {
        decode(&bytes).expect("sample instruction decodes");
    });
    let verifying = time_us(50, || {
        venue
            .verify(&instruction, now)
            .expect("sample instruction verifies");
    });
    let end_to_end = time_us(50, || {
        let decoded = decode(&bytes).expect("sample instruction decodes");
        venue
            .verify(&decoded, now)
            .expect("decoded sample instruction verifies");
    });

    println!("zkPI native verification\n");
    println!("  wire size        {} bytes", bytes.len());
    println!("  encode           {:.1} us", encoding.median);
    println!("  decode           {:.1} us", decoding.median);
    println!("  verify           {:.1} us", verifying.median);
    println!("  decode + verify  {:.1} us", end_to_end.median);

    if let Ok(path) = std::env::var("QOMM_BENCH_JSON") {
        let json = format!(
            concat!(
                "{{\n",
                "  \"host\": \"{}\",\n",
                "  \"rustc\": \"{}\",\n",
                "  \"wire_bytes\": {},\n",
                "  \"encode_us\": {},\n",
                "  \"decode_us\": {},\n",
                "  \"verify_us\": {},\n",
                "  \"decode_and_verify_us\": {},\n",
                "  \"deployment_target\": \"dedicated Avalanche L1 Rust VM\"\n",
                "}}\n"
            ),
            std::env::var("QOMM_HOST_LABEL").unwrap_or_else(|_| hosts::this_host()),
            rustc_version(),
            bytes.len(),
            encoding.json(),
            decoding.json(),
            verifying.json(),
            end_to_end.json(),
        );
        std::fs::write(&path, json).expect("could not write the measurement");
        println!("\nwrote {path}");
    }
}
