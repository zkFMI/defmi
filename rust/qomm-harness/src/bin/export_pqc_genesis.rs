//! Regenerate the explicitly PUBLIC local-development governance trust anchor.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keys = qomm_defmi::governance::public_development_keys()?;
    let config = serde_json::json!({
        "timestamp": 0,
        "committee": {
            "epoch": 1, "threshold": 3,
            "members": keys.iter().map(|(node, key)| serde_json::json!({
                "nodeID": node, "key": key.verifying_key(),
            })).collect::<Vec<_>>(),
        },
    });
    println!("{}", serde_json::to_string_pretty(&config)?);
    Ok(())
}
