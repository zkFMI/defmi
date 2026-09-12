#!/usr/bin/env python3
"""Remote-only sealed rough outcome launcher. Build is a launch preflight, not acceptance."""
import hashlib, json, os, pathlib, subprocess, sys, time
root = pathlib.Path(__file__).resolve().parents[2]
parent = root.parent
out = pathlib.Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=False)
sha = lambda b: hashlib.sha256(b).hexdigest()
write = lambda p,v: p.write_text(json.dumps(v, indent=2)+"\n")
native = len(sys.argv)>2 and sys.argv[2]=="--native"
contract_path = root / ("research/asset-privacy/native-contract.json" if native else "research/asset-privacy/contract.json")
contract = contract_path.read_bytes()
contract_id = json.loads(contract)["id"]
sources = {}
for repo, sub in [(root,"rust"),(parent / "zkfmi-crypto","src"),(parent / "zkfmi-crypto","research/cosnark-trial/src")]:
    for path in sorted((repo / sub).rglob("*")):
        if path.is_file() and "target" not in path.parts:
            sources[str(path.relative_to(parent))] = sha(path.read_bytes())
for path in [parent / "zkfmi-crypto/Cargo.toml", parent / "zkfmi-crypto/research/cosnark-trial/Cargo.toml", pathlib.Path(__file__), contract_path, root / "research/asset-privacy/run-native.sh", root / "research/asset-privacy/check-disclosure.py"]:
    sources[str(path.relative_to(parent))] = sha(path.read_bytes())
manifest = {"milestone":"RUN_ROUGH_END_TO_END_AND_OBSERVE_FINAL_METRIC", "closed":True,
 "contract_id":contract_id, "contract_sha256":sha(contract),
 "bottleneck":"Selected asset ID was public across native note and settlement records",
 "causal_hypothesis":"Blinded asset identities and bound same-value conversion preserve the whole canonical lifecycle",
 "single_change":"Native RPC reads and five-validator transport" if native else "Unsigned full-wrapper verification before signing; deterministic rejection checks", "baseline":"rough-03 final metric 1; source manifest 62ca1c8af41c62753d48bf0aede7d225b23d677595270bd3b9790af448cdaa96",
 "prediction":1, "most_likely_prediction_error":"Cross-generator normalization or recipient ciphertext metadata mismatch",
 "population":json.loads(contract)["population"], "rejection_rule":"Any execution error, balance mismatch or hard gate failure",
 "promotion_rule":"smoke_only; never accepted for production", "sources":sources}
write(out/"manifest.json", manifest)
(out/"contract.json").write_bytes(contract)
image = "pqc-full-integration:rust-1.97.1-mpspdz-9d809599-openssl-3.5.5-pqc-auth-v2"
base = ["docker","run","--rm","--init","--network","host","--mount",f"type=bind,src={parent},dst=/workspace",
 "--mount","type=volume,src=defmi-cargo-registry,dst=/usr/local/cargo/registry",
 "--mount","type=volume,src=defmi-cargo-git,dst=/usr/local/cargo/git",
 "--mount","type=volume,src=defmi-test-target,dst=/var/cache/defmi/target",
 "--env","CARGO_TARGET_DIR=/var/cache/defmi/target","--workdir","/workspace/defmi/rust"]
started=time.time()
with (out/"build.log").open("w") as log:
    build=subprocess.run(base+[image]+(["env","-u","MP_SPDZ_ROOT"] if native else [])+["cargo","build","--locked","--release","-j16","-p","defmi-avalanche-vm","--example","confidential-assets-acceptance"]+(["--bin","qomm-avalanche-vm"] if native else []),stdout=log,stderr=subprocess.STDOUT)
if build.returncode:
    write(out/"preflight.json",{"status":"blocked","reason":"build_failed","exit_code":build.returncode})
    sys.exit(build.returncode)
for name, digest in sources.items():
    if sha((parent/name).read_bytes()) != digest: raise RuntimeError("Sealed source changed: "+name)
write(out/"preflight.json",{"status":"ready","source_hashes_verified":True})
launch={"manifest_sha256":sha((out/"manifest.json").read_bytes()),"contract_sha256":sha(contract),"started_at":time.time()}
with (out/"launch.json").open("x") as f: json.dump(launch,f)
with (out/"execution.log").open("w") as log:
    command = ["bash","/workspace/defmi/research/asset-privacy/run-native.sh",f"/workspace/{out.relative_to(parent)}"] if native else ["/var/cache/defmi/target/release/examples/confidential-assets-acceptance"]
    result=subprocess.run(base+["--env",f"DEFMI_ASSET_PRIVACY_RUN_DIR=/workspace/{out.relative_to(parent)}",image]+command,stdout=log,stderr=subprocess.STDOUT)
if not (out/"outcome.json").exists():
    write(out/"outcome.json",{"verdict":"rejected","final_metric":0,"reason":"execution_failed_before_final_readback","exit_code":result.returncode,"manifest_sha256":launch["manifest_sha256"]})
outcome=json.loads((out/"outcome.json").read_text())
receipt={"contract_id":manifest["contract_id"],"contract_sha256":sha(contract),"manifest_sha256":launch["manifest_sha256"],"outcome_sha256":sha((out/"outcome.json").read_bytes()),"verdict":outcome["verdict"],"elapsed_seconds":time.time()-started,"exit_code":result.returncode}
write(out/"receipt.json",receipt)
with (root/"research/asset-privacy/ledger.jsonl").open("a") as f:f.write(json.dumps(receipt)+"\n")
print(json.dumps(outcome),flush=True)
sys.exit(result.returncode)
