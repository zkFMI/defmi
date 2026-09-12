#!/usr/bin/env python3
"""Inspect generated public records, allowing only definitions and full cohorts.
This is a serialization check, not a cryptographic or metadata-anonymity proof.
"""
import base64, hashlib, json, pathlib, sys
run = pathlib.Path(sys.argv[1])
assets = set(json.loads((run/"canonical-state.json").read_text())["assets"])
raw = {bytes.fromhex(a) for a in assets}
observed, unexpected = [], []

def allowed(path):
    return (path[:1] == ["assets"]
        or path[:2] == ["params", "asset"]
        or "permittedAssetIds" in path or "permittedAssetIDs" in path
        or len(path) >= 2 and path[-2:] == ["registry", "assets"])

def record(file, path, form, ok):
    entry={"file":file,"path":"/".join(map(str,path)),"encoding":form,"allowed_public_definition_or_cohort":ok}
    observed.append(entry)
    if not ok: unexpected.append(entry)

def walk(file, value, path):
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in assets: record(file,path+[key],"map_key",path==["assets"])
            walk(file,item,path+[key])
    elif isinstance(value,list):
        if len(value)==32 and all(type(x)==int and 0<=x<256 for x in value) and bytes(value) in raw:
            record(file,path,"byte_array",allowed(path[:-1]) or allowed(path))
        else:
            for i,item in enumerate(value): walk(file,item,path+[i])
    elif isinstance(value,str):
        if value.lower() in assets:
            record(file,path,"hex",allowed(path) or allowed(path[:-1]))
            return
        for encoding, decoder in [("hex_embedded",bytes.fromhex),("base64_embedded",lambda v:base64.b64decode(v,validate=True))]:
            try: decoded=decoder(value)
            except (ValueError,TypeError): continue
            if any(a in decoded for a in raw): record(file,path,encoding,False)

files=[run/"canonical-state.json",*sorted(run.glob("[0-9]*-transaction.json"))]
for file in files: walk(file.name,json.loads(file.read_text()),[])
state=json.loads((run/"canonical-state.json").read_text())
identities=state["confidential"]["identities"]
report={"scope":"generated canonical public state and accepted transaction JSON; exact IDs and common binary encodings",
 "limitations":["No claim of information-theoretic secrecy from this byte scan", "Public market, venue, issuer and cohort metadata may identify an asset"],
 "record_files":len(files),"confidential_identities":len(identities),"notes":len(state["notes"]),"claims":len(state["noteClaims"]),
 "unexpected_selected_asset_id_occurrences":unexpected,"permitted_public_occurrences":observed,
 "artifact_hashes":{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in files}}
(run/"disclosure-check.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps({"record_files":len(files),"identities":len(identities),"notes":len(state["notes"]),"claims":len(state["noteClaims"]),"unexpected":unexpected}))
sys.exit(bool(unexpected))
