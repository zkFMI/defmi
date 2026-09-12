#!/usr/bin/env bash
set -euo pipefail
umask 077
out="$1"
runner=/workspace/native-bin/avalanche-network-runner
avalanchego=/workspace/native-bin/avalanchego
vm=/var/cache/defmi/target/release/qomm-avalanche-vm
example=/var/cache/defmi/target/release/examples/confidential-assets-acceptance
plugin_dir="$out/plugins"
mkdir -p "$plugin_dir" "$out/network-logs" "$out/network-data"
vm_id="$($vm vmid)"
install -m 0755 "$vm" "$plugin_dir/$vm_id"
runner_pid=""
example_pid=""
cleanup() {
  find "$out" -maxdepth 1 -type f -exec chmod a+r -- {} +
  chmod a+rx "$out/network-logs"
  find "$out/network-logs" -type f -exec chmod a+r -- {} +
  if [[ -n "$runner_pid" ]]; then
    "$runner" control stop --endpoint="$endpoint" --request-timeout=30s >>"$out/network-logs/stop.log" 2>&1 || true
    kill -TERM "$runner_pid" >/dev/null 2>&1 || true
    wait "$runner_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$example_pid" ]] && kill -0 "$example_pid" >/dev/null 2>&1; then
    kill -TERM "$example_pid" >/dev/null 2>&1 || true
    wait "$example_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM
read -r runner_port gateway_port < <(python3 - <<'PY'
import socket
s=[socket.socket() for _ in range(2)]
for sock in s:sock.bind(("127.0.0.1",0))
print(*(sock.getsockname()[1] for sock in s))
PY
)
endpoint="localhost:$runner_port"
DEFMI_ASSET_PRIVACY_NATIVE=1 DEFMI_ASSET_PRIVACY_RUN_DIR="$out" "$example" >"$out/native-client.log" 2>&1 &
example_pid=$!
chmod a+r "$out/native-client.log"
for _ in {1..300}; do
  [[ -f "$out/genesis.bin" ]] && break
  kill -0 "$example_pid" || { cat "$out/native-client.log"; exit 1; }
  sleep 0.1
done
[[ -f "$out/genesis.bin" ]]
"$runner" server --port=":$runner_port" --grpc-gateway-port=":$gateway_port" --log-dir="$out/network-logs" >"$out/network-logs/server.log" 2>&1 &
runner_pid=$!
for _ in {1..100}; do
  "$runner" control rpc_version --endpoint="$endpoint" >/dev/null 2>&1 && break
  sleep 0.1
done
spec="[{\"vm_name\":\"defmivm\",\"genesis\":\"$out/genesis.bin\"}]"
"$runner" control start --endpoint="$endpoint" --request-timeout=5m --avalanchego-path="$avalanchego" \
  --plugin-dir="$plugin_dir" --root-data-dir="$out/network-data" --network-id=1337 --num-nodes=5 \
  --dynamic-ports --reassign-ports-if-used --blockchain-specs="$spec" >"$out/network-logs/start.log" 2>&1
"$runner" control wait-for-healthy --endpoint="$endpoint" --request-timeout=5m >"$out/network-logs/healthy.log" 2>&1
"$runner" control list-blockchains --endpoint="$endpoint" >"$out/network-logs/chains.log" 2>&1
"$runner" control uris --endpoint="$endpoint" >"$out/network-logs/uris.log" 2>&1
python3 - "$out" <<'PY'
import hashlib,json,pathlib,re,sys
out=pathlib.Path(sys.argv[1])
clean=lambda p:re.sub(r"\x1b\[[0-9;]*m","",p.read_text())
chain=re.search(r"Blockchain ID: (\S+)",clean(out/"network-logs/chains.log")).group(1)
uris=re.search(r"URIs: \[([^\]]+)\]",clean(out/"network-logs/uris.log")).group(1).split()
record={"chain_id":chain,"node_uris":uris,"binaries":{name:hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest() for name,path in {
"vm":"/var/cache/defmi/target/release/qomm-avalanche-vm","avalanchego":"/workspace/native-bin/avalanchego","runner":"/workspace/native-bin/avalanche-network-runner"}.items()}}
p=out/"network.json.tmp";p.write_text(json.dumps(record,indent=2)+"\n");p.replace(out/"network.json")
PY
for _ in {1..1200}; do
  [[ -f "$out/ready-for-restart.json" ]] && break
  kill -0 "$example_pid" || { cat "$out/native-client.log"; wait "$example_pid"; exit 1; }
  sleep 0.2
done
[[ -f "$out/ready-for-restart.json" ]]
"$runner" control restart-node node3 --endpoint="$endpoint" --request-timeout=3m --plugin-dir="$plugin_dir" >"$out/network-logs/restart.log" 2>&1
"$runner" control wait-for-healthy --endpoint="$endpoint" --request-timeout=3m >"$out/network-logs/restarted-healthy.log" 2>&1
: >"$out/restart-complete"
wait "$example_pid"
example_pid=""
cat "$out/native-client.log"
