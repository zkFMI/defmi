#!/usr/bin/env bash
set -euo pipefail

# One-command acceptance run for the dedicated, non-EVM DeFMI Avalanche L1.
# The two external binaries are resolved from explicit variables first and PATH
# second; they are never downloaded or silently substituted by this script.

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
qomm_root="$(CDPATH= cd -- "$root/../.." && pwd)"
runner="${AVALANCHE_NETWORK_RUNNER:-$(command -v avalanche-network-runner || true)}"
avalanchego="${AVALANCHEGO_PATH:-$(command -v avalanchego || true)}"
acceptance_bin="${QOMM_AVALANCHE_ACCEPTANCE_BIN:-$qomm_root/rust/target/release/run_avalanche_l1_acceptance}"
rust_vm="${QOMM_AVALANCHE_VM_BIN:-$qomm_root/rust/target/release/qomm-avalanche-vm}"
runner_port="${QOMM_ANR_PORT:-18080}"
gateway_port="${QOMM_ANR_GATEWAY_PORT:-18081}"
endpoint="localhost:${runner_port}"
out="${QOMM_AVALANCHE_ARTIFACT:-$qomm_root/artifacts/avalanche_l1_acceptance.json}"

if [[ -z "$runner" || ! -x "$runner" ]]; then
  echo "AVALANCHE_NETWORK_RUNNER must name an executable avalanche-network-runner" >&2
  exit 2
fi
if [[ -z "$avalanchego" || ! -x "$avalanchego" ]]; then
  echo "AVALANCHEGO_PATH must name an executable AvalancheGo binary" >&2
  exit 2
fi
if [[ ! -x "$acceptance_bin" ]]; then
  echo "QOMM_AVALANCHE_ACCEPTANCE_BIN must name the built Rust acceptance binary" >&2
  exit 2
fi
if [[ ! -x "$rust_vm" ]]; then
  echo "QOMM_AVALANCHE_VM_BIN must name the built QOMM Rust VM binary" >&2
  exit 2
fi

run_root="$(mktemp -d "${TMPDIR:-/tmp}/qomm-avalanche-l1.XXXXXX")"
plugin_dir="$run_root/plugins"
data_dir="$run_root/data"
logs_dir="$run_root/logs"
genesis="$run_root/genesis.bin"
projection="$run_root/projection.sqlite3"
mkdir -p "$plugin_dir" "$data_dir" "$logs_dir"

runner_pid=""
cleanup() {
  if [[ -n "$runner_pid" ]]; then
    "$runner" control stop --endpoint="$endpoint" --request-timeout=3m >/dev/null 2>&1 || true
    kill -TERM "$runner_pid" >/dev/null 2>&1 || true
    wait "$runner_pid" 2>/dev/null || true
  fi
  if [[ "${QOMM_KEEP_AVALANCHE_RUN:-0}" != "1" ]]; then
    rm -rf -- "$run_root"
  else
    echo "kept local Avalanche run at $run_root" >&2
  fi
}
trap cleanup EXIT INT TERM

vm_id="$("$rust_vm" vmid)"
install -m 0755 "$rust_vm" "$plugin_dir/$vm_id"
"$rust_vm" genesis --config "$root/config/test-genesis.json" --out "$genesis"

"$runner" server --port=":$runner_port" --grpc-gateway-port=":$gateway_port" \
  --log-dir="$logs_dir" >"$logs_dir/server.log" 2>&1 &
runner_pid="$!"

ready=0
for _ in {1..100}; do
  if "$runner" control rpc_version --endpoint="$endpoint" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ "$ready" != "1" ]]; then
  echo "avalanche-network-runner did not become ready; see $logs_dir/server.log" >&2
  exit 3
fi

spec="[{\"vm_name\":\"defmivm\",\"genesis\":\"$genesis\"}]"
"$runner" control start --endpoint="$endpoint" --request-timeout=5m \
  --avalanchego-path="$avalanchego" --plugin-dir="$plugin_dir" \
  --root-data-dir="$data_dir" --network-id=1337 --num-nodes=5 \
  --reassign-ports-if-used --blockchain-specs="$spec"
"$runner" control wait-for-healthy --endpoint="$endpoint" --request-timeout=5m

strip_ansi() {
  sed $'s/\033\\[[0-9;]*m//g'
}
chain_id="$({ "$runner" control list-blockchains --endpoint="$endpoint"; } 2>&1 \
  | strip_ansi | sed -n 's/.*Blockchain ID: //p' | head -n 1)"
uri_line="$({ "$runner" control uris --endpoint="$endpoint"; } 2>&1 \
  | strip_ansi | sed -n 's/.*URIs: \[\(.*\)\]/\1/p' | head -n 1)"
if [[ -z "$chain_id" || -z "$uri_line" ]]; then
  echo "could not discover the local chain ID or node URIs" >&2
  exit 4
fi

node_args=()
for uri in $uri_line; do
  node_args+=(--node-uri "$uri")
done

cd "$qomm_root"
"$acceptance_bin" \
  --chain-id "$chain_id" "${node_args[@]}" \
  --projection "$projection" --out "$out" \
  --runner "$runner" --avalanchego "$avalanchego" \
  --runner-endpoint "$endpoint" \
  --plugin-dir "$plugin_dir" --restart-node node3

echo "wrote $out"
