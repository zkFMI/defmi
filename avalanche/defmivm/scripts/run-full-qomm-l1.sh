#!/usr/bin/env bash
set -euo pipefail

# End-to-end acceptance for the non-EVM QOMM/DeFMI Avalanche L1:
# signed pre-trade authority -> account-free delegated note reserves -> real
# 7-party MP-SPDZ -> threshold zkPI finalization -> one atomic multi-RFQ L1
# settlement with no post-quote Maker/Taker signature.

umask 077
root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
qomm_root="$(CDPATH= cd -- "$root/../.." && pwd)"
venue_root="${QOMM_VENUE_ROOT:-$(dirname "$qomm_root")/qomm}"
committee_root="${ZKPI_ROOT:-$(dirname "$qomm_root")/zkpi}"
runner="${AVALANCHE_NETWORK_RUNNER:-$(command -v avalanche-network-runner || true)}"
avalanchego="${AVALANCHEGO_PATH:-$(command -v avalanchego || true)}"
rust_vm_override="${QOMM_AVALANCHE_VM_BIN:-}"
rust_vm="${rust_vm_override:-$qomm_root/rust/target/release/qomm-avalanche-vm}"
mp_spdz_root="${MP_SPDZ_ROOT:-}"
runner_port="${QOMM_ANR_PORT:-18090}"
gateway_port="${QOMM_ANR_GATEWAY_PORT:-18091}"
runner_endpoint="localhost:${runner_port}"
out="${QOMM_AVALANCHE_FULL_ARTIFACT:-$qomm_root/artifacts/avalanche_qomm_full_acceptance.json}"

if [[ -z "$runner" || ! -x "$runner" ]]; then
  echo "AVALANCHE_NETWORK_RUNNER must name an executable avalanche-network-runner" >&2
  exit 2
fi
if [[ -z "$avalanchego" || ! -x "$avalanchego" ]]; then
  echo "AVALANCHEGO_PATH must name an executable AvalancheGo binary" >&2
  exit 2
fi
if [[ -z "$mp_spdz_root" || ! -d "$mp_spdz_root" ]]; then
  echo "MP_SPDZ_ROOT must name the stock MP-SPDZ checkout" >&2
  exit 2
fi
if [[ -n "$rust_vm_override" && ! -x "$rust_vm" ]]; then
  echo "QOMM_AVALANCHE_VM_BIN must name the built QOMM Rust VM binary" >&2
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to assemble the acceptance receipt" >&2
  exit 2
fi

run_root="$(mktemp -d "${TMPDIR:-/tmp}/qomm-avalanche-full.XXXXXX")"
plugin_dir="$run_root/plugins"
data_dir="$run_root/data"
logs_dir="$run_root/logs"
genesis="$run_root/genesis.bin"
projection="$run_root/projection.sqlite3"
authority="$run_root/pretrade-authority.cbor"
ack="$run_root/pretrade-ack.cbor"
pretrade_report="$run_root/pretrade-report.json"
handoff="$run_root/mpc-handoff.cbor"
contexts="$run_root/settlement-contexts.cbor"
finalized="$run_root/finalized-handoff.cbor"
settlement_report="$run_root/settlement-report.json"
reserve_proof_root="$run_root/reserve-proof-parties"
external_kyb_anchor="$run_root/external-kyb-trust-anchor.json"
external_kyb_bundle="$run_root/external-kyb-bundle.json"
csd_signer_store="$run_root/csd-signer.keys"
csd_signer_pin="$run_root/csd-signer.pin"
csd_signer_metadata="$run_root/csd-signer-public.json"
mkdir -p "$plugin_dir" "$data_dir" "$logs_dir"

runner_pid=""
cluster_pid=""
proof_root=""
succeeded=0
cleanup() {
  if [[ -n "$cluster_pid" ]] && kill -0 "$cluster_pid" >/dev/null 2>&1; then
    kill -TERM "$cluster_pid" >/dev/null 2>&1 || true
    wait "$cluster_pid" 2>/dev/null || true
  fi
  if [[ -n "$runner_pid" ]]; then
    "$runner" control stop --endpoint="$runner_endpoint" --request-timeout=3m >/dev/null 2>&1 || true
    kill -TERM "$runner_pid" >/dev/null 2>&1 || true
    wait "$runner_pid" 2>/dev/null || true
  fi
  if [[ "$succeeded" == "1" && "${QOMM_KEEP_AVALANCHE_RUN:-0}" != "1" ]]; then
    rm -rf -- "$run_root"
    case "$proof_root" in
      "${TMPDIR:-/tmp}"/qomm-seven-node-*) rm -rf -- "$proof_root" ;;
    esac
  else
    echo "kept full Avalanche acceptance state at $run_root" >&2
    if [[ -n "$proof_root" ]]; then
      echo "kept private seven-node proof state at $proof_root" >&2
    fi
  fi
}
trap cleanup EXIT INT TERM

cd "$qomm_root/rust"
# This acceptance path starts stock MP-SPDZ as seven external OS processes. It
# intentionally does not link libSPDZ into the Rust coordinator; doing both can
# hide a host/target architecture mismatch behind linker "ignored file"
# warnings even though the external engine path is the one that actually ran.
env -u MP_SPDZ_ROOT cargo build --locked --release \
  --manifest-path "$venue_root/rust/Cargo.toml" --target-dir "$qomm_root/rust/target" \
  -p qomm-transport --features test-support --bin seven_node_cluster
env -u MP_SPDZ_ROOT cargo build --locked --release \
  --manifest-path "$committee_root/rust/Cargo.toml" --target-dir "$qomm_root/rust/target" \
  -p zkpi-committee --bin qomm_node_party
env -u MP_SPDZ_ROOT cargo build --locked --release \
  -p defmi-avalanche-vm --bin qomm-avalanche-vm \
  -p defmi-harness --bin run_pretrade_reservations \
  --bin build_settlement_contexts --bin settle_finalized_batch \
  --bin issue_external_kyb --bin zkpi-hsm-signer

seven_node="$qomm_root/rust/target/release/seven_node_cluster"
node_party="$qomm_root/rust/target/release/qomm_node_party"
pretrade="$qomm_root/rust/target/release/run_pretrade_reservations"
build_contexts="$qomm_root/rust/target/release/build_settlement_contexts"
settle="$qomm_root/rust/target/release/settle_finalized_batch"
issue_external_kyb="$qomm_root/rust/target/release/issue_external_kyb"
zkpi_hsm_signer="$qomm_root/rust/target/release/zkpi-hsm-signer"

if [[ ! -x "$rust_vm" ]]; then
  echo "the QOMM Rust VM build did not produce $rust_vm" >&2
  exit 2
fi

# This is a separate provider process. Only its public trust anchor and signed
# digest-only assertions cross into QOMM; its private signing key is never
# exported or inherited by the MPC/DeFMI processes.
"$issue_external_kyb" --trust-anchor-out "$external_kyb_anchor" \
  --bundle-out "$external_kyb_bundle" >"$logs_dir/external-kyb-provider.json"

# Acceptance uses a process-isolated encrypted-key emulator for the exact HSM
# protocol. It proves that DeFMI never loads the CSD private key, while the
# final receipt remains explicit that no physical hardware HSM was available.
openssl rand -hex 32 >"$csd_signer_pin"
chmod 0600 "$csd_signer_pin"
"$zkpi_hsm_signer" --initialize --store "$csd_signer_store" \
  --pin-file "$csd_signer_pin" --purpose defmi-csd-issuance \
  >"$csd_signer_metadata"
csd_signer_key_id="$(jq -er '.key_id' "$csd_signer_metadata")"
csd_signer_public="$(jq -er '.public_key' "$csd_signer_metadata")"

vm_id="$("$rust_vm" vmid)"
install -m 0755 "$rust_vm" "$plugin_dir/$vm_id"
"$rust_vm" genesis --config "$root/config/test-genesis.json" --out "$genesis"

"$runner" server --port=":$runner_port" --grpc-gateway-port=":$gateway_port" \
  --log-dir="$logs_dir" >"$logs_dir/server.log" 2>&1 &
runner_pid="$!"
ready=0
for _ in {1..100}; do
  if "$runner" control rpc_version --endpoint="$runner_endpoint" >/dev/null 2>&1; then
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
"$runner" control start --endpoint="$runner_endpoint" --request-timeout=5m \
  --avalanchego-path="$avalanchego" --plugin-dir="$plugin_dir" \
  --root-data-dir="$data_dir" --network-id=1337 --num-nodes=5 \
  --reassign-ports-if-used --blockchain-specs="$spec"
"$runner" control wait-for-healthy --endpoint="$runner_endpoint" --request-timeout=5m

strip_ansi() {
  sed $'s/\033\\[[0-9;]*m//g'
}
chain_id="$({ "$runner" control list-blockchains --endpoint="$runner_endpoint"; } 2>&1 \
  | strip_ansi | sed -n 's/.*Blockchain ID: //p' | head -n 1)"
uri_line="$({ "$runner" control uris --endpoint="$runner_endpoint"; } 2>&1 \
  | strip_ansi | sed -n 's/.*URIs: \[\(.*\)\]/\1/p' | head -n 1)"
if [[ -z "$chain_id" || -z "$uri_line" ]]; then
  echo "could not discover the local chain ID or node URIs" >&2
  exit 4
fi
read -r -a node_uris <<<"$uri_line"
if [[ "${#node_uris[@]}" -ne 5 ]]; then
  echo "expected exactly five Avalanche validator RPC endpoints" >&2
  exit 4
fi
primary_endpoint="${node_uris[0]%/}/ext/bc/$chain_id"

cd "$qomm_root"
QOMM_KEEP_ACCEPTANCE_ROOT=1 "$seven_node" \
  --slots 2 --pretrade-ack-timeout-seconds 300 \
  --mp-spdz-root "$mp_spdz_root" --runner "$node_party" \
  --evidence-out "$handoff" --pretrade-authority-out "$authority" \
  --pretrade-ack-in "$ack" \
  --external-kyb-trust-anchor "$external_kyb_anchor" \
  --external-kyb-bundle "$external_kyb_bundle" \
  >"$logs_dir/seven-node.log" 2>&1 &
cluster_pid="$!"

authority_ready=0
for _ in {1..1200}; do
  if [[ -s "$authority" ]]; then
    authority_ready=1
    break
  fi
  if ! kill -0 "$cluster_pid" >/dev/null 2>&1; then
    echo "seven-node MPC process exited before producing pre-trade authority" >&2
    exit 5
  fi
  sleep 0.1
done
if [[ "$authority_ready" != "1" ]]; then
  echo "timed out waiting for seven-node pre-trade authority" >&2
  exit 5
fi

"$pretrade" --authority "$authority" --ack-out "$ack" --state "$projection" \
  --report-out "$pretrade_report" --avalanche-endpoint "$primary_endpoint" \
  --avalanche-domain "$chain_id" --proof-party-bin "$seven_node" \
  --proof-root "$reserve_proof_root" --account-free-notes \
  --csd-signer-bin "$zkpi_hsm_signer" --csd-signer-store "$csd_signer_store" \
  --csd-signer-pin-file "$csd_signer_pin" --csd-signer-key-id "$csd_signer_key_id" \
  --csd-signer-public "$csd_signer_public" \
  --csd-signer-pq-key-id "$(jq -r .pq_key_id "$csd_signer_metadata")" \
  --csd-signer-pq-public "$(jq -r .pq_public_key "$csd_signer_metadata")"

if ! wait "$cluster_pid"; then
  cluster_pid=""
  echo "seven-node MPC acceptance failed; see $logs_dir/seven-node.log" >&2
  exit 5
fi
cluster_pid=""
proof_root="$(sed -n 's/^acceptance root: //p' "$logs_dir/seven-node.log" | head -n 1)"
if [[ -z "$proof_root" || ! -d "$proof_root" || ! -s "$handoff" ]]; then
  echo "seven-node MPC did not retain the proof state or final handoff" >&2
  exit 5
fi

"$build_contexts" --authority "$authority" --ack "$ack" --handoff "$handoff" \
  --contexts-out "$contexts"
"$seven_node" --finalize-handoff --proof-root "$proof_root" --handoff "$handoff" \
  --contexts "$contexts" --pretrade-ack "$ack" --finalized-out "$finalized"

peer_args=()
for uri in "${node_uris[@]:1}"; do
  peer_args+=(--avalanche-peer-endpoint "${uri%/}/ext/bc/$chain_id")
done
"$settle" --authority "$authority" --ack "$ack" --finalized-handoff "$finalized" \
  --state "$projection" --report-out "$settlement_report" \
  --avalanche-endpoint "$primary_endpoint" --avalanche-domain "$chain_id" \
  --account-free-notes \
  "${peer_args[@]}"

expected_root="$(jq -er '.after_state_root' "$settlement_report")"
state_root() {
  local endpoint="$1"
  curl --fail --silent --show-error --max-time 10 \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"defmivm.stateRoot","params":{}}' \
    "$endpoint" | jq -er '.result.stateRoot'
}

state_sync_status() {
  local endpoint="$1"
  curl --fail --silent --show-error --max-time 10 \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"defmivm.stateSyncStatus","params":{}}' \
    "$endpoint" | jq -e '.result'
}

# This is a genuine cold-join check, not a process restart over an already
# populated DB. node3 remains the same L1 validator, but its temporary
# Avalanche database is removed while the process is paused. On resume the
# Rust VM must accept a network-selected summary, fetch Merkle-proven chunks
# over AppRequest/AppResponse, install the state atomically, and emit
# StateSyncFinished before AvalancheGo can continue bootstrapping.
cold_sync_node_db="$data_dir/node3/db"
case "$cold_sync_node_db" in
  "$run_root"/data/node3/db) ;;
  *)
    echo "refusing to clear an unexpected validator DB path: $cold_sync_node_db" >&2
    exit 6
    ;;
esac
if [[ ! -d "$cold_sync_node_db" ]]; then
  echo "cold state-sync validator DB was not found: $cold_sync_node_db" >&2
  exit 6
fi
cold_sync_db_entries="$(find "$cold_sync_node_db" -mindepth 1 | wc -l | tr -d ' ')"
if [[ "$cold_sync_db_entries" -eq 0 ]]; then
  echo "cold state-sync test cannot prove a reset because node3 DB is empty" >&2
  exit 6
fi
restart_started="$(date +%s)"
"$runner" control pause-node node3 --endpoint="$runner_endpoint" --request-timeout=3m
rm -rf -- "$cold_sync_node_db"
install -d -m 0700 "$cold_sync_node_db"
"$runner" control resume-node node3 --endpoint="$runner_endpoint" --request-timeout=3m
"$runner" control wait-for-healthy --endpoint="$runner_endpoint" --request-timeout=5m
restart_elapsed="$(( $(date +%s) - restart_started ))"

recovered=0
for _ in {1..150}; do
  recovered=1
  for uri in "${node_uris[@]}"; do
    endpoint="${uri%/}/ext/bc/$chain_id"
    if [[ "$(state_root "$endpoint" 2>/dev/null || true)" != "$expected_root" ]]; then
      recovered=0
      break
    fi
  done
  if [[ "$recovered" == "1" ]]; then
    break
  fi
  sleep 0.2
done
if [[ "$recovered" != "1" ]]; then
  echo "Avalanche validators did not recover the product settlement state root" >&2
  exit 6
fi

cold_sync_endpoint="${node_uris[2]%/}/ext/bc/$chain_id"
cold_sync_status="$(state_sync_status "$cold_sync_endpoint")"
cold_sync_height="$(jq -er '.lastCompletedHeight | select(type == "number" and . > 0)' <<<"$cold_sync_status")"
cold_sync_summary_id="$(jq -er '.lastCompletedSummaryID | select(type == "string" and length > 0)' <<<"$cold_sync_status")"
if [[ "$(jq -r '.enabled and (.running | not) and (.lastError == null)' <<<"$cold_sync_status")" != "true" ]]; then
  echo "node3 did not report a completed error-free fast state sync" >&2
  exit 6
fi

mkdir -p "$(dirname -- "$out")"
avalanchego_version="$("$avalanchego" --version 2>&1 | head -n 1)"
# Some maintained network-runner builds expose their protocol version only
# through the live RPC surface and intentionally have no `--version` flag. A
# failed command substitution under `set -e` used to discard an otherwise
# successful full acceptance run just before writing its receipt.
runner_version="$({ "$runner" control rpc_version --endpoint="$runner_endpoint" || true; } 2>&1 \
  | strip_ansi | tail -n 1)"
if [[ -z "$runner_version" ]]; then
  runner_version="rpc-version-unreported"
fi
avalanchego_sha256="$(shasum -a 256 "$avalanchego" | awk '{print $1}')"
runner_sha256="$(shasum -a 256 "$runner" | awk '{print $1}')"
vm_sha256="$(shasum -a 256 "$rust_vm" | awk '{print $1}')"
mp_spdz_commit="$(git -C "$mp_spdz_root" rev-parse HEAD)"
receipt_tmp="$out.tmp.$$"
jq -s \
  --arg avalanchego_version "$avalanchego_version" \
  --arg avalanchego_sha256 "$avalanchego_sha256" \
  --arg runner_version "$runner_version" \
  --arg runner_sha256 "$runner_sha256" \
  --arg vm_sha256 "$vm_sha256" \
  --arg mp_spdz_commit "$mp_spdz_commit" \
  --argjson restart_elapsed "$restart_elapsed" \
  --argjson cold_sync_db_entries "$cold_sync_db_entries" \
  --argjson cold_sync_height "$cold_sync_height" \
  --arg cold_sync_summary_id "$cold_sync_summary_id" \
  '.[1] + {
    pretrade: .[0],
    runtime: {
      avalanchego_version: $avalanchego_version,
      avalanchego_sha256: $avalanchego_sha256,
      network_runner_version: $runner_version,
      network_runner_sha256: $runner_sha256,
      qomm_rust_vm_sha256: $vm_sha256,
      rpcchainvm_protocol: 45,
      mp_spdz_commit: $mp_spdz_commit,
      mpc_execution_mode: "external-seven-process-mp-spdz",
      embedded_libspdz_used: false,
      avalanche_validators: 5,
      mpc_parties: 7,
      physical_hosts: 1,
      validator_restart: {
        node: "node3",
        elapsed_seconds: $restart_elapsed,
        recovered: true,
        roots_verified: 5,
        database_reset: true,
        removed_database_entries: $cold_sync_db_entries
      },
      validator_fast_state_sync: {
        node: "node3",
        completed: true,
        height: $cold_sync_height,
        summary_id: $cold_sync_summary_id,
        merkle_chunk_transport: "rpcchainvm-app-request-response",
        install_mode: "atomic-static"
      }
    }
  }' "$pretrade_report" "$settlement_report" >"$receipt_tmp"
mv -f -- "$receipt_tmp" "$out"
succeeded=1
echo "wrote $out"
