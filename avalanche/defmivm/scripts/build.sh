#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out=${1:-"$root/build/defmivm"}
mkdir -p "$(dirname -- "$out")"
cd "$root"
go test ./...
go vet ./...
go build -trimpath -ldflags='-s -w' -o "$out" ./cmd/defmivm
"$out" version
"$out" vmid
