package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/shukob/defmi/avalanche/defmivm/genesis"
)

func TestGenesisCompilerProducesValidatedBinary(t *testing.T) {
	output := filepath.Join(t.TempDir(), "genesis.bin")
	require.NoError(t, genesisCommand([]string{
		"--config", filepath.Join("..", "..", "config", "test-genesis.json"),
		"--out", output,
	}))
	raw, err := os.ReadFile(output)
	require.NoError(t, err)
	parsed, err := genesis.Parse(raw)
	require.NoError(t, err)
	require.Equal(t, uint16(3), parsed.Committee.Threshold)
	require.Len(t, parsed.Committee.Members, 7)
}

func TestGenesisCompilerRejectsUnknownFields(t *testing.T) {
	config := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(config, []byte(`{
		"timestamp":0,
		"committee":{"epoch":1,"threshold":1,"members":[
			{"nodeID":"n","publicKey":"0000000000000000000000000000000000000000000000000000000000000000"}
		]},
		"unsafe":true
	}`), 0o600))
	require.ErrorContains(t, genesisCommand([]string{"--config", config}), "unknown field")
}
