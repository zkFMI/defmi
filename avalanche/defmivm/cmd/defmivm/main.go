package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/vms/rpcchainvm"
	"github.com/shukob/defmi/avalanche/defmivm"
	"github.com/shukob/defmi/avalanche/defmivm/genesis"
	"github.com/shukob/defmi/avalanche/defmivm/tx"
)

const maxConfigBytes = 1 << 20

type genesisConfig struct {
	Timestamp int64 `json:"timestamp"`
	Committee struct {
		Epoch     uint64 `json:"epoch"`
		Threshold uint16 `json:"threshold"`
		Members   []struct {
			NodeID    string `json:"nodeID"`
			PublicKey string `json:"publicKey"`
		} `json:"members"`
	} `json:"committee"`
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println(defmivm.Version)
			return
		case "vmid":
			fmt.Println(vmID())
			return
		case "genesis":
			if err := genesisCommand(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "genesis failed: %v\n", err)
				os.Exit(2)
			}
			return
		}
	}
	if err := rpcchainvm.Serve(context.Background(), &defmivm.VM{}); err != nil {
		fmt.Fprintf(os.Stderr, "defmivm failed: %v\n", err)
		os.Exit(1)
	}
}

func vmID() ids.ID {
	var raw [ids.IDLen]byte
	copy(raw[:], []byte("defmivm"))
	result, err := ids.ToID(raw[:])
	if err != nil {
		panic(err)
	}
	return result
}

func genesisCommand(args []string) error {
	flags := flag.NewFlagSet("genesis", flag.ContinueOnError)
	configPath := flags.String("config", "", "JSON committee configuration")
	outputPath := flags.String("out", "-", "binary genesis output or - for stdout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || flags.NArg() != 0 {
		return errors.New("usage: defmivm genesis --config FILE [--out FILE|-]")
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > maxConfigBytes {
		return errors.New("genesis config must contain 1..1048576 bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config genesisConfig
	if err := decoder.Decode(&config); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("genesis config contains trailing JSON")
	}
	sort.Slice(config.Committee.Members, func(i, j int) bool {
		return config.Committee.Members[i].NodeID < config.Committee.Members[j].NodeID
	})
	members := make([]tx.CommitteeMember, len(config.Committee.Members))
	for i, member := range config.Committee.Members {
		key, err := hex.DecodeString(member.PublicKey)
		if err != nil || len(key) != len(members[i].PublicKey) {
			return fmt.Errorf("member %q publicKey must be 32-byte hex", member.NodeID)
		}
		members[i].NodeID = member.NodeID
		copy(members[i].PublicKey[:], key)
	}
	g := &genesis.Genesis{Timestamp: config.Timestamp, Committee: tx.Committee{
		Epoch: config.Committee.Epoch, Threshold: config.Committee.Threshold,
		Members: members,
	}}
	encoded, err := genesis.Marshal(g)
	if err != nil {
		return err
	}
	if *outputPath == "-" {
		_, err = os.Stdout.Write(encoded)
		return err
	}
	temporary := *outputPath + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0o644); err != nil {
		return err
	}
	if err := os.Rename(temporary, *outputPath); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}
