// This component benchmark never signs or publishes ceremony artifacts. It
// compares production-circuit initialization with an authenticated genesis digest.
// It is not a transcript replay or a ceremony verification result.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
	m "proof-tool/internal/mpcceremony"
)

func smallFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("invalid benchmark metadata file")
	}
	return io.ReadAll(io.LimitReader(f, (1<<20)+1))
}

func run() error {
	if len(os.Args) != 2 {
		return errors.New("usage: mpc-phase2-resource-benchmark PUBLIC_INPUT_DIRECTORY")
	}
	root := os.Args[1]
	path := func(name string) string { return filepath.Join(root, name) }
	started := time.Now()
	trusted, err := m.LoadSignedDefinition(m.TrustPaths{DefinitionPath: path("ceremony.json"), DefinitionSignaturePath: path("ceremony.sig"), CoordinatorPublicKeyPath: path("coordinator.hex")})
	if err != nil {
		return err
	}
	raw, err := smallFile(path("seal.json"))
	if err != nil {
		return err
	}
	sig, err := smallFile(path("seal.sig"))
	if err != nil {
		return err
	}
	var seal m.SealRecord
	if err := m.VerifySignedRecord(raw, sig, &seal, trusted.Definition.Coordinator.KeyID, trusted.CoordinatorPublicKey); err != nil {
		return err
	}
	if seal.Phase != m.Phase1 || seal.CeremonyID != trusted.Definition.CeremonyID || len(seal.Outputs) != 1 {
		return errors.New("unexpected Phase 1 seal")
	}
	chain, _, err := m.LoadSignedChainExact(trusted, m.PhaseTranscriptPaths{RootDir: root, ChainPath: path("chain-0000.json"), ChainSignaturePath: path("chain-0000.sig")})
	if err != nil {
		return err
	}
	if chain.Phase != m.Phase2 || len(chain.Records) != 0 {
		return errors.New("expected zero-contribution Phase 2 chain")
	}
	phaseID, err := m.ComputePhaseID(trusted.Definition.CeremonyID, m.Phase2, chain.Genesis, seal.SealID)
	if err != nil {
		return err
	}
	if chain.PhaseID != phaseID {
		return errors.New("genesis chain does not bind seal")
	}
	compileStart := time.Now()
	circuit, err := m.CompileDestinationV3()
	if err != nil {
		return err
	}
	if err := m.ValidateCircuitBinding(circuit, trusted.Definition.Circuit); err != nil {
		return err
	}
	compileTime := time.Since(compileStart)
	readStart := time.Now()
	commons, digest, err := m.ReadCommonsFile(path("commons.bin"), m.CommonsShape{DomainN: circuit.Binding.DomainSize})
	if err != nil {
		return err
	}
	actual := m.Digest{SHA256: "sha256:" + hex.EncodeToString(digest.SHA256[:]), Blake2b256: "blake2b256:" + hex.EncodeToString(digest.BLAKE2b256[:]), Size: digest.Size}
	if actual != seal.Outputs[0].Digest {
		return errors.New("commons differ from authenticated seal")
	}
	readTime := time.Since(readStart)
	deriveStart := time.Now()
	genesis, _, err := m.InitializePhase2(circuit, commons)
	if err != nil {
		return err
	}
	deriveTime := time.Since(deriveStart)
	sha := sha256.New()
	blake, err := blake2b.New256(nil)
	if err != nil {
		return err
	}
	size, err := genesis.WriteTo(io.MultiWriter(sha, blake))
	if err != nil {
		return err
	}
	output := m.Digest{SHA256: "sha256:" + hex.EncodeToString(sha.Sum(nil)), Blake2b256: "blake2b256:" + hex.EncodeToString(blake.Sum(nil)), Size: size}
	if output != chain.Genesis.Digest {
		return errors.New("derived genesis differs from authenticated production genesis")
	}
	peakBytes, err := os.ReadFile("/sys/fs/cgroup/memory.peak")
	if err != nil {
		return fmt.Errorf("read benchmark cgroup peak: %w", err)
	}
	peak, err := strconv.ParseUint(strings.TrimSpace(string(peakBytes)), 10, 64)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"memory_peak_bytes": peak, "schema": "phase2-component-resource-benchmark-v1", "gomaxprocs": runtime.GOMAXPROCS(0),
		"circuit": circuit.Binding, "commons": actual, "genesis": output,
		"compile_seconds": compileTime.Seconds(), "read_seconds": readTime.Seconds(), "derive_seconds": deriveTime.Seconds(), "total_seconds": time.Since(started).Seconds(),
		"matches_authenticated_genesis": true, "full_transcript_verified": false,
	})
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
