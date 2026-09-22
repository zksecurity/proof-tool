package mpcceremony

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	gnarkmpc "github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup"
)

func TestVerifiedGenesisReplayMatchesIndependentReplay(t *testing.T) {
	circuit := compileEngineCircuit(t)
	first, err := ContributePhase1(circuit.Binding.DomainSize, nil)
	if err != nil {
		t.Fatal(err)
	}
	commons, err := SealPhase1(circuit.Binding.DomainSize, bytes.Repeat([]byte{0x31}, contributionChallengeSize), []*gnarkmpc.Phase1{first})
	if err != nil {
		t.Fatal(err)
	}
	var contributions []*gnarkmpc.Phase2
	for range 3 {
		next, err := ContributePhase2(circuit, commons, contributions)
		if err != nil {
			t.Fatal(err)
		}
		contributions = append(contributions, next)
	}
	for count := 0; count <= len(contributions); count++ {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			genesis, shape, err := InitializePhase2(circuit, commons)
			if err != nil {
				t.Fatal(err)
			}
			before := serializeEngineArtifact(t, genesis)
			archives := make([][]byte, count)
			for i := range count {
				archives[i] = serializeEngineArtifact(t, contributions[i])
			}
			head, err := replayPhase2FromVerifiedGenesis(genesis, shape, count, phase2SliceLoader(contributions[:count]))
			if err != nil {
				t.Fatal(err)
			}
			independent, _, err := replayPhase2State(circuit, commons, count, phase2SliceLoader(contributions[:count]))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(serializeEngineArtifact(t, head), serializeEngineArtifact(t, independent)) {
				t.Fatal("replay heads differ")
			}
			if !bytes.Equal(before, serializeEngineArtifact(t, genesis)) {
				t.Fatal("genesis mutated")
			}
			for i := range count {
				if !bytes.Equal(archives[i], serializeEngineArtifact(t, contributions[i])) {
					t.Fatalf("archive %d mutated", i)
				}
			}
		})
	}
	for index := range contributions {
		t.Run(fmt.Sprintf("invalid edge %d", index), func(t *testing.T) {
			genesis, shape, err := InitializePhase2(circuit, commons)
			if err != nil {
				t.Fatal(err)
			}
			bad := new(gnarkmpc.Phase2)
			if err := streamClone(contributions[index], bad); err != nil {
				t.Fatal(err)
			}
			bad.Parameters.G1.PKK[0].SetInfinity()
			altered := append([]*gnarkmpc.Phase2(nil), contributions...)
			altered[index] = bad
			if _, err := replayPhase2FromVerifiedGenesis(genesis, shape, len(altered), phase2SliceLoader(altered)); err == nil {
				t.Fatal("invalid contribution accepted")
			}
			if err := ReplayPhase2(circuit, commons, altered); err == nil {
				t.Fatal("independent replay accepted invalid contribution")
			}
		})
	}
	genesis, shape, err := InitializePhase2(circuit, commons)
	if err != nil {
		t.Fatal(err)
	}
	wrongShape := shape
	wrongShape.PKK++
	challenged := new(gnarkmpc.Phase2)
	if err := streamClone(genesis, challenged); err != nil {
		t.Fatal(err)
	}
	challenged.Challenge = make([]byte, contributionChallengeSize)
	for _, tc := range []struct {
		name    string
		genesis *gnarkmpc.Phase2
		shape   Phase2Shape
		count   int
		load    Phase2Loader
	}{
		{"nil genesis", nil, shape, 0, nil},
		{"wrong shape", genesis, wrongShape, 0, nil},
		{"nonzero challenge", challenged, shape, 0, nil},
		{"negative count", genesis, shape, -1, nil},
		{"nil loader", genesis, shape, 1, nil},
		{"nil contribution", genesis, shape, 1, func(int) (*gnarkmpc.Phase2, error) { return nil, nil }},
		{"loader failure", genesis, shape, 1, func(int) (*gnarkmpc.Phase2, error) { return nil, errors.New("read failed") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := replayPhase2FromVerifiedGenesis(tc.genesis, tc.shape, tc.count, tc.load); err == nil {
				t.Fatal("invalid replay accepted")
			}
		})
	}
}
