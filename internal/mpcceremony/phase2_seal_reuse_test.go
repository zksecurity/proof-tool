package mpcceremony

import (
	"bytes"
	gnarkmpc "github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup"
	"testing"
)

func TestOwnedPhase2SealMatchesIndependentKeys(t *testing.T) {
	circuit := compileEngineCircuit(t)
	first, err := ContributePhase1(circuit.Binding.DomainSize, nil)
	if err != nil {
		t.Fatal(err)
	}
	commons, err := SealPhase1(circuit.Binding.DomainSize, bytes.Repeat([]byte{0x41}, contributionChallengeSize), []*gnarkmpc.Phase1{first})
	if err != nil {
		t.Fatal(err)
	}
	contribution, err := ContributePhase2(circuit, commons, nil)
	if err != nil {
		t.Fatal(err)
	}
	archive := serializeEngineArtifact(t, contribution)
	history := []*gnarkmpc.Phase2{contribution}
	beacon := bytes.Repeat([]byte{0x42}, contributionChallengeSize)
	expectedPK, expectedVK, err := SealPhase2(circuit, commons, beacon, history)
	if err != nil {
		t.Fatal(err)
	}
	expectedPKBytes, expectedVKBytes := serializeEngineArtifact(t, expectedPK), serializeEngineArtifact(t, expectedVK)
	owned, err := initializeOwnedPhase2(circuit, commons)
	if err != nil {
		t.Fatal(err)
	}
	evals := owned.evaluations
	pk, vk, err := sealOwnedPhase2(owned, beacon, 1, phase2SliceLoader(history))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expectedPKBytes, serializeEngineArtifact(t, pk)) || !bytes.Equal(expectedVKBytes, serializeEngineArtifact(t, vk)) {
		t.Fatal("owned seal changed deterministic keys")
	}
	if !bytes.Equal(archive, serializeEngineArtifact(t, contribution)) {
		t.Fatal("seal mutated archived contribution")
	}
	if _, _, err := sealOwnedPhase2(owned, beacon, 1, phase2SliceLoader(history)); err == nil {
		t.Fatal("consumed initialization reused")
	}
	if owned.evaluations != nil {
		t.Fatal("consumed state retained evaluations")
	}
	// These arrays are retained by the first key set. A separately initialized
	// key set must remain independent even after the first set's arrays change.
	for i := range evals.G1.VKK {
		evals.G1.VKK[i].SetInfinity()
	}
	for i := range evals.G1.CKK {
		for j := range evals.G1.CKK[i] {
			evals.G1.CKK[i][j].SetInfinity()
		}
	}
	if !bytes.Equal(expectedPKBytes, serializeEngineArtifact(t, expectedPK)) || !bytes.Equal(expectedVKBytes, serializeEngineArtifact(t, expectedVK)) {
		t.Fatal("independently sealed keys share evaluation arrays")
	}
	if bytes.Equal(expectedVKBytes, serializeEngineArtifact(t, vk)) {
		t.Fatal("alias test did not exercise retained evaluation arrays")
	}
}
