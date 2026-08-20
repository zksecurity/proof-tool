// Package rehearsal defines a deliberately tiny circuit used only to exercise
// the MPC ceremony machinery.
//
// The production destination-v2 circuit has roughly 1.79 million constraints,
// which forces an FFT domain of 2^21. That makes every ceremony operation
// expensive: a single contribution moves 604 MiB and takes minutes, a phase
// close replays the whole accepted chain and takes over an hour, and a full
// rehearsal is a multi-day exercise. Testing the orchestration around the
// ceremony at that size is impractical.
//
// This circuit proves a trivial statement at a small domain so the same
// orchestration can be exercised in seconds. It proves nothing useful and must
// never appear in a production ceremony; CeremonyDefinition rejects it whenever
// mode is production, and the K21 rehearsal gate in the production decision
// continues to demand domain 2^21 so a run at this size can never satisfy it.
package rehearsal

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

const (
	// CircuitID names this circuit in a ceremony definition. The "rehearsal"
	// prefix is load bearing: it is what a reader sees in ceremony.json, and it
	// must be obvious at a glance that a transcript is not production evidence.
	CircuitID = "rehearsal-tiny-v1/bls12-381/groth16"

	// KeyVersion is the value passed to init --key-version to select this
	// circuit.
	KeyVersion = "rehearsal-tiny-v1"
)

// Circuit proves knowledge of a value whose cube equals the public input. The
// statement is arbitrary; what matters is that it compiles to a handful of
// constraints and therefore a small domain.
type Circuit struct {
	X   frontend.Variable
	Pub frontend.Variable `gnark:",public"`
}

func (c *Circuit) Define(api frontend.API) error {
	cube := api.Mul(api.Mul(c.X, c.X), c.X)
	api.AssertIsEqual(cube, c.Pub)

	// Exactly one Groth16 commitment, matching destination-v2.
	//
	// This is not decoration. Finalization exports a Cardano-format verifying
	// key whose BSB22 encoding assumes a single commitment, so a circuit with
	// none cannot be finalized at all. Without this the rehearsal circuit could
	// exercise the ceremony only as far as the beacon, and the finalize,
	// audit and release stages would stay untestable.
	committer, ok := api.(frontend.Committer)
	if !ok {
		return errors.New("rehearsal circuit requires a committer API")
	}
	commitment, err := committer.Commit(c.X)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, 0)
	return nil
}

// Assignment builds a satisfying witness for the given secret.
func Assignment(x int64) *Circuit {
	value := big.NewInt(x)
	cube := new(big.Int).Mul(value, value)
	cube.Mul(cube, value)
	return &Circuit{X: value, Pub: cube}
}
