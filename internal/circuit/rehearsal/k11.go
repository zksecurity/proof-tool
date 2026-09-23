package rehearsal

import "github.com/consensys/gnark/frontend"

const (
	K11KeyVersion = "rehearsal-k11-v1"
	K11CircuitID  = "rehearsal-k11-v1/bls12-381/groth16"
)

// K11Circuit proves the same public cubic statement as Circuit. The extra
// multiplication chain makes the MPC domain 2^11 for production-mode workflow
// exercises. It does not prove ownership of a Cardano credential.
type K11Circuit struct {
	X   frontend.Variable
	Pub frontend.Variable `gnark:",public"`
}

func (c *K11Circuit) Define(api frontend.API) error {
	if err := (&Circuit{X: c.X, Pub: c.Pub}).Define(api); err != nil {
		return err
	}
	chain := c.X
	for range 1024 {
		chain = api.Mul(chain, c.X)
	}
	api.AssertIsDifferent(chain, 0)
	return nil
}
