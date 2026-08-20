// Command mpc-rehearsal-config creates fresh same-host identities and exact
// canonical inputs for a local MPC ceremony rehearsal. It is deliberately not
// a production enrollment tool: production identities must be generated and
// governed independently by their owners.
package main

import (
	"flag"
	"fmt"
	"os"

	"proof-tool/internal/mpcrehearsal"
)

func main() {
	outDir := flag.String("out-dir", "", "fresh output directory")
	participantCount := flag.Int("participants", 3, "number of rehearsal participants (3-20)")
	beaconWitnessLead := flag.Uint(
		"beacon-witness-lead-seconds",
		300,
		"signed rehearsal witness/round lead in seconds (minimum 60)",
	)
	flag.Parse()
	if *outDir == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: mpc-rehearsal-config --out-dir FRESH_DIR [--participants 3]")
		os.Exit(2)
	}
	if *beaconWitnessLead > uint(^uint32(0)) {
		fmt.Fprintln(os.Stderr, "beacon witness lead exceeds uint32")
		os.Exit(2)
	}
	if err := generate(*outDir, *participantCount, uint32(*beaconWitnessLead)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("OK: generated rehearsal-only identities and canonical config in %s\n", *outDir)
}

func generate(outDir string, participantCount int, beaconWitnessLead uint32) error {
	return mpcrehearsal.Generate(outDir, participantCount, beaconWitnessLead)
}
