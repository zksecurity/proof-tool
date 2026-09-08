# Live rehearsal adapters

These adapters were used with the protocol library at
`657b634bd82eaee2f175af3e6746273e7526fe39` to complete an actual tiny-circuit ceremony.
They do not replace or relax the released verifier.

`live-rehearsal-sign` signs reviewed canonical operational records that lack an
`ops sign` command: custody handoffs/receipts, multi-relay beacon evidence, and the
complete operational bundle. It authenticates the signed definition, requires
rehearsal mode, checks the exact reviewed SHA-256 and required signer key, and
verifies its resulting detached signature. Output is create-only. Physical
observations and truthful record timestamps remain the operator's responsibility;
the adapter does not invent them. Verify receipts with their exact related handoff,
and verify bundles with the complete evidence root using the released CLI.

`../live-rehearsal-proof` generates a real proof for the exact pinned five-constraint
rehearsal circuit and the repository's public golden input. It authenticates the
preliminary keys, checks the circuit digest, uses the released cube-relation circuit,
and verifies the generated proof before writing public evidence. No wallet input is
accepted. The public cube root is a trivial rehearsal witness, not application
ownership evidence or contribution randomness.

Build from this repository:

```sh
CGO_ENABLED=0 go build -o /tmp/rehearsal-sign ./scripts/live-rehearsal-sign
CGO_ENABLED=0 go build -o /tmp/rehearsal-proof ./scripts/live-rehearsal-proof
```

Use fresh, role-specific rehearsal keys and an isolated signing environment. The
live run used network-disabled containers with only one role's key mounted; the
host stayed online and one operator owned all roles. Neither helper establishes
physical independence, physical erasure, or production readiness.

Validation included rejection of a wrong signer key and altered review digest,
real handoff/receipt verification, actual MPC-derived proof generation, complete
signed operational-bundle verification, both auditor replays, and release
verification with the frozen released CLI. The runtime evidence records the exact
helper binary hashes separately from the frozen contributor/verifier binaries.
