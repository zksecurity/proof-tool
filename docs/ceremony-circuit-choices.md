# Ceremony circuit choices

The signed ceremony definition binds one reviewed R1CS. `mpc-ceremony init`
accepts these key versions in rehearsal or production mode:

| Key version | Constraints | Domain | Statement | Production GO |
| --- | ---: | ---: | --- | --- |
| `ownership-destination-v3` | 1,444,667 | 2^21 | Cardano ownership and destination | Eligible after the separate production decision |
| `rehearsal-tiny-v1` | 5 | 2^3 | Public cubic test statement | Eligible for its exact signed test circuit |
| `rehearsal-k11-v1` | 1,030 | 2^11 | Public cubic test statement with a longer multiplication chain | Eligible for its exact signed test circuit |

The K11 domain has 2,048 elements, which is 1/1,024 of K21. Production mode
keeps its participation, software, and witnessing requirements when a test
circuit is selected. It does not change what the circuit proves. The signed
circuit identity and serialized R1CS digest distinguish every choice; a
GO for either test circuit approves only that circuit's signed ceremony and
release. It does not authorize ownership-proof use. The V5 decision binds an
exact-circuit rehearsal report as human-reviewed evidence; file presence alone
does not prove what the report claims.

For Definition V5, the decision draft uses
`proof-tool-mpc-production-decision-draft-v5`, `circuit_rehearsal`, and the
`exact-circuit-rehearsal` gate. The `mainnet_deployment_plan` evidence remains
mandatory; for a test circuit, that plan must explicitly rule out using its
keys as ownership-proof parameters. Historical V3/V4 decisions retain their
K21-only `k21_rehearsal` gate and field.

The `finalize rehearsal-evidence` command creates and verifies a proof of the
fixed public test statement for either test circuit. It does not use wallet
material or produce an ownership proof. The normal application prover/key
profile registry still accepts only application circuits.

The current Relay standalone coordinator guide offers all three choices.
Tessera setup imports remain unavailable for this runtime. Website selection
would require a new versioned shared setup contract and a compatible Tessera
release. No released binaries or live ceremony state are changed by these
source edits.
