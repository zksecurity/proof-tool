// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"strings"
)

func writeUsage(w io.Writer, topic []string) error {
	key := strings.Join(topic, " ")
	if text, ok := commandHelp[key]; ok {
		_, err := fmt.Fprint(w, text)
		return err
	}
	_, err := fmt.Fprint(w, rootHelp)
	return err
}

const rootHelp = `Usage:
  mpc-ceremony [--format human|json] [--quiet] <command> [flags]

Offline, append-only orchestration for this repository's BLS12-381 Groth16
multi-party setup. Identity generation is the only production command that
creates a signing key; all operational commands accept an existing local key.
The explicitly rehearsal-only initializer creates same-host test identities.
The binary performs no network access and never selects a mutable "latest"
artifact.

Commands:
  init                 Bind a ceremony to the compiled repository circuit
  identity generate    Create a local Ed25519 key and public identity document
  rehearsal init       Create and initialize a three-party tiny rehearsal
  inspect              Report chain state and next scheduled contribution
  phase1 contribute    Verify the full phase 1 chain and contribute
  phase1 attest-erasure Sign a participant cleanup claim (not physical erasure)
  phase1 verify        Verify and append one candidate contribution
  phase1 close         Close the accepted phase 1 chain
  phase1 beacon        Record signed post-closure beacon evidence
  phase1 seal          Apply an offline post-closure beacon
  phase2 init          Initialize circuit-specific phase 2
  phase2 contribute    Verify the full phase 2 chain and contribute
  phase2 attest-erasure Sign a participant cleanup claim (not physical erasure)
  phase2 verify        Verify and append one candidate contribution
  phase2 close         Close the accepted phase 2 chain
  phase2 beacon        Record signed post-closure beacon evidence
  finalize prepare     Replay both phases and publish preliminary final keys
  finalize complete    Verify external public evidence and create candidate
  finalize rehearsal-evidence  Generate a real proof for the tiny rehearsal circuit
  replay               Publicly replay both phases without signing
  audit                Independently replay and audit ceremony artifacts
  release sign         Sign an audited release manifest
  release verify       Verify release and ceremony coherence
  decision prepare     Derive the canonical production GO/NO-GO record
  decision sign        Sign the canonical production GO/NO-GO record
  decision verify      Verify decision evidence and role threshold
  checkpoint prepare   Re-derive a supported ceremony checkpoint from authenticated evidence
  checkpoint sign      Re-derive and sign an exact reviewed ceremony checkpoint
  checkpoint verify    Fully verify a signed ceremony checkpoint and its evidence
  checkpoint verify-stored  Infer and fully verify a fetched checkpoint ancestry
  inspect definition   Authenticate and describe a ceremony definition
  inspect chain        Authenticate and describe an accepted chain
  inspect participant  Match an existing key to the participant roster
  inspect enrollment   Authenticate an operational enrollment
  inspect checkpoint   Authenticate a storage-first workflow checkpoint
  inspect checkpoint-transition  Authenticate one legal checkpoint edge
  ops prepare-enrollment  Derive your ceremony-bound public enrollment
  ops sign             Sign your reviewed enrollment or observation offline
  ops prepare-public-witness-receipt  Prepare witnessed closure bytes
  ops prepare-mirror-receipt  Authenticate a relay draft for offline signing
  ops export-signing   Export canonical operational bytes for offline signing
  ops import-signature Import and verify a raw offline Ed25519 signature
  ops verify           Verify a signed operational record fail-closed

All input and output paths are explicit. Outputs must not already exist unless
command-specific help documents byte-exact crash continuation. There are no
network, automatic-discovery, overwrite, deterministic-randomness, or
verification-bypass flags.

Run "mpc-ceremony help <command>" for command-specific help.
`

var inspectHelp = `Usage:
  mpc-ceremony inspect --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --transcript-dir DIR [--full]

Read-only recovery inspection. Reports ceremony identity and mode, per-phase
accepted count and head record, the next scheduled participant and index, the
closure/beacon/seal state, and which referenced artifacts are present.

It requires no signing key, writes nothing, and never replays contributions.
Unlike every other command it discovers the highest published chain file per
phase; that is safe only because the result feeds no signing or verification
decision, and every discovered file is authenticated against the trust anchor
before being reported.

The default depth verifies signatures and structure and checks artifact
presence by size in seconds. --full additionally re-verifies every payload
digest, attestation, erasure, and verification record, which re-hashes every
artifact. The output states which depth ran.
`

const replayFlagsHelp = `
Required immutable replay evidence:
  --transcript-root DIR
  --phase1-chain FILE --phase1-chain-signature FILE
  --phase1-close FILE --phase1-close-signature FILE
  --phase1-beacon FILE --phase1-beacon-signature FILE
  --phase1-seal FILE --phase1-seal-signature FILE
  --phase2-chain FILE --phase2-chain-signature FILE
  --phase2-close FILE --phase2-close-signature FILE
  --phase2-beacon FILE --phase2-beacon-signature FILE

The signed chain, closure, beacon, and seal records bind the genesis,
contributions, attestations, erasure evidence, verification records, raw drand
responses, and commons by safe relative artifact name. Those artifacts are
strictly resolved beneath --transcript-root; the operator cannot substitute a
second path list.
`

var commandHelp = map[string]string{
	"identity": `Usage:
  mpc-ceremony identity generate --identity-id ID --display-name NAME \
    --private-key-out FRESH_SECRET_FILE \
    --public-identity-out FRESH_PUBLIC_FILE

Generate an Ed25519 ceremony signing identity from operating-system CSPRNG
entropy. Run "mpc-ceremony help identity generate" for handling rules.
`,
	"identity generate": `Usage:
  mpc-ceremony identity generate --identity-id ID --display-name NAME \
    --private-key-out FRESH_SECRET_FILE \
    --public-identity-out FRESH_PUBLIC_FILE

Generates a new Ed25519 key using the operating-system CSPRNG. The private
output is a proof-tool-compatible hex seed created with mode 0600; keep it on
the trusted machine and never send it to Relay or the coordinator. The public
output is canonical identity JSON containing the public key, its SHA-256
fingerprint, and an automatically derived key ID. Share only that public file.

Both parent directories must already exist and the output paths must be
distinct. Before creating the key, the command saves a protected recovery
record beside the private output. If creation stops after the private key is
saved but before the public file appears, repeating the exact command derives
that public file from the same key. If both files were completed before the
caller saw success, repeating the exact command verifies and adopts the exact
pair. Changed identity inputs or output bytes are rejected and a second key is
never generated automatically. Private key bytes are never printed.
`,
	"rehearsal": `Usage:
  mpc-ceremony rehearsal init --created-at RFC3339 --out-dir FRESH_DIR \
    [--beacon-lead-seconds N] [--allowed-binary FILE ...] \
    [--disable-optional-assurance]

Rehearsal commands create same-host test identities and must never be used as
production enrollment evidence.
`,
	"rehearsal init": `Usage:
  mpc-ceremony rehearsal init --created-at RFC3339 --out-dir FRESH_DIR \
    [--beacon-lead-seconds N] [--allowed-binary FILE ...] \
    [--disable-optional-assurance]

Creates fresh same-host identities and canonical configuration for exactly
three participants, then initializes a signed rehearsal-tiny-v1 ceremony. The
output is a functional test fixture, not production or independence evidence.
The beacon lead defaults to 300 seconds. --beacon-lead-seconds may shorten it
to at least 12 seconds for automated tests. The chosen value is signed into
the rehearsal definition. Production ceremonies configure the same field in
their policy JSON; production tooling should recommend 24 hours and clearly
warn before signing a shorter policy. With production witnesses enabled, the
close also reserves the fixed witness-observation window.
--disable-optional-assurance creates an explicit zero-witness, zero-mirror,
zero-ceremony-audit rehearsal while retaining future drand verification.
`,
	"inspect": inspectHelp + `
Authenticated record projections are also available as subcommands:
  mpc-ceremony inspect <definition|chain|participant|enrollment|checkpoint|checkpoint-transition> [flags]

These subcommands are read-only and machine-readable. They perform no network
access, replay, signing, or writes.
`,
	"inspect definition": `Usage:
  mpc-ceremony --format json inspect definition --ceremony FILE \
    --ceremony-signature FILE --coordinator-public-key-file KEY

Authenticates the exact canonical ceremony definition against the out-of-band
coordinator public key and reports its identity, mode, schedules, and circuit.
`,
	"inspect chain": `Usage:
  mpc-ceremony --format json inspect chain --ceremony FILE \
    --ceremony-signature FILE --coordinator-public-key-file KEY \
    --transcript-root DIR --chain FILE --chain-signature FILE

Authenticates the definition and accepted chain, validates the chain against
the frozen ceremony, and reports its records and digest-pinned artifacts. It
does not replay contribution payloads.
`,
	"inspect participant": `Usage:
  mpc-ceremony --format json inspect participant --ceremony FILE \
    --ceremony-signature FILE --coordinator-public-key-file KEY \
    --participant-signing-key KEY

Loads the existing Ed25519 private key with the hardened contribution-key
rules, derives only its public key, and matches it to exactly one identity in
the authenticated participant roster. Reports one-based phase schedule
positions, using null when the participant is absent. It performs no signing or
writes and never emits private-key bytes.
`,
	"inspect enrollment": `Usage:
  mpc-ceremony --format json inspect enrollment --ceremony FILE \
    --ceremony-signature FILE --coordinator-public-key-file KEY \
    --enrollment FILE --enrollment-signature FILE

Authenticates the exact canonical operational enrollment and its detached
proof-of-possession signature, then reports an immutable public projection of
the identity, role, role index, timestamp, and independence disclosure.
`,
	"inspect checkpoint": `Usage:
  mpc-ceremony --format json inspect checkpoint --ceremony FILE \
    --ceremony-signature FILE --coordinator-public-key-file KEY \
    --checkpoint FILE --checkpoint-signature FILE

Authenticates the exact canonical checkpoint against the independently trusted
ceremony definition and coordinator key. Reports the bounded workflow state,
submission slots, predecessor references, and artifact inventory. It does not
fetch or replay the protocol artifacts referenced by the checkpoint.
`,
	"inspect checkpoint-transition": `Usage:
  mpc-ceremony --format json inspect checkpoint-transition --ceremony FILE \
    --ceremony-signature FILE --coordinator-public-key-file KEY \
    --previous-checkpoint FILE --previous-checkpoint-signature FILE \
    --checkpoint FILE --checkpoint-signature FILE

Authenticates both exact signed checkpoints, verifies that the child binds the
exact parent record and detached signature, and enforces the legal structural
transition. It does not fetch or replay the protocol artifacts referenced by
that transition.
`,
	"checkpoint": `Usage:
  mpc-ceremony checkpoint <prepare|sign|verify|verify-stored> [flags]

Guarded storage-first checkpoint operations. Every operation re-authenticates
the exact signed definition, predecessor, both phase chains and all records
that cause the transition. The authenticated lifecycle runs from initialization
through both phases, the fully replayed final candidate, and the exact signed
release tree. Candidate acceptance and finalization replay the contribution
mathematics and cleanup evidence.
`,
	"submission": `Usage:
  mpc-ceremony submission <sign|accept> [flags]

Participant-authored storage-first submission envelopes. The exact slot is
selected only by its coordinator-preallocated attempt ID.
`,
	"submission accept": `Usage:
  mpc-ceremony submission accept [checkpoint evidence flags except acknowledgement] \
    --coordinator-signing-key KEY --out-dir FRESH_DIR

Replays the complete stored ancestry and the receipt or candidate evidence,
then creates the accepted acknowledgement and its descendant checkpoint as one
atomic four-file result. The coordinator key is loaded only after all untrusted
evidence passes verification. The acknowledgement is not acceptance by itself;
Relay must publish it only with the signed descendant checkpoint.
`,
	"submission sign": `Usage:
  mpc-ceremony submission sign --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --artifact-root DIR \
    --checkpoint FILE --checkpoint-signature FILE --attempt-id ID \
    --participant-signing-key KEY \
    (--receipt FILE --receipt-signature FILE | --candidate-dir DIR) \
    --out-dir FRESH_DIR

Authenticates the complete stored checkpoint ancestry, derives the exact
allocated slot, hashes only its fixed receipt or candidate payload inventory,
and atomically writes the participant-signed envelope pair. It does not create
or upload the transport manifest and never accepts a submission.
`,
	"checkpoint prepare": `Usage:
  mpc-ceremony checkpoint prepare --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --artifact-root DIR \
    --relay-release-id ID --transition KIND --chain FILE \
    --chain-signature FILE --head-payload FILE [transition flags] --out-dir DIR

Re-derives a canonical supported ceremony checkpoint from authenticated evidence and
writes canonical.json plus signing-request.json to a fresh directory.

For phase1-outbound-published also supply the previous checkpoint pair, signed
outbound handoff pair, --attempt-id, and --manifest-key. For
phase1-receipt-accepted supply the previous checkpoint pair, signed submission
envelope pair, signed acknowledgement pair, exact --manifest,
--next-attempt-id, and --next-manifest-key.

For phase1-candidate-accepted supply the previous checkpoint pair, fully
verified next chain and head payload, candidate envelope pair, accepted
acknowledgement pair, and exact manifest. Attempt scope is derived from the
preallocated candidate slot.

For phase1-closed supply the previous checkpoint pair and signed Phase 1 close
record pair. For phase1-beacon-recorded supply the previous checkpoint pair
and signed Phase 1 beacon record pair; the raw response named by the beacon
record must exist under the artifact root.

For phase1-sealed supply the previous checkpoint pair and signed Phase 1 seal
record pair. Relay fully replays Phase 1 and requires the exact commons.bin
named by that seal under the artifact root.

Phase 2 uses the corresponding --phase2-* inputs. For
final-candidate-recorded supply the canonical --candidate-dir final/candidate.
For final-release-recorded supply the canonical --release-dir final/release;
the complete release, including operational evidence and any required audits,
is strictly verified and closed against extra files.
`,
	"checkpoint sign": `Usage:
  mpc-ceremony checkpoint sign [all checkpoint prepare evidence flags] \
    --checkpoint FILE --signing-request FILE \
    --coordinator-signing-key KEY --out FRESH_FILE

Re-derives the checkpoint from all exact evidence, requires byte-for-byte
agreement with the reviewed checkpoint and signing request, checks that the
private key belongs to the authenticated coordinator, then signs it.
`,
	"checkpoint verify": `Usage:
  mpc-ceremony --format json checkpoint verify \
    [all checkpoint prepare evidence flags] \
    --checkpoint FILE --checkpoint-signature FILE

Re-derives and authenticates the signed checkpoint and all transition-defining
evidence within the supported lifecycle boundary. Its JSON projection sets fully_verified
only after those checks pass. Structural inspect checkpoint output must not be
used to advance Relay's trusted high-water state.
`,
	"checkpoint verify-stored": `Usage:
  mpc-ceremony --format json checkpoint verify-stored \
    --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --artifact-root DIR \
    --checkpoint FILE --checkpoint-signature FILE

Walks the fetched checkpoint ancestry and derives every evidence path and
transition input from the authenticated checkpoints themselves. Every
supported ceremony edge is fully re-derived through the signed final release;
candidate acceptance and finalization replay contribution mathematics and
cleanup, while closure and beacon validation use the exact authenticated head
and raw beacon response.
Only this command (or checkpoint verify with explicit evidence) emits
fully_verified=true. Structural inspect output is diagnostics-only.
`,
	"init": `Usage:
  mpc-ceremony init --key-version ownership-destination-v2 \
    --participants ROSTER.json --policy POLICY.json \
    --coordinator-key-id ID --coordinator-signing-key KEY \
    --created-at RFC3339 --out-dir DIR [--mode rehearsal|production] \
    [--session-nonce-hex HEX] [--allowed-binary FILE ...]

Compiles a registered repository circuit and writes a fresh signed ceremony
definition. The authoritative ceremony ID is derived from canonical content,
including a 32-byte session nonce securely generated when omitted. Production
mode requires exact clean source builds. The running binary is always allowed;
each repeated --allowed-binary adds one authenticated binary for another
platform to the signed definition.
`,
	"phase1": `Usage:
  mpc-ceremony phase1 <contribute|attest-erasure|verify|close|beacon|seal> [flags]

Phase 1 is sequential and append-only. Contributors and coordinators must name
the exact accepted chain; the command never discovers a "latest" state.
`,
	"phase1 contribute": `Usage:
  mpc-ceremony phase1 contribute --ceremony FILE \
    --ceremony-signature FILE --coordinator-public-key-file KEY \
    --transcript-dir DIR --chain FILE --chain-signature FILE \
    --participant-id ID --participant-signing-key KEY \
    --environment FILE --contributed-at RFC3339 --out-dir FRESH_DIR

Replays the complete accepted phase 1 chain before adding OS-generated
randomness. The input chain is never modified.
`,
	"phase1 attest-erasure": `Usage:
  mpc-ceremony phase1 attest-erasure --ceremony FILE \
    --ceremony-signature FILE --coordinator-public-key-file KEY \
    --participant-id ID --participant-signing-key KEY \
    --candidate-dir DIR --destroyed-at RFC3339

Writes erasure.json and its participant signature into the candidate directory
without replacing existing files. This is an operational attestation, not
technical or cryptographic proof that contribution randomness was erased.
Sign only after the contributor process has terminated, its ephemeral
environment was removed, and the participant confirmed no deliberate copies.
Host/VM remnants are explicitly not excluded by this statement.
`,
	"phase1 verify": `Usage:
  mpc-ceremony phase1 verify --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --transcript-dir DIR --chain FILE \
    --chain-signature FILE --candidate-dir DIR \
    --coordinator-signing-key KEY --accepted-at RFC3339

Authenticates the signed chain and candidate evidence, verifies the candidate
transition directly from the accepted native head, then appends immutable
numbered artifacts and a new signed chain record. Participant contribution and
phase close perform the independent full-prefix replays.
`,
	"phase1 close": `Usage:
  mpc-ceremony phase1 close --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --transcript-dir DIR --chain FILE \
    --chain-signature FILE --coordinator-signing-key KEY \
    --beacon-round N | --beacon-round-lead SECONDS

Replays the full phase, derives the exact Quicknet schedule from the round,
samples closed_at inside the core after replay, and atomically publishes the
signed closure only while the policy lead still holds.

At K=21 the replay takes hours, so --beacon-round asks you to predict it: a
round named too near is already public when the closure is written and the
whole replay is discarded. --beacon-round-lead instead derives the round from
the clock sampled after the replay, at least SECONDS ahead and never below the
signed witness lead. The round is not published or observable until the closure
record is written either way, so deriving it later commits to nothing sooner.
`,
	"phase1 beacon": `Usage:
  mpc-ceremony phase1 beacon --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --closure FILE \
    --closure-signature FILE --raw-response FILE --published-at RFC3339 \
    --coordinator-signing-key KEY --transcript-dir DIR

Cryptographically verifies an archived pinned drand quicknet response and
derives the protocol challenge from its signature. The command performs no
network fetch and accepts neither randomness nor a challenge from the operator.
`,
	"phase1 seal": `Usage:
  mpc-ceremony phase1 seal --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --transcript-dir DIR --closure FILE \
    --closure-signature FILE --beacon FILE --beacon-signature FILE \
    --coordinator-signing-key KEY --out-dir FRESH_DIR

The beacon is supplied as offline evidence and must satisfy the signed policy
and postdate the signed closure.
`,
	"phase2": `Usage:
  mpc-ceremony phase2 <init|contribute|attest-erasure|verify|close|beacon> [flags]

Phase 2 is bound to the exact compiled R1CS and verified phase 1 seal.
`,
	"phase2 init": `Usage:
  mpc-ceremony phase2 init --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --phase1-transcript-dir DIR \
    --phase1-seal FILE --phase1-seal-signature FILE \
    --coordinator-signing-key KEY --out-dir FRESH_DIR
`,
	"phase2 contribute": `Usage:
  mpc-ceremony phase2 contribute --ceremony FILE \
    --ceremony-signature FILE --coordinator-public-key-file KEY \
    --phase1-seal FILE --phase1-seal-signature FILE \
    --transcript-dir DIR --chain FILE --participant-id ID \
    --chain-signature FILE --participant-signing-key KEY \
    --environment FILE --contributed-at RFC3339 --out-dir FRESH_DIR
`,
	"phase2 attest-erasure": `Usage:
  mpc-ceremony phase2 attest-erasure --ceremony FILE \
    --ceremony-signature FILE --coordinator-public-key-file KEY \
    --participant-id ID --participant-signing-key KEY \
    --candidate-dir DIR --destroyed-at RFC3339

Signs the participant's Phase 2 logical-cleanup attestation. Host/VM remnants
are explicitly not excluded; confirm cleanup precautions before signing. The
statement is auditable evidence, not proof that secret randomness was erased.
`,
	"phase2 verify": `Usage:
  mpc-ceremony phase2 verify --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --phase1-seal FILE \
  --phase1-seal-signature FILE --transcript-dir DIR --chain FILE \
  --chain-signature FILE --candidate-dir DIR \
  --coordinator-signing-key KEY --accepted-at RFC3339

Authenticates the signed chain, Phase 1 seal, and candidate evidence; verifies
the candidate transition directly from the accepted native Phase 2 head; then
appends immutable numbered artifacts and a new signed chain record.
Participant contribution and phase close retain independent full replays.
`,
	"phase2 close": `Usage:
  mpc-ceremony phase2 close --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --phase1-seal FILE \
    --phase1-seal-signature FILE --transcript-dir DIR --chain FILE \
    --chain-signature FILE --coordinator-signing-key KEY \
    --beacon-round N | --beacon-round-lead SECONDS

Replays the full phase, derives the exact Quicknet schedule from the round,
samples closed_at inside the core after replay, and atomically publishes the
signed closure only while the policy lead still holds.

At K=21 the replay takes hours, so --beacon-round asks you to predict it: a
round named too near is already public when the closure is written and the
whole replay is discarded. --beacon-round-lead instead derives the round from
the clock sampled after the replay, at least SECONDS ahead and never below the
signed witness lead. The round is not published or observable until the closure
record is written either way, so deriving it later commits to nothing sooner.
`,
	"phase2 beacon": `Usage:
  mpc-ceremony phase2 beacon --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --closure FILE \
    --closure-signature FILE --raw-response FILE --published-at RFC3339 \
    --coordinator-signing-key KEY --transcript-dir DIR

Records the distinct Phase 2 post-closure beacon evidence used by finalize.
`,
	"finalize": `Usage:
  mpc-ceremony finalize prepare [FLAGS]
  mpc-ceremony finalize complete [FLAGS]
`,
	"finalize rehearsal-evidence": `Usage:
  mpc-ceremony finalize rehearsal-evidence --keys-dir DIR \
    --coordinator-public-key-file FILE --ceremony-id ID --out FILE

Authenticates preliminary keys and checks the exact supported tiny circuit.
Generates and verifies a real proof using public golden inputs. Never accepts
wallet material, overwrites evidence, or produces a production ownership proof.
`,
	"finalize prepare": `Usage:
  mpc-ceremony finalize prepare --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY [REPLAY EVIDENCE FLAGS] \
    --coordinator-signing-key KEY --prepared-at RFC3339_UTC \
    --out-dir FRESH_DIR
` + replayFlagsHelp + `

Independently compiles the circuit named by the signed ceremony definition
(ownership-destination-v2 in production, rehearsal-tiny-v1 in a rehearsal),
replays both phases, and publishes a coordinator-signed preliminary native
PK/VK tree. It is not a candidate and cannot be audited or released.
`,
	"finalize complete": `Usage:
  mpc-ceremony finalize complete --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY [REPLAY EVIDENCE FLAGS] \
    --coordinator-signing-key KEY --public-evidence FILE \
    --finalized-at RFC3339_UTC --out-dir FRESH_DIR
` + replayFlagsHelp + `

Replays both phases again, verifies the canonical external public proof
against the replayed final VK, and creates the coordinator-signed but
unsigned-for-release candidate. It accepts only the public evidence artifact.
Release signing remains a separate post-audit step.
`,
	"replay": `Usage:
  mpc-ceremony replay --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY [REPLAY EVIDENCE FLAGS] \
    --candidate-bundle DIR
` + replayFlagsHelp + `
Independently compiles the signed circuit and replays both phases, checking
randomness, final native keys, Cardano export and public proof evidence.
Requires no private key and writes no signed audit. Release signatures and
production approval are checked separately with release verify and decision verify.
`,
	"audit": `Usage:
  mpc-ceremony audit --ceremony FILE \
    --ceremony-signature FILE --coordinator-public-key-file KEY \
    [REPLAY EVIDENCE FLAGS] --candidate-bundle DIR \
    --auditor-id ID --auditor-signing-key KEY --audited-at RFC3339_UTC \
    --out FRESH_FILE --audit-signature FRESH_FILE
` + replayFlagsHelp + `

Audit always independently compiles the circuit and performs the full
two-phase replay. It emits a signed passing record only after reproducing the
candidate's native keys, Cardano export, and coherence evidence.
`,
	"release": `Usage:
  mpc-ceremony release <sign|verify> [flags]

Release authenticity is separate from MPC contribution identity.
`,
	"release sign": `Usage:
  mpc-ceremony release sign --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --candidate-bundle DIR \
	    [--audit-report FILE --audit-signature FILE]... \
	    --operational-evidence-root DIR \
	    --operational-bundle DIR/operational/evidence-bundle.json \
	    --operational-bundle-signature DIR/operational/evidence-bundle.sig \
	    --release-signing-key KEY --signature-key-id ID \
    --released-at RFC3339_UTC --release-dir FRESH_DIR
` + replayFlagsHelp + `

	Requires at least the signed minimum number of passing ceremony audits
	assurance policy, plus the coordinator-signed Phase 1 and Phase 2 operational
	bundle. Witness and mirror evidence likewise follows that signed policy;
	multi-relay beacon evidence remains required. The candidate is
	never mutated; all verified evidence is atomically published into a fresh
	release directory. For current ceremonies, the release signer independently
	replays both phases even when the signed audit minimum is zero.
`,
	"release verify": `Usage:
  mpc-ceremony release verify --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --keys-dir DIR \
    --manifest-public-key-file KEY --signature-key-id ID

Authenticates the release using the out-of-band release public key, then
strictly verifies the bundled audit evidence, transcript, native keys, Cardano
export, candidate signature, and checksums.
`,
	"decision": `Usage:
  mpc-ceremony decision <prepare|sign|verify> [flags]

Production decisions are canonical content-addressed records. The command
never fetches evidence URIs and never infers independence, host integrity,
entropy quality, erasure, public witnessing, mirrors, or attendance.
`,
	"decision prepare": `Usage:
  mpc-ceremony decision prepare --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --draft FILE --out FRESH_FILE \
    [--evidence-root DIR]

Strictly parses a production decision draft matching the authenticated
ceremony schema, derives
the release_id and decision_id, and checks ceremony, source, exact K=21
circuit, and signer-role bindings. The fresh output is the only byte string
the accountable roles should sign.
Definition V4 requires --evidence-root and verifies its complete local release
package and decision evidence before writing. Keep --out outside final/release.
Older definitions do not accept this preparation flag.
`,
	"decision sign": `Usage:
  mpc-ceremony decision sign --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --decision FILE \
    --evidence-root DIR \
    --role coordinator|auditor|release_signer --signer-id ID \
    --signing-key KEY --out FRESH_FILE

Signs the exact canonical decision bytes with one enrolled ceremony identity.
A GO record requires the coordinator, every auditor named by the record,
and the distinct release signer to sign the same bytes — one signature per
named auditor, so a ceremony with three auditors needs five signatures. Before loading a GO
signing key, the command hashes and semantically verifies the full local
evidence set. Definition V4 requires verified evidence for both GO and post-package
NO-GO; use the authenticated abort procedure for an earlier stop without a package.
Keep --out outside final/release. Older definitions retain optional evidence
verification for NO-GO records reporting unavailable evidence.
`,
	"decision verify": `Usage:
  mpc-ceremony decision verify --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --decision FILE \
    --signature FILE [--signature FILE ...] \
    --evidence-root DIR

Strictly parses the record and detached role signatures, hashes every local
evidence artifact, checks release/candidate/transcript/operational/audit
coherence. GO requires every applicable gate to PASS and signatures from the
coordinator, release signer and every required ceremony auditor. Disabled optional
gates must explicitly be NOT_REQUIRED. V4 evidence uses local logical names;
legacy evidence URIs are content bindings only. No network fetch or publication
occurs. Verification of external reports binds reviewed claims, not independent
proof that the reported real-world actions happened.
`,
	"ops": `Usage:
  mpc-ceremony ops <prepare-public-witness-receipt|prepare-mirror-receipt|export-signing|import-signature|verify> [flags]

Operational records cover proof-of-possession enrollment, transfers and
receipts, immutable mirrors, pre-beacon public witnesses, multi-operator relay
evidence, governance events, and the release-bound operational evidence bundle.
`,
	"ops prepare-public-witness-receipt": `Usage:
  mpc-ceremony ops prepare-public-witness-receipt \
    --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --transcript-root DIR \
    --closure FILE --closure-signature FILE \
    --witness-enrollment FILE --witness-enrollment-signature FILE \
    --publication-location URI --observed-at RFC3339_UTC \
    --out-dir FRESH_DIR

Authenticates the ceremony, coordinator-signed closure, and public-witness
proof-of-possession enrollment. It validates the human-claimed observation
against the signed closure and beacon schedule, hashes the publication location,
and exports canonical.json plus signing-request.json for offline review and
signing. The program validates coherence; it does not claim to have observed
publication itself and never reads the witness private key.
`,
	"ops prepare-mirror-receipt": `Usage:
  mpc-ceremony ops prepare-mirror-receipt --draft FILE \
    --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --transcript-root DIR \
    --chain FILE --chain-signature FILE \
    --mirror-enrollment FILE --mirror-enrollment-signature FILE \
    --out-dir FRESH_DIR

Authenticates the exact accepted chain prefix and the mirror operator's signed
proof-of-possession enrollment, recomputes every receipt file reference, and
requires the relay draft to match. It then exports canonical.json and
signing-request.json without reading a private signing key.
`,
	"ops prepare-enrollment": `Usage:
  mpc-ceremony ops prepare-enrollment --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --identity PUBLIC_IDENTITY_JSON \
    --role ROLE [--role-index N] --disclosure PUBLIC_TEXT_FILE \
    --enrolled-at RFC3339 --out-dir FRESH_DIR

Derives the canonical enrollment from the authenticated definition and the
owner's public identity and disclosure. Internal role indices are derived;
external witness/mirror indices are assigned through the coordination channel.
No private key is read. Share the entire public export with the disclosure.
`,
	"ops prepare-handoff": `Usage:
  mpc-ceremony ops prepare-handoff --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --transcript-root DIR \
    --chain FILE --chain-signature FILE --participant-id ID \
    --direction outbound|return [--candidate-dir DIR] --out-dir FRESH_DIR

Derives the next turn from the signed current chain. Outbound names its input;
return hashes the completed candidate including cleanup acknowledgment. Creates
an unsigned canonical packet with the actual current time and one-hour expiry.
Review and sign before sending. Preserve an existing packet instead of overwriting
it. A late-created handoff cannot replace a missing earlier custody event.
`,
	"ops prepare-receipt": `Usage:
  mpc-ceremony ops prepare-receipt --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --transcript-root RECEIVED_FILES_ROOT \
    --handoff FILE --handoff-signature FILE --sender-public-key-file KEY \
    --out-dir FRESH_DIR

First receive the exact named public files into their logical paths under the
received-files root. Verifies the sender signature and every received file digest,
then prepares a receipt at the actual current time. Review and sign it as the
named recipient. No network transfer or physical-air-gap claim is made.
`,
	"ops sign": `Usage:
  mpc-ceremony ops sign --record-type TYPE --record CANONICAL_FILE \
    --ceremony FILE --ceremony-signature FILE --coordinator-public-key-file KEY \
    --signing-key OWN_KEY_FILE --reviewed [--reviewed-sha256 HEX] --out FRESH_SIGNATURE_JSON

Offline owner signing for enrollment, public-witness, mirror-receipt, handoff,
receipt, beacon-evidence and evidence-bundle records.
Bundle signing additionally requires --evidence-root DIR and verifies every
referenced operational record before reading the coordinator’s signing key.
Authenticates the ceremony, canonical record and owner key. Review the exact
record and associated disclosure/observations before --reviewed. This signs
your claim; it does not independently observe publication or prove independence.
Enrollment signing requires its matching disclosure tree beside the record.
The reviewed hash binds signing to bytes previously shown by a helper. It is
required for handoff, receipt, beacon-evidence and evidence-bundle signing.
Run ops verify afterwards; receipts require --related-record and bundles require
--evidence-root. A signature alone does not verify a complete ceremony.
`,
	"ops prepare-bundle": `Usage:
  mpc-ceremony ops prepare-bundle --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --evidence-root PUBLIC_DIR \
    --out-dir PUBLIC_DIR/operational

Discovers bounded public JSON and signatures; never point it at private keys or
credentials. Reports missing or conflicting evidence by phase and turn. Keep
original relative paths when collecting public records from their owners.
The operational directory may exist; existing evidence is preserved. Bundle,
signature and signing-request files must not already exist. Interrupted output
is retained for inspection, never automatically overwritten.
Witness and mirror requirements come from the authenticated ceremony
definition; the operator cannot weaken them to fit the available evidence.
If complete, independently verifies all referenced evidence and exports an
UNSIGNED canonical bundle and signing request. It does not invent records,
backdate observations, or sign for other roles. Release still requires the
coordinator's bundle signature and successful signed-bundle verification.
`,
	"ops export-signing": `Usage:
  mpc-ceremony ops export-signing --record-type TYPE --record FILE \
    --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --out-dir FRESH_DIR

Strictly verifies the canonical record and ceremony binding, then exports
canonical.json and signing-request.json. No private signing key is read.
`,
	"ops import-signature": `Usage:
  mpc-ceremony ops import-signature --record-type TYPE --canonical FILE \
    --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --signer-public-key-file KEY \
    --raw-signature FILE --out FRESH_FILE

Accepts 64 raw signature bytes or 128 lowercase hex characters, verifies the
offline Ed25519 signature over exact canonical bytes and signer identity, then
writes the repository detached-signature format without replacement.
`,
	"ops verify": `Usage:
  mpc-ceremony ops verify --record-type TYPE --record FILE --signature FILE \
    --ceremony FILE --ceremony-signature FILE \
    --coordinator-public-key-file KEY --signer-public-key-file KEY \
    [--related-record HANDOFF] [--evidence-root DIR]

Authenticates canonical bytes, immutable ceremony fields, enrolled signer, and
detached signature. Receipt verification requires the exact related handoff.
Evidence-bundle verification requires the complete local evidence root and
validates both authenticated chains, every custody transfer, independent
mirrors and public witnesses, and at least two distinct beacon relay operators.
`,
}
