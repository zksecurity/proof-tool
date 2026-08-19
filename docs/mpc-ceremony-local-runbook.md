# MPC Ceremony — Local Runbook

Everything below was executed against the working tree at `ba065e6` and the
outputs are the real ones, not illustrative.

## Scope

This is an orientation and rehearsal runbook: how to build the tool, stand up a
ceremony on one machine, and read what comes out. It is **not** a production
procedure.

The production procedure is `docs/mpc-ceremony-runbook.md` (1,590 lines), which
is currently absent from `main`; it was removed by a history-filtering rewrite.
It survives in `refs/pull/34/head` of `Anastasia-Labs/proof-tool` at commit
`fd8516e`. Anything about enrollment, custody, witnessing, mirrors, beacon
selection, or release gates comes from that document, not this one.

Same-host identities prove nothing about participant independence. A rehearsal
transcript is never mainnet key material.

## The two roots of trust

Every other file in a ceremony is derived and self-authenticating. Exactly two
things must reach you through channels you already trust.

**1. The coordinator public key.** `coordinator-public-key.hex` decides whether a
signature counts. Take it from the same bundle as the signature it verifies and
you have proven only that the bundle agrees with itself — which any forger can
arrange. It must arrive over an independent authenticated channel.

**2. The binary.** `SoftwareBinding` in the definition pins the tool digest,
source commit, and dependency versions; `VerifyRunningSoftware` refuses to
proceed on a mismatch. So the binary is a trust input too: built from a verified
signed tag, reproduced in two independent environments, hashes published
separately. `scripts/build-mpc-ceremony-release.sh` and
`scripts/verify-mpc-ceremony-reproducible.sh` do this for production. Maintainers
publish the directly downloadable binary and its full verification package by
following `docs/mpc-ceremony-release.md`.

Everything else — `ceremony.json`, `ceremony.sig`, chains, contributions,
closures — may travel over untrusted transport. Tampering makes verification
fail rather than succeed.

## Trust paths

Nearly every subcommand takes the same three flags, which map to
`mpcceremony.TrustPaths` (`internal/mpcceremony/workflow.go:46`):

    --ceremony                    ceremony.json
    --ceremony-signature          ceremony.sig
    --coordinator-public-key-file coordinator-public-key.hex

All three are mandatory (`workflow.go:180-184`). `LoadSignedDefinition` turns
them into a `TrustedCeremony`, and every downstream check validates against that
rather than against loose files. The third path exists specifically so the trust
anchor is supplied from outside the bundle. The code cannot tell whether you
honoured that; only your process can.

## Prerequisites

Go 1.26.5 exactly, per `go.mod` and the pinned `ProductionGoVersion` in
`internal/mpcceremony/model.go`. A user-local install is fine:

    export PATH="$HOME/.local/go/bin:$PATH"
    go version   # go1.26.5 linux/amd64

**Build with `go build`, never `go run`.** `go run` does not embed VCS metadata,
and the binary refuses to start without it:

    running executable is missing vcs build setting

`software.go:172-205` requires `vcs`, `vcs.revision` and `vcs.modified`.
`vcs.revision` becomes the ceremony's `source_commit`, which every contribution
attestation must match; `vcs.modified` must be `false` for production, so a
dirty checkout is refused outright. Inspect any binary with
`go version -m ./dist/mpc-ceremony`.

## Quick start

    bash scripts/mpc-demo-init.sh /tmp/mpcdemo 3

That wrapper does the three steps below and refuses to reuse an existing root.
The manual form follows, because the wrapper hides the parts worth understanding.

### 1. Build

    go build -o dist/mpc-ceremony ./cmd/mpc-ceremony
    ./dist/mpc-ceremony help

### 2. Generate rehearsal identities and canonical config

    go run ./scripts/mpc-rehearsal-config --out-dir /tmp/mpcdemo --participants 3

Writes `config/{participants,policy,environment}.json` plus Ed25519 keypairs for
eleven identities at three participants: coordinator, release signer, two
auditors, three participants, two public witnesses, two mirror operators.

These config files are **canonical JSON**, not ordinary JSON. The decoder rejects
unknown fields, duplicate fields, reordered fields, pretty printing, extra
whitespace, trailing data, and a trailing newline. Do not hand-edit them and do
not round-trip them through `jq -S`; alphabetical key sorting changes the schema
order and the file stops parsing. Generate them with a program that calls
`MarshalCanonical`.

### 3. Initialize

    D=/tmp/mpcdemo
    ./dist/mpc-ceremony --format json init \
      --key-version ownership-destination-v2 \
      --participants "$D/config/participants.json" \
      --policy "$D/config/policy.json" \
      --coordinator-key-id coordinator-key \
      --coordinator-signing-key "$D/keys/coordinator.ed25519.private.hex" \
      --created-at 2026-08-11T00:00:00Z \
      --mode rehearsal \
      --out-dir "$D/public"

`--coordinator-key-id` must equal the `key_id` inside `participants.json`. It is
not a name you choose. Read it back rather than guessing:

    python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["coordinator"]["key_id"])' \
      "$D/config/participants.json"

Expect several minutes; `init` compiles the K=21 circuit. Observed output:

    {"level":"info","message":"compiling circuit"}
    {"nbSecret":157,"nbPublic":1,"message":"parsed circuit inputs"}
    {"nbConstraints":1791413,"message":"building constraint builder"}
    {"schema":"proof-tool-mpc-command-result-v1","ok":true,"command":"init",
     "ceremony_id":"sha256:965b04d8...520e", ... }

## The seven artifacts

           4608  ceremony.json
            434  ceremony.sig
             65  coordinator-public-key.hex
      129448055  ownership-destination.ccs
            490  phase1/chain-0000.json
            434  phase1/chain-0000.sig
      603980121  phase1/genesis.bin

**`ceremony.json`** — the signed root document. Its `ceremony_id` is a
domain-tagged SHA-256 over its own canonical bytes, so the file names itself.
Contains the circuit binding (1,791,413 constraints, domain 2,097,152 = 2^21, the
R1CS digest), the pinned software stack, the roster, per-phase policies, and the
drand beacon policy. Also a `session_nonce_hex` so two ceremonies with identical
inputs still receive distinct IDs.

**`ceremony.sig`** — detached Ed25519 signature over the exact bytes of
`ceremony.json`. Carries `signed_sha256`, so the signature names what it covers,
plus `key_id` and `public_key_fingerprint`.

**`coordinator-public-key.hex`** — the raw 32-byte public key in hex. Trust root;
distribute out of band.

**`ownership-destination.ccs`** — the compiled constraint system. Makes the
ceremony circuit-specific: Phase 2 is built from it, and its digest is pinned in
`ceremony.json`, so a different circuit is a different ceremony.

**`phase1/genesis.bin`** — the starting powers-of-tau state, 576 MiB. The first
432 bytes are three empty update proofs (tau, alpha, beta); the real ladder
begins at offset 432 with a length prefix of `0x200000` = 2,097,152. Points are
compressed, and `0xc0` in a leading byte means "compressed, point at infinity".

**`phase1/chain-0000.json`** — the empty chain: `"records": []`, plus `phase_id`
and the genesis `ArtifactRef` pinning that 576 MiB file by both digests and its
size. This is the head the first participant contributes on top of.

**`phase1/chain-0000.sig`** — coordinator signature over that chain document.

Note the split: two files hold all 705 MB of data, five hold all the authority in
about 6 KB. The large files are inert until a signed record names them by digest.

## Verifying what you got

The signature names its own key and its own payload. Both bindings should check
out:

    python3 - <<'EOF'
    import hashlib, json
    D = "/tmp/mpcdemo/public"
    pk = open(f"{D}/coordinator-public-key.hex").read().strip()
    sig = json.load(open(f"{D}/ceremony.sig"))
    print("key fingerprint :", "sha256:" + hashlib.sha256(bytes.fromhex(pk)).hexdigest())
    print("claimed in sig  :", sig["public_key_fingerprint"])
    print("signed_sha256   :", sig["signed_sha256"])
    print("actual of json  :", "sha256:" + hashlib.sha256(open(f"{D}/ceremony.json","rb").read()).hexdigest())
    EOF

This proves internal consistency only. It becomes meaningful when the public key
came from an independent channel.

## Gotchas encountered

- `go run` fails with `missing vcs build setting`. Use `go build`.
- `--coordinator-key-id` must match `participants.json`. A wrong value produces
  a redacted error that blanks your input but leaves the correct value visible,
  because that came from a file rather than argv.
- `scripts/mpc-demo-init.sh` refuses an existing root. Use a fresh path.
- The full rehearsal harness refuses to start below its capacity floors — 100 GiB
  free and 16 GiB available RAM by default. Check with
  `scripts/check-mpc-k21-capacity.sh`, override via `MPC_K21_MIN_*` env vars.
- Config files are canonical JSON. Editing them by hand breaks parsing.

## Beyond init

The next step is `phase1 contribute` for the first scheduled participant, which
replays the entire accepted chain before sampling entropy. At K=21 with three
participants that is gigabytes of I/O and hours of verification. Replay
progress is reported on stderr so running can be told apart from hung.

For a staged, resumable local run through the whole lifecycle, use the real
harness instead of driving the CLI by hand:

    scripts/run-mpc-k21-local-rehearsal.sh prepare "$FRESH_ROOT" ./dist/mpc-ceremony 5
    scripts/run-mpc-k21-local-rehearsal.sh phase1-contribute "$FRESH_ROOT" ./dist/mpc-ceremony
    scripts/run-mpc-k21-local-rehearsal.sh phase1-close "$FRESH_ROOT" ./dist/mpc-ceremony FUTURE_ROUND
    ...

It never fetches a beacon. The operator closes each phase on a future drand
round, publicly witnesses the closure, waits for that round, obtains the exact
raw response independently, and resumes. That sequencing is the security
property, not a formality: see the 2026-07-24 closure-timing incident recorded in
`docs/mpc-production-readiness.md`.

## Beacon precedent in other ceremonies

How the drand-quicknet-with-future-round design compares to other trusted-setup
implementations (surveyed 2026-08-11):

- **Celo snark-setup-operator (Plumo)** — yes, drand mainnet, pre-announced
  future round (923709, ~June 8 2021). `verify_transcript --apply-beacon` seeds
  an RNG from the 32-byte beacon hash, runs an actual contribution, then
  re-verifies it against the transcript
  ([verify_transcript.rs](https://github.com/celo-org/snark-setup-operator/blob/master/src/bin/verify_transcript.rs),
  [celo-bls-snark-rs #220](https://github.com/celo-org/celo-bls-snark-rs/issues/220)).
  Mechanically the closest precedent to this design.
- **Perpetual Powers of Tau** — yes, applied per phase-2 branch-off rather than
  once: announce a future Ethereum beacon-chain slot, take its RANDAO reveal,
  apply via `snarkjs powersoftau beacon … 31` (2^31 hash iterations)
  ([prepare-phase-2.md](https://github.com/privacy-ethereum/perpetualpowersoftau/blob/master/prepare-phase-2.md)).
  The doc itself notes "experts differ as to whether the beacon step adds any
  security" but snarkjs requires it.
- **p0tion (PSE)** — yes at finalization, but weakest: the coordinator types a
  beacon value into a prompt, which is SHA-256'd and applied via `zKey.beacon`
  with only 2^10 iterations; no drand, block hash, or future-round binding
  anywhere in the repo
  ([finalize.ts](https://github.com/privacy-ethereum/p0tion/blob/main/packages/phase2cli/src/commands/finalize.ts),
  [prompts.ts:705](https://github.com/privacy-ethereum/p0tion/blob/main/packages/phase2cli/src/lib/prompts.ts)).

The pattern comes from Zcash's 2018 Powers of Tau — 2^42 SHA-256 iterations over
the hash of Bitcoin block 514200, pre-announced
([attestation 0088](https://github.com/ZcashFoundation/powersoftau-attestations/tree/master/0088)).
The "beacon is unnecessary" claim traces to the Snarky Ceremonies paper
([eprint 2021/219](https://eprint.iacr.org/2021/219.pdf),
Kohlweiss/Maller/Siim/Volkhov, Asiacrypt 2021), which proved Groth16 ceremony
security without a beacon — yet all three implementations above still apply one
as defense-in-depth. This project's drand-quicknet-with-future-round design is
in line with the field and stricter than p0tion, roughly matching Plumo.
