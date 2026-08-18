# MPC Ceremony — Attack/Defense Inventory

The deliberate security defenses in `internal/mpcceremony` and its CLI, each
mapped to the attack it counters, with code anchors (line numbers drift; treat
them as anchors, not guarantees). Known gaps at the end. Consumer-package
hardening (prover, wasm, streampk, proofassets) is tracked separately in the
"untrusted decode" PR.

## The five ideas (ELI5)

The ceremony is a group taking turns stirring secret ingredients into a shared
pot; the result is safe if one ingredient stays secret and nobody swaps the pot
unwatched. Almost every defense below is one of five ideas:

1. **Never trust a label — check the contents.** Everything carries a hash,
   recomputed at every use, not once.
2. **Never trust a path.** Look before opening, open, look again — symlinks and
   mid-read swaps are caught.
3. **Write once, never overwrite.** History is append-only and hash-chained;
   publishing is create-only-if-absent.
4. **One person can't cheat alone.** Distinct keys per role, multiple
   sign-offs, randomness from a public beacon fixed in the future.
5. **Assume every input is hostile.** One canonical form, exact lengths, sane
   bounds; two encodings of "the same" thing is an attack.

## 1 · Filesystem

- Symlink swap: `Lstat` + `ModeSymlink` rejection before every read
  (`files.go` `openRegularExact`, `workflow.go` `readRegularBounded`,
  publication/audit/decision walks); per-component parent check
  (`rejectSymlinkComponents`).
- TOCTOU: `os.SameFile` after open, size stability during hash, trailing-byte
  read after (`workflow.go`, `publication.go`, `keybundle`).
- Path traversal: clean-relative-name validation (`validateArtifactName`),
  `filepath.Rel` containment (`resolveArtifactPath`), stdin/URL rejection at
  the CLI.
- Overwrite/rollback: `O_EXCL`, hard-link publish, `RENAME_NOREPLACE`,
  retry only against byte-identical existing state (`requireAbsentOrExact`);
  signature published before its record; fsync with re-validating recovery.
- Permissions: 0600 files, 0700 dirs, group/world bits rejected; directory
  member allowlists.
- Exhaustion: size caps everywhere (16 GiB artifacts, 16 MiB records, 1 MiB
  drand, 4 KiB keys, 100k-entry trees).

## 2 · Cryptographic

- Forged records: Ed25519 over exact bytes before parsing; out-of-band
  coordinator anchor; `KeyID` untrusted until the bytes authenticate
  (`attestation.go` `VerifyExact`, `workflow.go` `LoadSignedDefinition`).
- Unusable identity keys: canonical-encoding and small-order rejection via
  `filippo.io/edwards25519` (`validateEd25519PublicKey`) — a small-order key
  verifies signatures for any message.
- Key substitution: fingerprint re-derived on load; private key must match the
  enrolled identity.
- Artifact substitution: dual SHA-256+BLAKE2b+size pinning, re-hashed at every
  use; R1CS digested before native decode; running binary digest-matched to
  the signed definition on every command.
- Encoding equivalence: decoded gnark objects re-serialized and required
  byte-identical (`requireCanonicalRoundTrip`).
- Invalid points: BLS12-381 compressed-flag check (`preflight.go`); gnark
  subgroup checks on by default on the ceremony path.
- Context confusion: per-record-type domain tags + `0x00` separator; beacon
  challenge uses length-prefixed tuple encoding; content-addressed record IDs
  recomputed everywhere.
- Rigged beacon: drand quicknet chain/key/scheme pinned in the signed
  definition; randomness derived from the verified BLS signature, never
  operator-supplied.
- Broken verifier: finalization requires the verifier to *reject* seven
  tampered variants (negative controls, `finalize.go`).
- Mutation aliasing: archived inputs cloned before gnark's mutating
  `Verify`/`Seal` (`streamClone`; acceptance path verifies a throwaway clone);
  spent seal heads not retained; panic boundaries around gnark decode/verify.

## 3 · Serialization

- Canonical JSON: duplicate/unknown-field and trailing-data rejection, then
  re-marshal byte-equality (`UnmarshalCanonical`); depth/key caps
  (`strictjson`).
- Length-field lies: exact-size `LimitedReader`, EOF proof, `math/bits`
  overflow-checked arithmetic, allocation only after locally derived expected
  sizes (`preflight.go` — Phase 2 shape never taken from an untrusted
  artifact).
- Aliasing: lowercase exact-length hex; canonical RFC3339Nano timestamps.

## 4 · Identity and roster

- Sybil/role overlap: three-dimension uniqueness (ID, key ID, fingerprint)
  across coordinator, release signer, auditors, roster, witnesses, mirrors;
  release signer ≠ coordinator; external auditors disjoint from all actors.
- Deceptive names: control characters, bidi formatting, and zero-width
  characters rejected in display names and artifact-name segments
  (`rejectDeceptiveRunes` — explicit Cf list so ZWNJ/ZWJ stay writable);
  256-byte display-name cap; whitespace-only attested fields rejected.
- Bounds aligned across layers: auditors 2..20 at enrollment = transcript
  capacity; IDs restricted to `[a-z0-9-_.:]`, 1..128.

## 5 · Transcript and chain

- History rewrite: hash-chained records (index, previous payload, previous
  record ID), whole-chain validation on append, frozen scheduled participant
  order, ≤20 records.
- Fake contributions: full replay from deterministic genesis with per-step
  `Verify`; no-op contributions rejected; gnark challenge must equal SHA-256
  of the previous payload (binds native transcript to the JSON chain);
  10-field attestation binding plus chronology; erasure binds the contribution
  and must postdate it.

## 6 · Network

- The package imports no networking; evidence URIs are validated
  (`https`/`ipfs`, no userinfo/fragment) and recorded, never fetched.

## 7 · Process and operations

- Beacon precommitment: future-round requirement; round schedule pinned; lead
  re-checked immediately before atomic publish; production reserves a witness
  observation window on top of the signed minimum (`requiredCloseLead`) so
  witness receipts stay satisfiable; derived rounds sampled from the
  post-replay clock; Phase 2 round must differ from Phase 1.
- Quorums: witnesses ≥2 (distinct IDs and fingerprints, unanimous on closure),
  3–16 distinct-operator relay observations, 2–8 mirror receipts per head,
  ≥2 audits.
- Production mode: clean git tree, pinned build profile, no module `replace`,
  all scheduled participants required, running software re-verified per
  command.
- Separation of duties: release needs ≥2 distinct passing audits and a
  distinct pre-existing release key; GO needs coordinator + every named
  auditor + release signer, exactly; audits bundled in auditor-ID order so
  the transcript always matches the decision's required order.
- Recovery: read-only `inspect` reports chain state and the next scheduled
  contribution from signed data only — no key, no writes, no replay.
- Release trees: exact name-set equality, no unpinned files, sorted checksum
  manifests, ceilings derived from the bundle layers' own maxima (32768).

## 8 · Other

- CLI diagnostics redact argv by construction (single stderr outlet); short
  values replaced only as whole tokens so short key IDs stay protected without
  blanking unrelated digits.
- Secrets excluded from published evidence; fixed sidecar paths, no `latest`
  discovery; golden public vector pinned.

## Fixed during this audit

Ed25519 point validation · deceptive-rune and display-name hardening ·
whitespace-only attested fields · artifact-name control characters ·
clone-before-verify on the acceptance path · witness observation window ·
counted-gate alignment (auditor cap, audit ordering, release-tree ceiling) ·
audits-gate label renamed while no signed record existed · redaction by
construction with token matching · read-only `inspect` · beacon round derived
post-replay · replay/seal/phase2-init progress reporting.

## Known gaps (open)

1. **`streampk` URL path has no digest verification.** `OpenKeyURL` range-reads
   proving-key bytes into decoders with `NoSubgroupChecks()`; the compensating
   `IsOnCurve` landed in the untrusted-decode PR, but nothing hashes the
   fetched bytes against the signed manifest on that path.
2. **Mainnet has no script-hash recompile gate.** The exporter binds the VK
   hash to the VK bytes, but nothing binds `reclaim_global.script_hash` to a
   script recompiled from the VK outside the Preprod-pinned
   `formal/scripts/lock-active-artifacts.mjs`. Fix belongs in
   `ValidateReclaimDeployment` or by lifting the Preprod-only guard.
3. **Latent enrollment-cap overflow.** The bundle's per-category maxima
   (witnesses, per-head mirror operators) sum past the 128-identity enrollment
   cap; reachable only with genuinely distinct operators at every head.
   Fails closed at bundle assembly.
4. **No constant-time comparisons in the package.** Defensible — every
   comparison is over public values — recorded so reviewers don't re-derive it.
