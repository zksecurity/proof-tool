# MPC Ceremony — Attack/Defense Inventory

A survey of the deliberate security defenses implemented in the ceremony codebase
(`internal/mpcceremony`, `internal/streampk`, `internal/msmengine`,
`internal/keybundle`, `cmd/mpc-ceremony`, `cmd/wasm-prover`), each mapped to the
attack it counters, with code citations. Known gaps are listed at the end.

Line numbers are as of the commit this document was written against; treat them
as anchors, not guarantees.

## ELI5

The ceremony is a group of people taking turns stirring secret ingredients into
a shared pot, and the final recipe is only safe if at least one person's
ingredient stays secret and nobody swaps the pot when no one is looking. Almost
every defense below is one of these five ideas:

1. **Never trust a label, always check the contents.** Every file, key, and
   record carries a fingerprint (hash), and the code re-computes and compares
   that fingerprint every single time it touches the thing — not just once at
   the start. A swapped file is caught even if it has the right name.
2. **Never trust a path.** A file path can secretly be a signpost (symlink)
   pointing somewhere else, and a file can be swapped in the instant between
   "check it" and "open it." The code looks before opening, opens, then looks
   again to make sure it's still the same file.
3. **Write once, never overwrite.** Ceremony history is append-only. New
   records link to the previous one by fingerprint (like a blockchain), so
   rewriting, reordering, or deleting history breaks the chain visibly.
   Publishing uses "create only if it doesn't exist" operations so nothing
   authoritative can ever be silently replaced.
4. **One person can't cheat alone.** The coordinator, release signer, auditors,
   and participants must all be different people with different keys; releases
   need multiple independent sign-offs; and the random beacon comes from a
   public source (drand) chosen far enough in the future that nobody can know
   it in advance.
5. **Assume the input is hostile.** Every byte parsed — JSON, curve points,
   sizes, timestamps — is checked for exactly one canonical form, exact length,
   and sane bounds before it's used. Two different encodings of "the same"
   thing are treated as an attack, not a convenience.

The known gaps section at the end lists the handful of places where these
ideas are not yet applied consistently.

## 1. Filesystem

### Symlink attacks (CWE-59)

Attack: plant a symlink at an expected path so the tool reads or writes
somewhere else (another user's key, `/etc/passwd`, an attacker-controlled file).

- `openRegularExact` Lstats and rejects `ModeSymlink` and non-regular files
  before opening — `internal/mpcceremony/files.go:127-133`
- `readRegularBounded` same pattern for signed records and keys —
  `internal/mpcceremony/workflow.go:2165-2174`
- Publication file/tree inspection rejects symlinks and non-regular entries —
  `internal/mpcceremony/publication.go:101-106,301,322`
- Key bundle reads require a regular file with secret permissions —
  `internal/keybundle/keybundle.go:232-244`
- CLI inputs reject symlinks — `cmd/mpc-ceremony/ops.go:309-314`,
  `cmd/mpc-ceremony/executor.go` (`readPublicKeyHex`)
- Walk/copy paths reject symlink entries —
  `internal/mpcceremony/audit.go:1517-1519`, `decision.go:1068`,
  `finalize.go:1741-1746`
- `rejectSymlinkComponents` Lstats every parent path component and rejects any
  symlink or non-directory intermediate; its doc comment explicitly disclaims
  race-freeness versus `openat2(RESOLVE_NO_SYMLINKS)` —
  `internal/mpcceremony/workflow.go:2650-2684`

### TOCTOU races (CWE-367)

Attack: swap the file between the check and the open, or mutate it while it is
being read or hashed.

- `os.SameFile(linkInfo, info)` re-check after open ("changed while being
  opened") — `internal/mpcceremony/files.go:141-153`
- SameFile + size check + trailing one-byte read ("changed while being read") —
  `internal/mpcceremony/workflow.go:2180-2200`
- SameFile before hashing, size stability during, SameFile + size again after
  ("changed while being hashed") — `internal/mpcceremony/publication.go:121-150`
- Tree inspection re-Lstats the root after the walk to detect a mid-walk swap —
  `internal/mpcceremony/publication.go:296-356`
- `copyRegularNoReplace` triple-checks source identity/size before, during, and
  after the copy — `internal/mpcceremony/audit.go:1416-1468`
- Running-executable digest re-checks size mid-hash —
  `internal/mpcceremony/software.go:343-370`
- Key bundle reads: SameFile + size + trailing-byte read —
  `internal/keybundle/keybundle.go:250-267`
- Key manifest re-compared (`reflect.DeepEqual`) after signature verification
  ("manifest changed after signature verification") —
  `internal/keybundle/keybundle.go:141-146`

### Path traversal / containment (CWE-22)

Attack: artifact names or URLs that escape the intended directory
(`../../…`, absolute paths, scheme smuggling).

- `validateArtifactName`: rejects `\`, leading `/`, non-clean paths, `.`;
  bounds length and requires UTF-8 — `internal/mpcceremony/model.go:543-551`
- `resolveArtifactPath`: absolute-path + `filepath.Rel` containment (rejects
  `..` escapes) + symlink-component rejection —
  `internal/mpcceremony/workflow.go:2605-2625`
- `logicalPathWithin` for outputs rejects `.`/`..`/escapes —
  `internal/mpcceremony/workflow.go:2627-2648`
- `safeRelativePath` rejects absolute paths, `\`, `://`, `?`, `#`, non-clean —
  `internal/proofassets/chunk_manifest.go:920-923`
- `resolveChunkURL` rejects `\`, `://`, `?`, `#`, `../`, non-clean; requires an
  absolute base URL with scheme and host —
  `internal/msmengine/sharded_js.go:367-390`
- Path flags reject `-` (stdin) and URLs — `cmd/mpc-ceremony/parse.go:955-966`

### Overwrite / partial-state attacks on authoritative records

Attack: replace, truncate, or roll back already-published ceremony state; leave
a torn write that later reads as valid.

- `atomicWriteNoReplace`: temp file in the same directory, 0600, size check,
  fsync, strict read-back validation, hard-link publish (never replaces) —
  `internal/mpcceremony/files.go:266-336`
- `publishFileWithOps`: `link()` publish, destination identity via SameFile,
  byte and mode revalidation, parent fsync with recovery retry —
  `internal/mpcceremony/publication.go:168-287`
- Directory publication via `RENAME_NOREPLACE`; rejects empty staging;
  idempotent recovery only for a byte-exact existing tree —
  `internal/mpcceremony/publication.go:378-525`
- `publicationError` commit-state tracking so a committed publication is never
  rolled back by cleanup defers — `internal/mpcceremony/publication.go:18-46`
  (used at `workflow.go:289,689,1822,1958`)
- `O_WRONLY|O_CREATE|O_EXCL` with 0600 for new files —
  `internal/mpcceremony/audit.go:1437`, `finalize.go:1872-1911`
- `requireAbsentOrExact`: a retry may only succeed against a byte-identical
  existing artifact; any mismatch aborts —
  `internal/mpcceremony/workflow.go:2230-2256`
- Signature published before its record, so a record can never exist without
  its signature — `internal/mpcceremony/workflow.go:2209-2227`
- Durability: `syncDirectory` — `internal/mpcceremony/files.go:383-393`;
  fsync-failure recovery re-validates before retrying —
  `internal/mpcceremony/publication.go:527-552`

### Permissions

Attack: key material readable by other local users.

- `requirePrivateRealDirectory` rejects group/world permission bits —
  `internal/mpcceremony/workflow.go:2401-2413`
- `mkdirAllPrivateDurable`: 0700, per-level real-directory checks, parent
  fsync — `internal/mpcceremony/workflow.go:2460-2498`
- Directory-member allowlist; only `.<name>.partial-*` temporaries may be
  reaped — `internal/mpcceremony/workflow.go:2415-2458`
- Private key files must be mode 0600 or stricter —
  `internal/keybundle/keybundle.go:239-241`

### Resource exhaustion

Attack: oversized inputs exhaust memory or disk.

- `MaxArtifactSize` = 16 GiB, fail-closed —
  `internal/mpcceremony/preflight.go:28,188-196`
- Signed records capped at 16 MiB — `internal/mpcceremony/workflow.go:25`;
  drand responses at 1 MiB — `internal/mpcceremony/beacon.go:17`
- File sizes must be in `[1, max]` — `internal/mpcceremony/workflow.go:2190-2192`
- Per-file bound and 100,000-entry tree cap in publication —
  `internal/mpcceremony/publication.go:108-115,304-311`
- 4096-byte caps on signature/public-key artifacts —
  `internal/mpcceremony/decision.go:815,819`
- Per-artifact-type byte caps — `internal/keybundle/keybundle.go:27-31`

## 2. Cryptographic

### Forged or replayed records

Attack: fabricate a signed record, or trust a key named inside the (untrusted)
record itself.

- `VerifyExact`: schema/algorithm validation, key-ID match, public-key
  fingerprint match, signed-data SHA-256 match, then `ed25519.Verify` —
  `internal/mpcceremony/attestation.go:70-97`
- `VerifySignedRecord`: authenticate the exact bytes before strict parsing —
  `internal/mpcceremony/attestation.go:117-131`
- `LoadSignedDefinition`: requires an external out-of-band coordinator public
  key (an in-tree copy is insufficient); the signature's `KeyID` is deliberately
  not trusted for role assignment until the external anchor has authenticated
  the bytes; identity key cross-checked against the anchor —
  `internal/mpcceremony/workflow.go:179-230`
- Offline operational signatures verified over exact canonical bytes before
  wrapping — `internal/mpcceremony/operational.go:584-614`

### Key substitution

Attack: swap in a different key for an enrolled identity.

- `identityPublicKey` re-derives and checks the fingerprint on every load —
  `internal/mpcceremony/workflow.go:2138-2147`
- Loaded private key must match the enrolled identity's public key —
  `internal/mpcceremony/workflow.go:2149-2162`
- Decision signing key must equal the required ceremony identity —
  `internal/mpcceremony/decision.go:617-620`
- A 64-byte private key's public half must match its seed derivation —
  `internal/keybundle/keybundle.go:194-199`

### Artifact substitution

Attack: hand the verifier different bytes than were signed.

- Every `Digest` carries SHA-256 + BLAKE2b-256 + exact size; tagged lowercase
  hex enforced — `internal/mpcceremony/model.go:76-104`
- Every referenced artifact re-hashed against its signed ref before use —
  `internal/mpcceremony/workflow.go:2686-2699`
- R1CS digested before native decoding (vector lengths are unsafe from an
  unauthenticated file) — `internal/mpcceremony/r1cs.go:271-302` (comment at
  84-87)
- Circuit binding requires exact match of both hashes and serialization size —
  `internal/mpcceremony/r1cs.go:68-82`
- Running tool binary must digest-match the signed software binding —
  `internal/mpcceremony/software.go:321-330`
- CCS pinned by blake2b/sha256/size against the signed manifest —
  `cmd/wasm-prover/main_js.go:1024-1033`

### Encoding-equivalence attacks

Attack: two different byte encodings that decode to the same object, defeating
digest-based identity.

- `requireCanonicalRoundTrip`: re-serialize the decoded gnark object and
  require byte-identical size plus both digests —
  `internal/mpcceremony/files.go:191-216`
- `streamClone` round-trips through a pipe with byte-count and trailing-byte
  equality — `internal/mpcceremony/phase1.go:259-310`

### Invalid curve points / small subgroups

Attack: a point that parses but sits outside the prime-order subgroup leaks
secrets via Pohlig–Hellman over the cofactor (the ZKHack trusted-setup
primitive).

- BLS12-381 compressed-point flag-byte check rejects non-canonical prefixes —
  `internal/mpcceremony/preflight.go:427-438`
- Ceremony path uses gnark-crypto decoder defaults with subgroup checks ON,
  and `UpdateProof.Verify` additionally runs `IsInSubGroup()` and rejects
  infinity (upstream `mpcsetup.go:94-99`)
- `msmengine` pinned decoders skip the subgroup check only on
  digest-authenticated bytes and explicitly re-add `IsOnCurve()` per point —
  `internal/msmengine/serialize.go:103-122,139-158`; the non-pinned siblings
  use `SetBytes` (full validation) — `serialize.go:85-98,124-137`

### Cross-protocol / context confusion

Attack: a hash or signature computed for one record type accepted as another.

- `canonicalHash(domain, value)`: per-record-type domain tag + `0x00`
  separator + canonical JSON — `internal/mpcceremony/model.go:421-431`.
  Distinct tags for root, phase, acceptance, genesis, close, beacon, seal,
  audit, final-transcript, contribution/erasure attestations, signed release,
  production decision, and full replay (see `definition.go`, `chain.go`,
  `attestation.go`, `decision.go`, `audit.go`)
- `DeriveBeaconChallenge`: domain tag + `0x00`, 4-byte big-endian length
  prefix on every variable-length field, 8-byte BE round — unambiguous tuple
  encoding — `internal/mpcceremony/chain.go:790-825`
- Public-input digest domain-prefixed —
  `internal/mpcceremony/finalize.go:1367-1374`

### ID substitution

Attack: reuse a record's contents under a different record ID.

- Every record ID is content-addressed: recomputed over the record with the ID
  field blanked, mismatch rejected, and the ID field required to be empty
  during computation — `internal/mpcceremony/chain.go:60-72` (and the parallel
  checks in `definition.go`, `attestation.go`, `finalize.go`, `decision.go`)

### Rigged randomness beacon

Attack: operator supplies or biases the public randomness.

- Drand quicknet chain hash, public key, scheme, genesis, and period pinned in
  the signed definition — `internal/mpcceremony/model.go:317-355`
- `VerifyDrandBeaconResponse`: real BLS verification against the pinned key;
  randomness derived as `sha256(verified signature)`, never taken from the
  response; unchained schemes' `previous_signature` rejected —
  `internal/mpcceremony/beacon.go:44-107`
- Caller-supplied challenge values rejected unless equal to the deterministic
  derivation — `internal/mpcceremony/chain.go:629-634`

### A verifier that accepts anything

Attack: a broken or stubbed verifier reports success on garbage.

- Negative-control verification at finalization: after the positive check, the
  verifier must *reject* a changed destination, changed credential, changed
  digest, bit-flipped proof, wrong verifying key, truncated proof, and
  appended proof; all eight report booleans required true —
  `internal/mpcceremony/finalize.go:1313-1363,223-232`
- Wrong-key negative control negates `G1.K[0]` (mutating `Alpha` would not be
  a valid negative test because the verifier uses the precomputed pairing) —
  `internal/mpcceremony/finalize.go:1426-1455`

### Crash-as-oracle / denial via panic

- Panic boundaries around gnark decode/verify of untrusted input —
  `internal/mpcceremony/files.go:338-381`,
  `internal/mpcceremony/phase1.go:312-336`

## 3. Serialization

Attack class: JSON smuggling (duplicate keys, unknown fields, trailing data),
non-canonical encodings that alias distinct digests, length-field lies,
integer overflow.

- `MarshalCanonical`: rejects nil and `map[string]any`; requires `Validate()` —
  `internal/mpcceremony/model.go:363-382`
- `UnmarshalCanonical`: duplicate-key scan, `DisallowUnknownFields`,
  trailing-token rejection, `Validate()`, then re-marshal and require byte
  equality with the input — `internal/mpcceremony/model.go:386-419`
- Recursive duplicate-key detection with `UseNumber()` —
  `internal/mpcceremony/model.go:433-501`
- `strictjson`: max depth 64, max 100,000 object keys, duplicate-key and
  trailing-value rejection — `internal/strictjson/strictjson.go:14-17,75-106`
- Drand JSON parsed strictly before any crypto —
  `internal/mpcceremony/beacon.go:58-69,109-118`
- `nativeReadExact`: `io.LimitedReader` at the exact expected size; decoder
  must consume exactly that and leave zero trailing bytes —
  `internal/mpcceremony/files.go:172-189`
- Preflight scanner tracks consumed bytes, rejects overrun, and proves EOF
  with a one-byte read — `internal/mpcceremony/preflight.go:383-393,497-509`
- `checkedAdd`/`checkedMul`/`checkedSub` via `math/bits` for all size
  arithmetic — `internal/mpcceremony/preflight.go:198-219`
- `MaxDomainN = 2^32` (BLS12-381 2-adicity), `MaxPhase2Commitments = 255`
  (gnark's 1-byte commitment domain tag aliases beyond that) —
  `internal/mpcceremony/preflight.go:20-24`
- Phase 2 shape must come from the locally compiled R1CS, never from an
  untrusted artifact — `internal/mpcceremony/preflight.go:57-63`, enforced at
  `workflow.go:2707-2747` and `files.go:103-124`
- Stream length prefixes must equal locally derived expected lengths before
  any allocation — `internal/mpcceremony/preflight.go:458-470`
- streampk domain header: canonical-flag byte check, trailing-byte rejection,
  every FFT domain field recomputed against `fft.NewDomain` —
  `internal/streampk/keysource.go:163-217`
- Timestamps must be UTC `Z` and round-trip canonically through RFC3339Nano —
  `internal/mpcceremony/model.go:553-565`
- Hex must be exact-length lowercase (rejects mixed-case aliasing) —
  `internal/mpcceremony/model.go:510-522`

## 4. Identity / roster

Attack class: one actor holding multiple roles (Sybil), colluding role
overlap, duplicate enrollment.

- Release signer distinct from coordinator by ID and key ID —
  `internal/mpcceremony/definition.go:161-163`
- At least two auditors; uniqueness across coordinator/release signer/auditors
  in three dimensions: identity ID, key ID, public-key fingerprint —
  `internal/mpcceremony/definition.go:164-198`
- Roster uniqueness against all prior roles, same three dimensions —
  `internal/mpcceremony/definition.go:199-225`
- Same three-dimension uniqueness re-applied at enrollment input —
  `internal/mpcceremony/workflow.go:68-123`
- Phase policy: non-empty, ≤ 20 participants, minimum within bounds, all IDs
  in roster, no duplicates — `internal/mpcceremony/model.go:177-198`
- A participant may appear at most once per phase chain —
  `internal/mpcceremony/chain.go:205-208`
- Exactly two enrolled audits by distinct auditors with distinct key IDs, plus
  two external audits with distinct signer fingerprints —
  `internal/mpcceremony/decision.go:487-515`
- External auditor keys disjoint from coordinator, release signer, and all
  enrolled auditors — `internal/mpcceremony/decision.go:792-803`
- GO decision requires exactly the required signer set — no extras, none
  missing; duplicate signatures rejected —
  `internal/mpcceremony/decision.go:683-716`
- Public witnesses and mirror operators must not overlap any ceremony actor —
  `internal/mpcceremony/operational.go:937-950`
- Transfer sender/recipient distinct — `internal/mpcceremony/operational.go:1007-1024`
- IDs restricted to `[a-z0-9-_.:]`, 1–128 chars —
  `internal/mpcceremony/model.go:531-541`

## 5. Transcript / chain integrity

Attack class: rewrite, reorder, fork, or truncate ceremony history; splice a
contribution that was never verified.

- `Chain.Validate`: strictly increasing timestamps, contiguous 1-based
  indices, `PreviousPayload` = accepted head, `PreviousRecordID` = prior
  record ID (hash chaining), ceremony/phase identity match, ≤ 20 records —
  `internal/mpcceremony/chain.go:159-214`
- `Append` validates the entire candidate chain before mutating —
  `internal/mpcceremony/chain.go:216-227`
- Accepted payload must differ from the previous payload (no no-op
  contributions) — `internal/mpcceremony/chain.go:106-108,374-376`
- Domain-separated genesis anchor — `internal/mpcceremony/chain.go:382-398`
- Chain participants must match the frozen scheduled order from the signed
  definition — `internal/mpcceremony/chain.go:283-297`
- `ValidateAttestationAcceptance`: record must be the next child of the head
  (index, payload, and record ID all three); 10-field binding between record
  and attestation; software binding equality; full chronology (contributed
  after created, after previous acceptance; accepted after destruction) —
  `internal/mpcceremony/chain.go:301-380`
- gnark contribution challenge must equal SHA-256 of the previous payload —
  binds the native transcript to the JSON chain —
  `internal/mpcceremony/workflow.go:2865-2877`
- `verifyChainFiles`: every record's native payload re-digested; participant
  attestation, erasure, and coordinator verification records verified;
  growing-prefix revalidation — `internal/mpcceremony/workflow.go:2701-2828`
- Full replay from deterministic genesis with per-step `previous.Verify(next)`;
  clone-before-verify so archived inputs are never mutated —
  `internal/mpcceremony/phase1.go:145-205`, `phase2.go:228-292`
- Replayed shape must equal the signed circuit binding —
  `internal/mpcceremony/phase2.go:264-268`
- Erasure attestation binds the contribution in 8 fields; destruction must
  postdate contribution — `internal/mpcceremony/attestation.go:257-280`
- Coordinator verification record must match the chain record field-for-field —
  `internal/mpcceremony/workflow.go:1323-1343`
- Transfer receipts bind `sha256(exact handoff bytes)` plus 10 scope fields,
  with a validity window — `internal/mpcceremony/operational.go:709-724`
- Operational evidence must cover every accepted head and terminate at the
  close record's head — `internal/mpcceremony/operational_bundle.go:544-549`

## 6. Network / download

- `internal/mpcceremony` imports no networking; verification never fetches a
  URI or trusts mutable network state —
  `internal/mpcceremony/decision.go:82-84`
- Evidence URIs restricted to `https`/`ipfs`, canonical encoding, no userinfo,
  no fragment, host required, ≤ 2048 bytes; recorded, never fetched —
  `internal/mpcceremony/decision.go:1322-1342`
- `Content-Encoding` must be empty or `identity` (blocks transparent-
  decompression length/digest confusion) —
  `internal/msmengine/sharded_js.go:326-328`,
  `apps/ownership-proof-web/public/proof-runtime/msm-worker.js:313-326`
- Exact-size reads via `LimitReader(size+1)` —
  `internal/msmengine/sharded_js.go:329-335`
- Dual-digest chunk verification before use; verify-before-cache (no error
  path can populate the LRU) — `internal/msmengine/sharded_js.go:337-364`,
  `msm-worker.js:313-326`
- Compressed CCS: wire bytes hashed and length-checked against a signed pin
  while inflating; trailer drained; mismatch falls back to the fully pinned
  identity asset (cannot downgrade integrity) —
  `cmd/wasm-prover/main_js.go:1187-1211`
- Unpinned compile fallback refused when `ccs_url` is absent —
  `cmd/wasm-prover/main_js.go:1043`
- Manifest signature URL and public key must be supplied together —
  `cmd/wasm-prover/main_js.go:1449-1495`
- Readahead discards bodies; integrity enforced only at consumption —
  `cmd/wasm-prover/readahead_js.go:14-21`
- Section byte ranges bounds-checked against the plan's file size —
  `internal/msmengine/sharded_js.go:282-284`

## 7. Process / operational

### Beacon precommitment

Attack: coordinator who already knows the beacon output closes the phase
around it.

- `beacon_not_before` must postdate close and exactly equal the pinned
  quicknet round schedule — `internal/mpcceremony/chain.go:493-509`
- Round must be in the future at close; lead ≥ signed minimum —
  `internal/mpcceremony/chain.go:567-589`
- Lead re-checked immediately before the atomic publish, with a 2-second
  safety margin and a clock-monotonicity check —
  `internal/mpcceremony/workflow.go:1538-1583,28`
- Production requires ≥ 24h witness lead —
  `internal/mpcceremony/definition.go:8,232-239`
- Phase 2 beacon round must differ from Phase 1's (no round reuse) —
  `internal/mpcceremony/workflow.go:1409-1414`
- Beacon `published_at` must not precede the committed time or round schedule —
  `internal/mpcceremony/chain.go:755-764`
- Challenge must be exactly 32 bytes; future-round requirement mandatory —
  `internal/mpcceremony/model.go:345-353`
- Round-time arithmetic overflow-checked —
  `internal/mpcceremony/chain.go:773-785`

### Quorum weakening

- Public-witness quorum ≥ 2; receipts must meet it, with witness ID and key
  fingerprint de-duplication and unanimity on closure and round —
  `internal/mpcceremony/operational.go:741-781`,
  `operational_bundle.go:110-119`
- Multi-relay beacon: 3–16 observations, distinct relay IDs, distinct
  operator IDs, distinct endpoint digests, unanimous verified randomness —
  `internal/mpcceremony/operational.go:394-427`
- 2–8 immutable mirror receipts per accepted head —
  `internal/mpcceremony/operational_bundle.go:72-75`
- ≥ 2 independent audits — `internal/mpcceremony/chain.go:1174-1176`,
  `audit.go:867-868`

### Production-mode hardening

- Production requires all scheduled participants accepted (rehearsal permits
  ≥ minimum); ≥ 2 roster participants and ≥ 2 scheduled per phase with
  `minimum == len(participants)` — `internal/mpcceremony/chain.go:530-539`,
  `definition.go:240-254`

### Supply chain

- Production requires a clean git tree and exact build profile: pinned Go
  version, GOOS/GOARCH/GOAMD64, compiler, buildmode, `CGO_ENABLED=false`,
  `trimpath` — `internal/mpcceremony/software.go:433-463`,
  `definition.go:124-139`
- VCS must be git; revision 40 lowercase hex, not all-zero; `vcs.modified`
  false in production — `internal/mpcceremony/software.go:172-208,491-504`
- Module `replace` directives rejected in production; duplicate build
  settings and linked modules rejected —
  `internal/mpcceremony/software.go:383-400,465-489`
- Production executable identity read from `/proc/self/exe` —
  `internal/mpcceremony/software.go:41-50`
- Running software re-verified against the signed definition on every
  operational command — `internal/mpcceremony/workflow.go:232-244`

### Separation of duties

- Release signing requires ≥ 2 distinct enrolled passing audits and a
  distinct pre-existing release key; release directory must differ from the
  candidate directory — `internal/mpcceremony/audit.go:277-343`
- Audits must bind the exact candidate replay root and output set, and
  postdate candidate finalization — `internal/mpcceremony/audit.go:862-956`
- Release must strictly postdate every audit —
  `internal/mpcceremony/audit.go:958-963`
- Release self-verified via full `VerifyRelease` before publication —
  `internal/mpcceremony/audit.go:469-479`
- `PrepareFinalization` output is explicitly not a candidate and is rejected
  by audit/release commands — `internal/mpcceremony/finalize.go:451-455`
- "Trust the published seal" shortcut restricted to coordinator acceptance;
  contribution/close/finalize/audit paths must independently replay Phase 1
  before sampling secret randomness —
  `internal/mpcceremony/workflow.go:2879-2885`
- GO decision requires coordinator + both auditors + release signer, exactly —
  `internal/mpcceremony/decision.go:705-716,1253-1260`

### Contribution environment and erasure

- Contribution attestation requires OS CSPRNG, swap disabled, crash dumps
  disabled, telemetry disabled, ephemeral environment, destruction plan —
  `internal/mpcceremony/attestation.go:144-156`
- Erasure attestation requires process termination, ephemeral storage
  destroyed, no backup retained —
  `internal/mpcceremony/attestation.go:249-251`

### Ordering of secret sampling

- All deterministic preflights complete before MPC entropy is sampled; the
  candidate directory is created after replay so a crash cannot strand an
  empty candidate — `internal/mpcceremony/workflow.go:675-692`
- Participant must be the one scheduled at the exact index —
  `internal/mpcceremony/workflow.go:664-668`

### Release / evidence tree exactness

- `verifyReleaseTreeExact`: no unexpected, missing, symlinked, or non-regular
  entries — `internal/mpcceremony/audit.go:1486-1543`
- Release tree walk rejects any unpinned file; every pinned artifact must be
  present with the exact digest — `internal/mpcceremony/decision.go:1043-1103`
- `verifyChecksumsExact`: exact entry count, sorted order, no duplicates,
  digest re-verification — `internal/mpcceremony/audit.go:1021-1071`
- Release artifacts strictly ordered by unique logical name, 16–4096 files —
  `internal/mpcceremony/decision.go:196-205,1035-1039`
- One name / one URI may not map to conflicting evidence —
  `internal/mpcceremony/decision.go:1262-1276`

### Governance

- Restart must bind a genuinely fresh ceremony ID; `new_ceremony_id`
  forbidden on non-restart records —
  `internal/mpcceremony/operational.go:493-502,885-905`
- Passing audit must have zero findings; failing audit ≥ 1 —
  `internal/mpcceremony/chain.go:1031-1041`

## 8. Other

- **CLI error redaction**: every caller-supplied argument value replaced with
  `<redacted>` in diagnostics (unexpected positionals can be seed phrases);
  longest-first replacement avoids partial-substring leaks —
  `cmd/mpc-ceremony/main.go:140-176`
- **Secret exclusion from published evidence**: master XPrv, seed, derivation
  path, and wallet material excluded from `PublicFinalizationEvidence` —
  `internal/mpcceremony/finalize.go:262-265`
- **Golden-vector pinning**: public evidence must use the exact repository
  golden public vector — `internal/mpcceremony/finalize.go:289-292`
- **No mutable discovery**: fixed sidecar paths; no `latest` lookup or
  directory scan — `internal/mpcceremony/workflow.go:34-42`,
  `finalize.go:63-65`
- **Fail-closed release verification**: requires an out-of-band trusted public
  key; refuses to verify without the native proving key —
  `internal/mpcceremony/audit.go:504-509`
- **Integer/type safety on 32-bit wasm**: `nbWires` overflow guard —
  `internal/streampk/keysource.go:143-145`; Phase 2 shape derivation overflow
  guards — `internal/mpcceremony/r1cs.go:352-386`

## Known gaps

1. **Ed25519 identity keys are not validated as curve points — FIXED
   2026-08-13.** `Identity.Validate` previously checked only that the key is
   32 bytes of hex. Small-order/non-canonical points were accepted, and stdlib
   `ed25519.Verify` (`attestation.go:93`) does not reject small-order keys — a
   small-order public key admits signatures that verify for any message.
   Non-canonical encodings would also have evaded the fingerprint-based
   duplicate-key detection (`definition.go:218`). Now fixed:
   `validateEd25519PublicKey` (`internal/mpcceremony/model.go`) decodes with
   `filippo.io/edwards25519`, requires canonical encoding (re-encoded bytes
   must equal input), and rejects small-order points via
   `MultByCofactor == identity`.
2. **`streampk` URL path skips subgroup checks with no compensating
   verification.** `internal/streampk/keysource.go:116,133,378,393` use
   `NoSubgroupChecks()` with no `IsOnCurve` and no digest verification on the
   URL path. Documented as finding D2 in
   `docs/mpc-ceremony-proposed-changes.md:255-329`.
3. **`Identity.DisplayName` is unbounded and permits control characters —
   FIXED 2026-08-15.** `Identity.Validate` checked only trimming and UTF-8
   validity, so there was no length cap and interior ANSI escapes, bidi
   overrides, and zero-width characters passed into signed records, logs, and
   transcripts. `validateArtifactName` was partially hardened 2026-08-13
   (512-byte cap, `unicode.IsControl`, no untrimmed path segments) but shared
   the same blind spot, because `unicode.IsControl` reports Unicode category
   **Cc** only, while every bidi and zero-width character is category **Cf**.

   Both validators now share `rejectDeceptiveRunes` (`model.go:643-674`), which
   rejects control characters, the bidi formatting set
   (`U+202A`-`U+202E`, `U+2066`-`U+2069`, `U+200E`, `U+200F`), and `U+200B`.
   `validateDisplayName` (`model.go:620-641`) adds a 256-byte cap. The bidi and
   zero-width sets are listed explicitly rather than rejecting all of category
   Cf, because `U+200C` (ZWNJ) is required for Persian and Indic text and
   `U+200D` (ZWJ) joins emoji sequences; a blanket ban would make legitimate
   names unwritable. Covered by `deceptive_names_test.go`, including the
   over-blocking cases.

   Severity was low and remains worth recording: `DisplayName` is never read
   for a decision — four references in the tree, all declaration, validation,
   or construction — and identity is keyed on ID, key ID, and public-key
   fingerprint. Nothing was forgeable. The target was the human review step
   that the audit and release stages depend on, via the Trojan Source technique
   (CVE-2021-42574) applied to attested names rather than source code.

4. **Whitespace-only values passed presence checks in two attested fields —
   FIXED 2026-08-13.** `ContributionEnvironment.OS`/`.Architecture`
   (`attestation.go:145`) and audit findings (`chain.go:1038`) used plain
   `== ""`, so `" "` satisfied "must not be empty." Both now require trimmed,
   non-empty values, matching the `DisplayName` convention.
