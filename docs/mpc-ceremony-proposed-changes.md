# MPC Ceremony — Proposed Changes

Checked against the working tree at `ba065e6` on 2026-08-10. Items marked
**verified** cite the file and line that establishes them. Items marked
**proposal** are new work, not defects. Items marked **open** were not
investigated and are listed so they are not mistaken for cleared.

No cryptographic break was found. Severity below reflects operational impact.

## A · Consistency defects

Both are fail-closed — they block valid work rather than admit invalid work —
but both surface at the worst possible moment.

### A1 · Audit count is inconsistent across three layers — medium, verified

A ceremony may enroll **two or more** auditors (`internal/mpcceremony/definition.go:164`).
`SignRelease` accepts **two or more** signed audit reports
(`internal/mpcceremony/audit.go:867`, `len(inputs) < 2`). But `ProductionDecision`
requires **exactly two** (`internal/mpcceremony/decision.go:487`, `len(d.Audits) != 2`).

A ceremony that enrolls three auditors — permitted, and strictly more
conservative — can therefore produce a valid signed release that can never be
recorded in a valid production decision. The failure appears after the ceremony
is complete, at final GO signing, when nothing can be redone.

**Fix.** Pick one rule and apply it in all three places. Accepting `>= 2` in the
decision is the better direction: more independent auditors should never be
harder to record than the minimum. The same question applies to `ExternalAudits`
at `internal/mpcceremony/decision.go:501`.

### A2 · The runbook's failover drill calls a command that does not exist — medium, verified

Step 3 of the Restore And Failover Drill instructs the operator to "run read-only
`inspect`, and compare the derived next participant/index with the primary run
card." There is no `inspect` in the CLI — neither `cmd/mpc-ceremony/parse.go` nor
`cmd/mpc-ceremony/usage.go` mentions it.

The only `inspect` is a stage of `scripts/run-mpc-k21-local-rehearsal.sh:1616`,
and it reads that script's own `state/steps/*.complete` markers rather than the
signed chain. A production ceremony driven through the CLI directly — which is
what the runbook's main body documents — has no recovery inspection at all.

The answer is a pure function of already-signed data:

    next_index       = len(chain.Records) + 1
    next_participant = policy.Participants[len(chain.Records)]

with the frozen order enforced at `internal/mpcceremony/chain.go:283-286`. No
signing key and no replay are required.

**Fix.** Add `mpc-ceremony inspect` — read-only, public keys only, never writes.
Report ceremony ID and mode, per-phase accepted count and head record ID, next
scheduled participant and index, and which artifacts are present or missing. Two
verification depths: metadata-and-hashes by default (seconds), full replay behind
`--full` (hours at K=21). It must state which depth it ran; during a recovery
window nobody waits for the replay.

### A3 · Long-running commands report no progress — medium, verified

`internal/mpcceremony` has no logger and no print path at all. That is the right
call for this domain: the package handles signing keys and secret contribution
state, and having no output path is stronger than having a careful one. It also
keeps operations deterministic and replayable with no side channels. The CLI
reinforces it by redirecting gnark's global logger to stderr so stdout carries
only the result contract (`cmd/mpc-ceremony/main.go:20-23`).

The cost is that a K=21 phase close replays for hours with zero output. An
operator cannot distinguish running from hung, and cannot calibrate how long a
close actually takes on their hardware.

That is not merely a usability complaint. Misjudging replay duration is precisely
what caused the 2026-07-24 closure-timing incident: the operator chose a beacon
round roughly an hour out, the replay took longer than that, and the round was
already public by the time the closure was written. The current code fails
loudly in that situation (see the `validateCloseCommitTime` guard), so the unsafe
closure can no longer be produced — but the operator still burns the attempt and
must restart with a farther round, having no better information than last time
about how far is far enough.

**Fix.** Add progress reporting that does not weaken the boundary. Two options
that both preserve the no-print rule inside the package:

- an optional progress callback on the `*Options` structs, invoked per replayed
  contribution with an index and count, which the CLI renders to **stderr**; or
- structured timing returned in the `*Result` struct, so the CLI can report
  measured per-contribution and total replay duration after the fact.

The callback form is more useful operationally because it also feeds the
beacon-round choice: an operator who can see "contribution 3 of 5, 41 minutes
elapsed" can pick a safe round. Neither form prints from the package, and neither
carries secret material — an index, a count, and a duration only.

### A4 · CLI error redaction is a per-call-site blocklist — low, verified

Before printing an error, the CLI runs the message through `redactCLIError`
(`cmd/mpc-ceremony/main.go:137-167`), which collects argv-derived strings, sorts
them longest-first, and `strings.ReplaceAll`s them out. The intent is right:
arguments include signing-key paths. Three limits are worth recording.

1. **It only catches what literally appears in argv.** A path read from a config
   file, or any value derived from a key, is not in the candidate set and passes
   through unmodified.
2. **It is opt-in per call site.** `writeDiagnostic` (`main.go:227`) performs no
   redaction; only the error paths call `redactCLIError`. A new diagnostic that
   forgets it leaks silently, and nothing in the build catches that.
3. **The candidate guard is minimal.** `addCLIErrorCandidate` rejects only `""`,
   `"-"` and `"--"` (`main.go:220-225`), so a short argument value can blank
   unrelated substrings of a message. That is over-redaction rather than a leak,
   but it degrades diagnostics exactly when they are needed.

This is defense-in-depth, not the actual control. The real protection is that
`internal/mpcceremony` has no print path at all, so secret material is never in a
position to be written. Redaction is the net under that.

**Fix.** Low priority, but two cheap hardening steps: route *all* CLI output
through one helper that redacts by construction, so a new call site cannot opt
out by accident; and add a minimum-length floor in `addCLIErrorCandidate` to stop
short values blanking unrelated text. Neither changes the trust boundary.

## B · Documentation integrity

### B1 · Eight governance documents were stripped from `main`; ten links to them remain — high, verified

PR #34 merged, but the branch was history-filtered and force-pushed first.
Diffing the pull-request head against the merged head yields exactly eight
deleted documentation files, 2,738 lines, and **zero code changes**. Both
lineages have 217 commits with byte-identical author and committer timestamps —
the signature of a path-filtering rewrite, not a revert.

    docs/mpc-ceremony-runbook.md              1590
    docs/mpc-external-audit-package.md         202
    docs/mpc-production-readiness.md           198
    docs/mpc-security-review.md                192
    docs/mpc-production-go-no-go-template.md   187
    docs/production-readiness.md               143
    docs/next-steps-to-mainnet.md              124
    docs/mainnet-deployment-preparation.md     102

No commit deletes them; they survive only in `refs/pull/34/head` (`fd8516e`) of
`https://github.com/Anastasia-Labs/proof-tool`. Meanwhile `docs/README.md` still
indexes five of them with full descriptions — including "the formal mainnet
go/no-go matrix, current **NO-GO**, blocking rehearsal incident" — and
`docs/trusted-setup-ceremony.md` links three more. Ten dangling references in
total.

The practical effect: `main` advertises a NO-GO decision record it does not
contain, and the procedure governing a mainnet trusted setup exists only inside a
pull-request ref.

**Fix.** Ask upstream whether the removal was deliberate before restoring
anything — documents that say NO-GO and disqualify the current binary may have
been withheld on purpose. If deliberate, remove the ten dangling links so the
index stops advertising absent files. If accidental, restore all eight. The
current state is the worst of both.

## C · New capability: object-storage backend (S3/R2)

Proposal, not a defect. The governing rule is one sentence: **object storage is
transport, never trust.**

### C1 · Keep all fetching outside the ceremony binary

`internal/mpcceremony` imports no networking at all, deliberately. The runbook's
guarantee boundary lists "no implicit `latest`, overwrite, or network-fetch
behavior" as an enforced property, and `internal/mpcceremony/decision.go:84`
states that verification "never fetches a URI or trusts mutable network state."
Putting fetch inside the binary deletes a stated security property.

**Design.** A separate sync tool moves bytes; the ceremony tool keeps verifying
local files. Downloading is already safe because every artifact is pinned by
digest in the signed chain and re-checked by `verifyArtifactBytes` — a hostile
bucket can cause a failure, never a forgery.

### C2 · Closure publication has no atomic equivalent in object storage — highest risk of this section

On-disk safety rests on `RENAME_NOREPLACE` and staged directories published by
atomic rename. S3/R2 has no atomic directory rename. Per-object create-if-absent
is available via conditional writes (`If-None-Match: *`), but a closure directory
can become **half-visible** — and the closure is precisely the artifact whose
publication moment is security-critical, since the 2026-07-24 incident was a
closure-timing failure.

**Design.** Upload closure objects under a temporary prefix, then make them
visible by writing a single immutable pointer object last. One object flip, not a
multi-object window.

### C3 · A mirror is only immutable if the bucket enforces it

Anyone holding credentials can overwrite an object. To honestly claim an
`ImmutableMirrorReceipt`, the bucket needs object lock, retention, and
versioning — and the receipt should record that configuration alongside
`StorageLocationSHA256`.

Independence is a separate requirement: two buckets in one R2 account is one
mirror. The gate wants distinct operators, exactly as the three-relay beacon rule
does.

### C4 · Reuse the existing publication allowlist; emit real mirror receipts

`scripts/package-mpc-public-evidence.sh` already builds a "fail-closed,
content-hashed public evidence tree" where "private control keys and files
outside the explicit allowlist are never copied." Do not write a second answer to
*what may be published* — that is how a signing key reaches a bucket.

On the other side, the sync tool should emit `ImmutableMirrorReceipt` records
(`internal/mpcceremony/operational.go:341`) from its uploads. Those feed the
operational evidence bundle and satisfy the two-independent-mirrors gate, so the
work lands in a slot the schema already has.

- Verify by re-downloading and re-hashing, not by trusting the upload response.
- A `latest` pointer is for humans; no tool may resolve one.
- Sizing is comfortable: roughly 3.6 GB of accepted state at five participants
  and roughly 9 GB of cumulative prefix downloads. R2 zero-egress matters because
  each participant pulls the full prefix before contributing.

## D · Open — not yet investigated

### D1 · The verifying-key seam between ceremony and deployed validator

The ceremony's entire output is a verifying key that
`contracts/ownership-verifier` consumes — 785 lines in `src/Ownership/Verify.hs`
doing on-chain BLS12-381 Groth16, parsing the VK from a `BuiltinByteString`. A
flawless ceremony plus a validator that misparses or misapplies that VK still
loses funds; a perfect validator fed a compromised VK verifies forgeries happily.
Neither audit covers the seam.

Start from `scripts/verify-mpc-final-plutus-evidence.sh` and
`internal/mpcceremony/plutus_evidence_script_test.go` — they exist specifically to
test this seam, so they record what the authors already believed needed proving.

**Partially traced, and there is a gap.** The VK reaches the chain as a
compile-time script parameter. `reclaim-scripts-export global-v2` takes
`<672-byte-cardano-verifier-key-hex>` *and*
`<blake2b-256-verifier-key-hash-hex>` as two separate arguments
(`contracts/ownership-verifier/export/ReclaimDeploymentScripts.hs:79`).
`printGlobalV2Script` then prints that hash straight into the exported JSON's
`verifier_vk_hash` field without ever hashing the VK bytes it compiled in
(`ReclaimDeploymentScripts.hs:91-95`). The exporter will therefore emit a script
that verifies against VK *A* while its manifest advertises `blake2b256(B)`.

Whether a downstream check binds them — `verify-proof-release.mjs`, the
reclaim-server manifest code, or the coherence checks the runbook lists — is not
yet traced. The current Preprod manifest
(`apps/ownership-proof-web/public/proof-assets/reclaim-deployment.json`) is
self-consistent, with `reclaim_global.verifier_vk_hash` equal to
`proof.cardano_vk_blake2b256`, and is honestly labelled
`destination_key_provenance: "single-actor local Preprod setup; not an MPC
ceremony"`.

This is the same failure shape as the snarkjs/Circom incidents documented by
zkSecurity (Foom, ~$1.4M; Veil, 2.9 ETH): correct library, correct maths, wrong
artifact deployed.

### D2 · Subgroup checks are disabled on the streaming proving-key path

BLS12-381's curves have cofactors, so points on `E(F_p)` outside the order-`r`
subgroup exist. Accepting one as a group element is the classic small-subgroup /
invalid-curve failure (Cremers and Jackson, *Prime, Order Please!*, CSF 2019).

The ceremony path is closed. gnark-crypto's `NewDecoder` defaults
`subGroupCheck: true` (`ecc/bls12-381/marshal.go:63`), mpcsetup's `ReadFrom` uses
that default, and `UpdateProof.Verify` additionally runs explicit
`IsInSubGroup()` on both proof points and rejects the infinity point
(`ecc/bls12-381/mpcsetup/mpcsetup.go:94-99`).

Six call sites outside the ceremony explicitly opt out:

    internal/streampk/keysource.go:116,133,378,393
    internal/msmengine/serialize.go:112,148

All pass `curve.NoSubgroupChecks()`. Both callers were traced. They differ.

**`msmengine` is authenticated — no issue found.** The chunked browser path
verifies every chunk before any decoder sees it
(`apps/ownership-proof-web/public/proof-runtime/msm-worker.js:317-326`): exact
size, `content-encoding: identity` enforced, then `__msmengineVerifyChunkBytes`
against both the `sha256` and `blake2b256` recorded in the signed
`ChunkManifest`, with verify-before-cache so rejected bytes cannot enter the LRU.
The unchecked decoder is reached only via `unmarshalG1PointsPinned` /
`unmarshalG2PointsPinned`, whose doc comment states they decode
"digest-authenticated proving-key points", and which still run `IsOnCurve()` on
every point after skipping the subgroup check. The checked sibling
`unmarshalG1Points` uses `SetBytes`, which validates subgroups.

One fragility worth fixing anyway: `pinnedDecode` defaults to `true`
(`cmd/wasm-prover/main_js.go:934`) and is overridable from request JSON
(`req.PinnedDecode`). It is a tuning knob, not a value derived from whether the
bytes were actually verified. Safe today only because the fetch path always
verifies; nothing enforces the coupling.

**`streampk` is NOT authenticated on the URL path — this is the real finding.**
`internal/streampk` contains no digest verification at all: grepping
`range.go`, `keysource.go` and `index.go` for sha256/blake2b/digest/verify
returns nothing. `ValidateIndex` validates structure, not content.

Its two callers diverge:

- `openStreamingArtifactsFromDir` (`cmd/wasm-prover/main_js.go:1332-1357`)
  verifies the proving key's SHA-256, BLAKE2b-256 **and** size against the signed
  key manifest before calling `streampk.OpenKeyFile`. Correct.
- `openStreamingArtifactsFromURLs` (`main_js.go:1360-1441`) verifies the
  verifying key thoroughly (hash, sha256, size) and compares the index's
  `file_size` to the manifest — but **never digests the proving key bytes**. It
  then calls `streampk.OpenKeyURL(&index, pkURL, opts...)`, which issues HTTP
  range requests straight into decoders that skip subgroup checks. The key
  manifest signature is itself optional on this path
  (`verifyOptionalKeyManifestSignature`).

The exposure is immediate rather than theoretical: `KeySource.open`
(`internal/streampk/keysource.go:112-139`) range-reads the G1 singletons
(alpha, beta, delta) and the G2 singletons (beta, delta) and decodes all five
with `NoSubgroupChecks()` at open time — before any chunk-manifest machinery
applies, and with no on-curve check either, unlike the `msmengine` pinned path.

This is exactly the primitive the ZKHack trusted-setup puzzle exploits: a point
that parses, lies on the curve, and sits outside the order-r subgroup leaks the
secret scalar to Pohlig-Hellman over the smooth cofactor. BLS12-381's G1
cofactor `(x-1)^2/3` factors into 3, 11, 10177, 859267 and 52437899, so the
smooth part is trivially attackable. What is at risk here is a proving key rather
than a ceremony secret, so the impact is malformed-input handling and possible
incorrect proofs rather than direct key recovery — but the missing check is the
same one.

**Fix.** Either verify the proving key digest on the URL path before opening the
source, or have `streampk` verify per-range digests from a pinned index the way
the chunk path does. At minimum, add `IsOnCurve()` after the singleton decode so
`streampk` is no weaker than `msmengine`, and make `pinnedDecode` derive from
verification state rather than being caller-supplied.

**Still open.** Whether `openStreamingArtifactsFromURLs` is reachable in a
production deployment, or whether shipping configurations always route through
the chunk-manifest path. That determines severity, not whether the gap exists.

### D3 · Sweep the remaining twelve gates for the A1 defect class

A1 was found by comparing what the definition permits, what the release accepts,
and what the decision demands for one gate. The other twelve were not checked for
the same mismatch — witnesses, mirrors, relay operators, and participant counts
all have counts asserted in more than one layer.
