# Unsigned public ceremony replay

`mpc-ceremony replay` accepts the same ceremony trust, replay evidence, and candidate
paths as `audit`, but no auditor identity, private key, timestamp, or output signature.
It independently compiles the signed circuit, replays both phases, validates the beacon
and seal bindings, and compares final native keys, Cardano export, and public proof
evidence. It calls the same replay/comparison helper as signed audits. It writes no
protocol assertion and does not waive any running-software or signed-policy checks.
Use `mpc-ceremony replay --help` for the complete file flags.

`release verify` remains a separate check of the signed release and bundled evidence;
`decision verify` checks production approval. Their JSON results include
`release_manifest_sha256` so archive tools can require a GO decision for the exact
release they have verified, not another release from the same ceremony.

The installed verifier must satisfy the frozen definition's exact software binding.
This new entry point does not authorize newer binaries for old ceremonies. Trust keys
may come from the website publishing the archive when that is the reader's selected
trust source. Passing checks do not prove secret deletion, offline execution, or human
independence, and unsigned replay must never be described as an enrolled signed audit.

The signed lifecycle helper exercises unsigned replay before signed audits and rejects
a tampered candidate signature. Run `go test ./cmd/mpc-ceremony ./internal/mpcceremony`
with the normal repository vendor preparation. Builds used by the signed workflow need
real Go VCS metadata: use a full checkout if the local Go version cannot stamp linked
Git worktrees. Do not disable software identity verification to accommodate missing
build metadata.
