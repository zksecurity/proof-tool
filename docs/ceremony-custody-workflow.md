# Supported custody and tiny-proof commands

These commands close the gaps found in the September 2026 same-operator rehearsal.
They do not change the signed protocol, waive operational evidence, prove physical
independence, or authorize a production release.

## Each participant turn

1. Before computation, the coordinator runs `ops prepare-handoff` with the exact
   current signed chain, next participant, `--direction outbound`, and a fresh
   output directory. The command derives the next index, predecessor, software,
   circuit, input payload and current creation/expiry times.
2. The coordinator reviews `canonical.json`, then runs `ops sign --record-type
   handoff --reviewed --reviewed-sha256 HEX` with their own key and a fresh
   signature output. The hash is the SHA-256 of the exact reviewed canonical bytes.
3. Transfer the canonical handoff, signature and named public payload to the
   participant through the agreed channel. Keep credentials separate.
4. The participant places received payloads at their named relative paths under
   their received-files root. `ops prepare-receipt` verifies the sender signature
   and hashes every retained file, then records the actual current receipt time.
   Review/sign the receipt as `--record-type receipt`, and return its exact bytes
   and signature to the coordinator before computing.
5. Verify the receipt with `ops verify --record-type receipt --related-record
   ORIGINAL_HANDOFF`, the recipient public key and their receipt signature.
6. Compute using the approved contributor supervisor. Retain the completed public
   candidate and cleanup acknowledgment after container removal.
7. Before acceptance, the participant repeats handoff preparation with `--direction
   return --candidate-dir DIR`. It binds the same pre-acceptance chain and the five
   public candidate files, including cleanup acknowledgment and signatures.
8. The coordinator receives those named public files, prepares and signs the return
   receipt, retains both directions of custody evidence, and only then accepts.

Use a fresh directory per turn and direction. Interrupted packets are retained;
these commands never overwrite them. Handoffs expire after one hour. A missing
historical handoff cannot be repaired by creating or backdating a later receipt.
The final operational verifier still checks complete custody chronology against
accepted contributions; merely signing one record does not establish that result.

Run `mpc-ceremony help ops prepare-handoff` and `help ops prepare-receipt` for the
complete flags. Receiver preparation performs no network transfer itself and cannot
prove how the files crossed between machines. Signing belongs on the key-owning
station; container network isolation does not physically disconnect its host.

## Aggregate operational evidence

`ops sign` also supports canonical `beacon-evidence` and `evidence-bundle` records.
Both require explicit review and the exact reviewed SHA-256. They retain the same
signed-definition, canonical-record and owner-key checks as other record types.
Run `ops verify --record-type evidence-bundle --evidence-root DIR` afterwards;
this performs the full evidence verification and is mandatory before final release.
Unsupported record types, changed reviewed bytes, wrong owner keys and existing
signature outputs fail closed.

## Tiny rehearsal proof

After `finalize prepare`, run:

```sh
mpc-ceremony finalize rehearsal-evidence \
  --keys-dir /work/preliminary \
  --coordinator-public-key-file /trust/coordinator-public-key.hex \
  --ceremony-id EXPECTED_SIGNED_CEREMONY_ID \
  --out /work/public-finalization-evidence.json
```

This authenticates the preliminary keys under the separately trusted coordinator
key, requires the exact supported five-constraint rehearsal circuit, and generates
and verifies a real proof using the repository's public golden input. It accepts
no wallet secret inputs. The output feeds `finalize complete`, which independently
replays the ceremony and validates the proof. Production circuits must use their
own compatible public-evidence generation process.

## Release sequencing

Publish these commands through the protected proof-tool release workflow. Relay
must then pin that exact reviewed release and its checksums in both role images.
Existing frozen ceremonies retain their previous tool/software/workflow pins.
Source tests or a local binary alone do not activate a new production release.
