# Publishing `mpc-ceremony`

This is the maintainer procedure for publishing the Linux/amd64
`mpc-ceremony` binary and its complete verification package. Ceremony operators
normally download and verify these assets; they do not need the release build
environment or its private signing key.

The Go module remains `proof-tool`. Relay communicates with `mpc-ceremony`
through its versioned CLI output, so publishing does not require a module-path
migration or an importable Go package.

## Release assets

Every GitHub release must contain both:

- `mpc-ceremony`, the directly downloadable Linux/amd64 executable; and
- `mpc-ceremony-<tag>-linux-amd64.tar`, the complete directory produced by
  `scripts/build-mpc-ceremony-release.sh`, including checksums, SBOMs, source
  and toolchain metadata, and the package manifest.

Publishing `checksums.sha256` separately is recommended for convenience. The
authenticated release announcement must independently state the repository,
tag, source commit, binary SHA-256, package SHA-256, release mode, and—only for
production—the approved tag-signer and build-signing public-key fingerprints.
A checksum hosted beside a binary detects transfer corruption but is not an
independent trust channel.

## Required release gates

Before selecting a release commit:

1. Merge all approved security fixes.
2. Require the `MPC ceremony release validation` workflow to pass. It rebuilds
   the patched vendor tree, creates two unsigned rehearsal packages, verifies
   that they are byte-identical, confirms that no production signatures exist,
   and exercises the CLI against the exact Relay commit pinned in the workflow.
3. Review any change to `RELAY_COMMIT`; a moving branch or tag is not an
   acceptable compatibility input.
4. Confirm `go.mod` still declares `module proof-tool`.

The workflow can also be rerun from the Actions tab with **Run workflow**. CI
rehearsals are unsigned and are never production releases.

## Publish a test release

A test release proves the download path without using either production signing
key. Its tag and GitHub release must say `rehearsal`, and the release must be a
prerelease.

Start from a clean ordinary clone, not a linked worktree, so Go can embed the
exact VCS revision:

    TEST_TAG=mpc-ceremony-rehearsal-v0.0.0-YYYYMMDD.N
    git fetch origin --tags
    git checkout --detach origin/main
    test -z "$(git status --porcelain)"
    test "$(sed -n 's/^module //p' go.mod)" = proof-tool
    bash scripts/bootstrap-vendor.sh
    mkdir -p /tmp/mpc-release-a-parent /tmp/mpc-release-b-parent
    scripts/build-mpc-ceremony-release.sh \
      --mode rehearsal \
      --out-dir /tmp/mpc-release-a-parent/release
    scripts/build-mpc-ceremony-release.sh \
      --mode rehearsal \
      --out-dir /tmp/mpc-release-b-parent/release
    RELEASE_COMMIT=$(git rev-parse HEAD)
    scripts/verify-mpc-ceremony-reproducible.sh \
      --mode rehearsal \
      --expected-commit "$RELEASE_COMMIT" \
      --expected-tag none \
      --tag-signer-fingerprint none \
      --trusted-build-public-key-file none \
      /tmp/mpc-release-a-parent/release \
      /tmp/mpc-release-b-parent/release
    test ! -e /tmp/mpc-release-a-parent/release/build-package-manifest.sig
    test ! -e /tmp/mpc-release-a-parent/release/build-package-manifest-public-key.hex

Create a deterministic full-package archive and its separate checksums:

    RELEASE_DIR=/tmp/mpc-release-a-parent/release
    RELEASE_EPOCH=$(<"$RELEASE_DIR/source-date-epoch.txt")
    PACKAGE=/tmp/mpc-ceremony-$TEST_TAG-linux-amd64.tar
    tar --sort=name --format=gnu --owner=0 --group=0 --numeric-owner \
      --mtime="@$RELEASE_EPOCH" \
      -C "$(dirname "$RELEASE_DIR")" \
      -cf "$PACKAGE" "$(basename "$RELEASE_DIR")"
    cp "$RELEASE_DIR/checksums.sha256" /tmp/checksums.sha256
    (cd /tmp && sha256sum "$(basename "$PACKAGE")" > package.sha256)

Tag the exact tested commit, push the tag, and create an explicitly unsigned
prerelease:

    git tag -a "$TEST_TAG" "$RELEASE_COMMIT" \
      -m "Unsigned mpc-ceremony rehearsal $TEST_TAG"
    git push origin "refs/tags/$TEST_TAG"
    gh release create "$TEST_TAG" \
      --repo zksecurity/proof-tool \
      --verify-tag \
      --prerelease \
      --title "UNSIGNED rehearsal: $TEST_TAG" \
      --notes "Unsigned test release for installation and compatibility testing. NOT FOR PRODUCTION CEREMONIES." \
      "$RELEASE_DIR/mpc-ceremony#mpc-ceremony (Linux amd64, unsigned rehearsal)" \
      "$PACKAGE#Complete unsigned verification package" \
      "/tmp/checksums.sha256#Binary checksums from the package" \
      "/tmp/package.sha256#Verification-package checksum"

Download the assets into a fresh directory and compare them with the retained
local outputs before announcing the test:

    DOWNLOAD_DIR=$(mktemp -d /tmp/mpc-release-download.XXXXXXXX)
    gh release download "$TEST_TAG" \
      --repo zksecurity/proof-tool \
      --dir "$DOWNLOAD_DIR"
    sha256sum "$DOWNLOAD_DIR"/*
    cmp "$DOWNLOAD_DIR/mpc-ceremony" "$RELEASE_DIR/mpc-ceremony"

## Publish a production release

Production is different in three ways: the source tag is signed by the approved
tag signer, the package manifest is signed by the offline release build key,
and an independent auditor reproduces and verifies the package before anything
is published. Never place the build-signing private key in GitHub Actions.

On the offline Linux/amd64 release machine with Go 1.26.5, check out the approved
signed tag, bootstrap the vendor tree, and create two production builds:

    RELEASE_TAG=REPLACE_WITH_APPROVED_SIGNED_TAG
    TAG_SIGNER_FINGERPRINT=REPLACE_WITH_APPROVED_FINGERPRINT
    BUILD_SIGNING_KEY=/offline/mpc-build-signing-key
    git fetch origin --tags
    git checkout --detach "$RELEASE_TAG"
    RELEASE_COMMIT=$(git rev-parse "$RELEASE_TAG^{commit}")
    test "$(git rev-parse HEAD)" = "$RELEASE_COMMIT"
    test -z "$(git status --porcelain)"
    bash scripts/bootstrap-vendor.sh
    mkdir -p /retained/mpc-release-a-parent /retained/mpc-release-b-parent
    scripts/build-mpc-ceremony-release.sh \
      --mode production \
      --signed-tag "$RELEASE_TAG" \
      --tag-signer-fingerprint "$TAG_SIGNER_FINGERPRINT" \
      --build-signing-key "$BUILD_SIGNING_KEY" \
      --out-dir /retained/mpc-release-a-parent/release
    scripts/build-mpc-ceremony-release.sh \
      --mode production \
      --signed-tag "$RELEASE_TAG" \
      --tag-signer-fingerprint "$TAG_SIGNER_FINGERPRINT" \
      --build-signing-key "$BUILD_SIGNING_KEY" \
      --out-dir /retained/mpc-release-b-parent/release

The independent auditor obtains the build public key through the independent
trust channel and runs:

    TRUSTED_BUILD_PUBLIC_KEY=/trusted/mpc-build-public-key.hex
    scripts/verify-mpc-ceremony-reproducible.sh \
      --mode production \
      --expected-commit "$RELEASE_COMMIT" \
      --expected-tag "$RELEASE_TAG" \
      --tag-signer-fingerprint "$TAG_SIGNER_FINGERPRINT" \
      --trusted-build-public-key-file "$TRUSTED_BUILD_PUBLIC_KEY" \
      /retained/mpc-release-a-parent/release \
      /retained/mpc-release-b-parent/release

Package the verified `release` directory with the deterministic `tar` command
from the test procedure, replacing `TEST_TAG` with `RELEASE_TAG`. Upload the
direct binary, full package, and separate checksums with `gh release create`,
but omit `--prerelease` and all rehearsal wording. Publish the authenticated
release announcement only after an independent download-and-verify pass.

Never reuse a test tag or replace assets on an existing release. If anything is
wrong, leave an audit trail, mark the release unusable, and publish a new tag.
