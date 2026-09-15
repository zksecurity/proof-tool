package mpcceremony

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/blake2b"

	"proof-tool/internal/prover"
)

const (
	gnarkModulePath       = "github.com/consensys/gnark"
	gnarkCryptoModulePath = "github.com/consensys/gnark-crypto"
	drandModulePath       = "github.com/drand/drand/v2"
	gitRevisionHexLength  = 40
)

type runningSoftwareSource struct {
	executable     func() (string, error)
	readBuildInfo  func() (*debug.BuildInfo, bool)
	runtimeVersion func() string
}

func productionSoftwareSource() runningSoftwareSource {
	return runningSoftwareSource{
		executable:     productionExecutablePath,
		readBuildInfo:  debug.ReadBuildInfo,
		runtimeVersion: runtime.Version,
	}
}

func productionExecutablePath() (string, error) {
	if runtime.GOOS != ProductionGOOS {
		return "", fmt.Errorf(
			"production executable identity requires %s /proc/self/exe, running on %s",
			ProductionGOOS,
			runtime.GOOS,
		)
	}
	return "/proc/self/exe", nil
}

// RunningSoftwareBinding derives the software identity from the process that
// is actually running. It intentionally ignores ceremony JSON: production
// initialization must put this value into the signed definition rather than
// accepting operator-supplied software metadata.
//
// Production binaries must be built from a clean Git checkout with VCS build
// information enabled. The exact executable bytes and linked gnark module
// versions are included in the returned binding.
func RunningSoftwareBinding(proofToolVersion string) (SoftwareBinding, error) {
	return RunningSoftwareBindingForMode(proofToolVersion, ModeProduction)
}

// RunningSoftwareBindingForMode derives the running process identity under
// the selected ceremony policy. Production requires vcs.modified=false.
// Rehearsal permits either clean or dirty builds and records the exact flag.
func RunningSoftwareBindingForMode(proofToolVersion, mode string) (SoftwareBinding, error) {
	return runningSoftwareBinding(proofToolVersion, mode, productionSoftwareSource())
}

// SoftwareBindingWithAllowedBinaryFiles authenticates additional
// mpc-ceremony executables and returns one canonical, platform-keyed policy.
// Every binary must have identical source and dependency metadata; exactly one
// binary is permitted for each platform and architecture variant.
func SoftwareBindingWithAllowedBinaryFiles(
	primary SoftwareBinding,
	proofToolVersion string,
	mode string,
	paths []string,
) (SoftwareBinding, error) {
	bindings := make([]SoftwareBinding, 0, len(paths))
	for index, path := range paths {
		binding, err := SoftwareBindingFromExecutableFileForMode(path, proofToolVersion, mode)
		if err != nil {
			return SoftwareBinding{}, fmt.Errorf("authenticate allowed binary %d %q: %w", index, path, err)
		}
		if err := requireCommonSoftwareIdentity(primary, binding); err != nil {
			return SoftwareBinding{}, fmt.Errorf("allowed binary %d %q: %w", index, path, err)
		}
		bindings = append(bindings, binding)
	}
	return softwareBindingWithAllowedBindings(primary, bindings)
}

// SoftwareBindingFromExecutableFileForMode authenticates one mpc-ceremony
// executable without running it. Callers must supply the expected release
// version and ceremony mode; both remain part of the validated binding.
func SoftwareBindingFromExecutableFileForMode(path, proofToolVersion, mode string) (SoftwareBinding, error) {
	file, err := os.Open(path)
	if err != nil {
		return SoftwareBinding{}, fmt.Errorf("open executable %q: %w", path, err)
	}
	info, err := buildinfo.Read(file)
	if err != nil {
		file.Close()
		return SoftwareBinding{}, fmt.Errorf("read executable %q build info: %w", path, err)
	}
	if info.Path != "proof-tool/cmd/mpc-ceremony" {
		file.Close()
		return SoftwareBinding{}, fmt.Errorf("executable %q main package %q, want %q", path, info.Path, "proof-tool/cmd/mpc-ceremony")
	}
	fdPath, err := openFileDescriptorPath(file)
	if err != nil {
		file.Close()
		return SoftwareBinding{}, err
	}
	source := runningSoftwareSource{
		executable:     func() (string, error) { return fdPath, nil },
		readBuildInfo:  func() (*debug.BuildInfo, bool) { return info, true },
		runtimeVersion: func() string { return info.GoVersion },
	}
	binding, bindingErr := runningSoftwareBinding(proofToolVersion, mode, source)
	closeErr := file.Close()
	if bindingErr != nil {
		return SoftwareBinding{}, bindingErr
	}
	if closeErr != nil {
		return SoftwareBinding{}, fmt.Errorf("close executable %q: %w", path, closeErr)
	}
	return binding, nil
}

func softwareBindingWithAllowedBindings(
	primary SoftwareBinding,
	additional []SoftwareBinding,
) (SoftwareBinding, error) {
	if err := primary.Validate(); err != nil {
		return SoftwareBinding{}, fmt.Errorf("primary software binding: %w", err)
	}
	for index, binding := range additional {
		if err := binding.Validate(); err != nil {
			return SoftwareBinding{}, fmt.Errorf("allowed software binding %d: %w", index, err)
		}
		if err := requireCommonSoftwareIdentity(primary, binding); err != nil {
			return SoftwareBinding{}, fmt.Errorf("allowed software binding %d: %w", index, err)
		}
	}
	binaries := primary.AllowedBinaries()
	for _, binding := range additional {
		binaries = append(binaries, binding.primaryBinary())
	}
	sort.Slice(binaries, func(i, j int) bool {
		return binaries[i].platformKey() < binaries[j].platformKey()
	})
	for index := 1; index < len(binaries); index++ {
		if binaries[index-1].platformKey() == binaries[index].platformKey() {
			return SoftwareBinding{}, fmt.Errorf(
				"multiple allowed binaries target platform %s",
				binaries[index].platformKey(),
			)
		}
	}
	result := primary
	result.GoOS = binaries[0].GoOS
	result.GoArch = binaries[0].GoArch
	result.GoAMD64 = binaries[0].GoAMD64
	result.GoARM64 = binaries[0].GoARM64
	result.ToolBinary = binaries[0].ToolBinary
	result.Binaries = binaries
	if err := result.Validate(); err != nil {
		return SoftwareBinding{}, fmt.Errorf("allowed software policy: %w", err)
	}
	return result, nil
}

func openFileDescriptorPath(file *os.File) (string, error) {
	switch runtime.GOOS {
	case "linux":
		return "/proc/self/fd/" + strconv.FormatUint(uint64(file.Fd()), 10), nil
	case "darwin":
		return "/dev/fd/" + strconv.FormatUint(uint64(file.Fd()), 10), nil
	default:
		return "", fmt.Errorf("secure allowed-binary inspection is unsupported on %s", runtime.GOOS)
	}
}

func requireCommonSoftwareIdentity(expected, actual SoftwareBinding) error {
	switch {
	case expected.ProofToolVersion != actual.ProofToolVersion:
		return softwareMismatch("proof_tool_version", expected.ProofToolVersion, actual.ProofToolVersion)
	case expected.GnarkVersion != actual.GnarkVersion:
		return softwareMismatch("gnark_version", expected.GnarkVersion, actual.GnarkVersion)
	case expected.GnarkCryptoVersion != actual.GnarkCryptoVersion:
		return softwareMismatch("gnark_crypto_version", expected.GnarkCryptoVersion, actual.GnarkCryptoVersion)
	case expected.DrandVersion != actual.DrandVersion:
		return softwareMismatch("drand_version", expected.DrandVersion, actual.DrandVersion)
	case expected.GoVersion != actual.GoVersion:
		return softwareMismatch("go_version", expected.GoVersion, actual.GoVersion)
	case expected.Compiler != actual.Compiler:
		return softwareMismatch("compiler", expected.Compiler, actual.Compiler)
	case expected.BuildMode != actual.BuildMode:
		return softwareMismatch("build_mode", expected.BuildMode, actual.BuildMode)
	case expected.CGOEnabled != actual.CGOEnabled:
		return softwareMismatch("cgo_enabled", expected.CGOEnabled, actual.CGOEnabled)
	case expected.TrimPath != actual.TrimPath:
		return softwareMismatch("trimpath", expected.TrimPath, actual.TrimPath)
	case expected.SourceCommit != actual.SourceCommit:
		return softwareMismatch("source_commit", expected.SourceCommit, actual.SourceCommit)
	case expected.SourceDirty != actual.SourceDirty:
		return softwareMismatch("source_dirty", expected.SourceDirty, actual.SourceDirty)
	default:
		return nil
	}
}

// VerifyRunningSoftware fails unless every field in expected describes the
// exact clean binary that is currently running.
func VerifyRunningSoftware(expected SoftwareBinding) error {
	return VerifyRunningSoftwareForMode(expected, ModeProduction)
}

// VerifyRunningSoftwareForMode verifies the current process under the selected
// ceremony policy, including an exact match of the VCS modified flag.
func VerifyRunningSoftwareForMode(expected SoftwareBinding, mode string) error {
	return verifyRunningSoftware(expected, mode, productionSoftwareSource())
}

func runningSoftwareBinding(
	proofToolVersion string,
	mode string,
	source runningSoftwareSource,
) (SoftwareBinding, error) {
	if err := validateSoftwareMode(mode); err != nil {
		return SoftwareBinding{}, err
	}
	if proofToolVersion != prover.ProofToolVersion {
		return SoftwareBinding{}, fmt.Errorf(
			"proof tool version %q, want compiled version %q",
			proofToolVersion,
			prover.ProofToolVersion,
		)
	}
	if source.executable == nil || source.readBuildInfo == nil || source.runtimeVersion == nil {
		return SoftwareBinding{}, errors.New("running software source is incomplete")
	}

	executablePath, err := source.executable()
	if err != nil {
		return SoftwareBinding{}, fmt.Errorf("resolve running executable: %w", err)
	}
	toolBinary, err := digestRunningExecutable(executablePath)
	if err != nil {
		return SoftwareBinding{}, fmt.Errorf("digest running executable: %w", err)
	}

	buildInfo, ok := source.readBuildInfo()
	if !ok || buildInfo == nil {
		return SoftwareBinding{}, errors.New("running executable has no Go build information")
	}
	goVersion := source.runtimeVersion()
	if strings.TrimSpace(goVersion) == "" {
		return SoftwareBinding{}, errors.New("running Go version is empty")
	}
	if buildInfo.GoVersion != goVersion {
		return SoftwareBinding{}, fmt.Errorf(
			"linked Go version %q does not match runtime version %q",
			buildInfo.GoVersion,
			goVersion,
		)
	}
	goOS, err := uniqueBuildSetting(buildInfo, "GOOS")
	if err != nil {
		return SoftwareBinding{}, err
	}
	goArch, err := uniqueBuildSetting(buildInfo, "GOARCH")
	if err != nil {
		return SoftwareBinding{}, err
	}
	goAMD64 := ""
	if goArch == "amd64" {
		goAMD64, err = uniqueBuildSetting(buildInfo, "GOAMD64")
		if err != nil {
			return SoftwareBinding{}, err
		}
	}
	goARM64 := ""
	if goArch == "arm64" {
		goARM64, err = uniqueBuildSetting(buildInfo, "GOARM64")
		if err != nil {
			return SoftwareBinding{}, err
		}
	}
	compiler, err := uniqueBuildSetting(buildInfo, "-compiler")
	if err != nil {
		return SoftwareBinding{}, err
	}
	buildMode, err := uniqueBuildSetting(buildInfo, "-buildmode")
	if err != nil {
		return SoftwareBinding{}, err
	}
	cgoEnabled, err := booleanBuildSetting(buildInfo, "CGO_ENABLED", false)
	if err != nil {
		return SoftwareBinding{}, err
	}
	trimPath, err := booleanBuildSetting(buildInfo, "-trimpath", false)
	if err != nil {
		return SoftwareBinding{}, err
	}
	if mode == ModeProduction {
		if err := validateProductionBuildProfile(
			goVersion,
			goOS,
			goArch,
			goAMD64,
			goARM64,
			compiler,
			buildMode,
			cgoEnabled,
			trimPath,
		); err != nil {
			return SoftwareBinding{}, err
		}
	}

	vcs, err := uniqueBuildSetting(buildInfo, "vcs")
	if err != nil {
		return SoftwareBinding{}, err
	}
	if vcs != "git" {
		return SoftwareBinding{}, fmt.Errorf("linked VCS is %q, want %q", vcs, "git")
	}
	sourceCommit, err := uniqueBuildSetting(buildInfo, "vcs.revision")
	if err != nil {
		return SoftwareBinding{}, err
	}
	if err := validateCleanGitRevision(sourceCommit); err != nil {
		return SoftwareBinding{}, fmt.Errorf("vcs.revision: %w", err)
	}
	sourceModified, err := uniqueBuildSetting(buildInfo, "vcs.modified")
	if err != nil {
		return SoftwareBinding{}, err
	}
	var sourceDirty bool
	switch sourceModified {
	case "false":
	case "true":
		sourceDirty = true
	default:
		return SoftwareBinding{}, fmt.Errorf(
			"vcs.modified is %q, want %q or %q",
			sourceModified,
			"false",
			"true",
		)
	}
	if mode == ModeProduction && sourceDirty {
		return SoftwareBinding{}, fmt.Errorf(
			"vcs.modified is %q; production ceremony binaries must be built from a clean checkout",
			sourceModified,
		)
	}

	gnarkVersion, err := linkedModuleVersion(buildInfo, gnarkModulePath)
	if err != nil {
		return SoftwareBinding{}, err
	}
	if gnarkVersion != GnarkVersion {
		return SoftwareBinding{}, fmt.Errorf(
			"linked %s version %q, want %q",
			gnarkModulePath,
			gnarkVersion,
			GnarkVersion,
		)
	}
	gnarkCryptoVersion, err := linkedModuleVersion(buildInfo, gnarkCryptoModulePath)
	if err != nil {
		return SoftwareBinding{}, err
	}
	if gnarkCryptoVersion != GnarkCryptoVersion {
		return SoftwareBinding{}, fmt.Errorf(
			"linked %s version %q, want %q",
			gnarkCryptoModulePath,
			gnarkCryptoVersion,
			GnarkCryptoVersion,
		)
	}
	drandVersion, err := linkedModuleVersion(buildInfo, drandModulePath)
	if err != nil {
		return SoftwareBinding{}, err
	}
	if drandVersion != DrandVersion {
		return SoftwareBinding{}, fmt.Errorf(
			"linked %s version %q, want %q",
			drandModulePath,
			drandVersion,
			DrandVersion,
		)
	}

	binding := SoftwareBinding{
		ProofToolVersion:   proofToolVersion,
		GnarkVersion:       gnarkVersion,
		GnarkCryptoVersion: gnarkCryptoVersion,
		DrandVersion:       drandVersion,
		GoVersion:          goVersion,
		GoOS:               goOS,
		GoArch:             goArch,
		GoAMD64:            goAMD64,
		GoARM64:            goARM64,
		Compiler:           compiler,
		BuildMode:          buildMode,
		CGOEnabled:         cgoEnabled,
		TrimPath:           trimPath,
		SourceCommit:       sourceCommit,
		SourceDirty:        sourceDirty,
		ToolBinary:         toolBinary,
	}
	binding.Binaries = []SoftwareBinary{binding.primaryBinary()}
	if err := binding.Validate(); err != nil {
		return SoftwareBinding{}, fmt.Errorf("derived software binding: %w", err)
	}
	return binding, nil
}

func verifyRunningSoftware(
	expected SoftwareBinding,
	mode string,
	source runningSoftwareSource,
) error {
	if err := validateSoftwareMode(mode); err != nil {
		return err
	}
	if err := expected.Validate(); err != nil {
		return fmt.Errorf("expected software binding: %w", err)
	}
	if mode == ModeProduction && expected.SourceDirty {
		return errors.New("expected software binding records a dirty source checkout")
	}
	if err := validateCleanGitRevision(expected.SourceCommit); err != nil {
		return fmt.Errorf("expected source_commit: %w", err)
	}

	actual, err := runningSoftwareBinding(expected.ProofToolVersion, mode, source)
	if err != nil {
		return fmt.Errorf("derive running software binding: %w", err)
	}
	if err := requireCommonSoftwareIdentity(expected, actual); err != nil {
		return err
	}
	actualBinary := actual.primaryBinary()
	for _, allowed := range expected.AllowedBinaries() {
		if allowed == actualBinary {
			return nil
		}
	}
	return fmt.Errorf(
		"running software binary %s (%s) is not in the signed allowlist",
		actualBinary.platformKey(), actualBinary.ToolBinary.SHA256,
	)
}

func digestRunningExecutable(path string) (Digest, error) {
	file, err := os.Open(path)
	if err != nil {
		return Digest{}, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return Digest{}, err
	}
	if !info.Mode().IsRegular() {
		return Digest{}, fmt.Errorf("%q is not a regular file", path)
	}
	if info.Size() <= 0 {
		return Digest{}, fmt.Errorf("%q is empty", path)
	}

	shaHash := sha256.New()
	blakeHash, err := blake2b.New256(nil)
	if err != nil {
		return Digest{}, fmt.Errorf("create BLAKE2b-256 hasher: %w", err)
	}
	size, err := io.Copy(io.MultiWriter(shaHash, blakeHash), file)
	if err != nil {
		return Digest{}, err
	}
	if size != info.Size() {
		return Digest{}, fmt.Errorf(
			"%q changed size while hashing: read %d bytes, stat reported %d",
			path,
			size,
			info.Size(),
		)
	}

	result := Digest{
		SHA256:     "sha256:" + hex.EncodeToString(shaHash.Sum(nil)),
		Blake2b256: "blake2b256:" + hex.EncodeToString(blakeHash.Sum(nil)),
		Size:       size,
	}
	if err := result.Validate(); err != nil {
		return Digest{}, err
	}
	return result, nil
}

func uniqueBuildSetting(info *debug.BuildInfo, key string) (string, error) {
	var value string
	found := false
	for _, setting := range info.Settings {
		if setting.Key != key {
			continue
		}
		if found {
			return "", fmt.Errorf("running executable has duplicate %s build settings", key)
		}
		value = setting.Value
		found = true
	}
	if !found {
		return "", fmt.Errorf("running executable is missing %s build setting", key)
	}
	return value, nil
}

func optionalBuildSetting(info *debug.BuildInfo, key string) (string, bool, error) {
	var value string
	found := false
	for _, setting := range info.Settings {
		if setting.Key != key {
			continue
		}
		if found {
			return "", false, fmt.Errorf("running executable has duplicate %s build settings", key)
		}
		value = setting.Value
		found = true
	}
	return value, found, nil
}

func booleanBuildSetting(info *debug.BuildInfo, key string, absentValue bool) (bool, error) {
	value, found, err := optionalBuildSetting(info, key)
	if err != nil {
		return false, err
	}
	if !found {
		return absentValue, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("running executable has invalid %s build setting %q", key, value)
	}
	return parsed, nil
}

func validateProductionBuildProfile(
	goVersion string,
	goOS string,
	goArch string,
	goAMD64 string,
	goARM64 string,
	compiler string,
	buildMode string,
	cgoEnabled bool,
	trimPath bool,
) error {
	switch {
	case goVersion != ProductionGoVersion:
		return softwareMismatch("go_version", ProductionGoVersion, goVersion)
	case goOS != ProductionGOOS:
		return softwareMismatch("goos", ProductionGOOS, goOS)
	case goArch != "amd64" && goArch != "arm64":
		return fmt.Errorf("running software goarch %q, want %q or %q", goArch, "amd64", "arm64")
	case goArch == "amd64" && goAMD64 != ProductionGOAMD64:
		return softwareMismatch("goamd64", ProductionGOAMD64, goAMD64)
	case goArch == "amd64" && goARM64 != "":
		return softwareMismatch("goarm64", "", goARM64)
	case goArch == "arm64" && goARM64 != ProductionGOARM64:
		return softwareMismatch("goarm64", ProductionGOARM64, goARM64)
	case goArch == "arm64" && goAMD64 != "":
		return softwareMismatch("goamd64", "", goAMD64)
	case compiler != ProductionCompiler:
		return softwareMismatch("compiler", ProductionCompiler, compiler)
	case buildMode != ProductionBuildMode:
		return softwareMismatch("build_mode", ProductionBuildMode, buildMode)
	case cgoEnabled:
		return errors.New("running software cgo_enabled mismatch: production requires false")
	case !trimPath:
		return errors.New("running software trimpath mismatch: production requires true")
	default:
		return nil
	}
}

func linkedModuleVersion(info *debug.BuildInfo, modulePath string) (string, error) {
	var matched *debug.Module
	for _, module := range info.Deps {
		if module == nil || module.Path != modulePath {
			continue
		}
		if matched != nil {
			return "", fmt.Errorf("running executable contains duplicate %s modules", modulePath)
		}
		matched = module
	}
	if matched == nil {
		return "", fmt.Errorf("running executable is missing linked module %s", modulePath)
	}
	if matched.Replace != nil {
		return "", fmt.Errorf(
			"running executable uses a replacement for %s; production requires the exact published module",
			modulePath,
		)
	}
	if strings.TrimSpace(matched.Version) == "" {
		return "", fmt.Errorf("running executable has no version for linked module %s", modulePath)
	}
	return matched.Version, nil
}

func validateCleanGitRevision(revision string) error {
	if len(revision) != gitRevisionHexLength {
		return fmt.Errorf("must be exactly 40 lowercase hexadecimal characters, got %d", len(revision))
	}
	if revision != strings.ToLower(revision) {
		return errors.New("must use lowercase hexadecimal")
	}
	if _, err := hex.DecodeString(revision); err != nil {
		return errors.New("must be exactly 40 lowercase hexadecimal characters")
	}
	if strings.Trim(revision, "0") == "" {
		return errors.New("must identify a real Git commit, not the all-zero object ID")
	}
	return nil
}

func softwareMismatch(field string, expected, actual any) error {
	return fmt.Errorf("running software %s mismatch: expected %v, got %v", field, expected, actual)
}

func validateSoftwareMode(mode string) error {
	switch mode {
	case ModeProduction, ModeRehearsal:
		return nil
	default:
		return fmt.Errorf("software binding mode %q, want %q or %q", mode, ModeProduction, ModeRehearsal)
	}
}
