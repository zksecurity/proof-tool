// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/consensys/gnark/logger"
)

func main() {
	// gnark defaults its global logger to stdout. Keep stdout exclusively for
	// the CLI result contract, especially the single JSON object promised by
	// --format json.
	logger.SetOutput(os.Stderr)
	os.Exit(runCLI(context.Background(), os.Args[1:], os.Stdout, os.Stderr, workflowExecutor{}))
}

func runCLI(ctx context.Context, args []string, stdout, stderr io.Writer, executor Executor) int {
	invocation, err := parseInvocation(args)
	if err != nil {
		var help *helpRequest
		if errors.As(err, &help) {
			if err := writeUsage(stdout, help.topic); err != nil {
				writeDiagnostic(stderr, args, "error: write help: %v\n", err)
				return 6
			}
			return 0
		}
		var usage *usageError
		if errors.As(err, &usage) {
			message := redactCLIError(usage.message, args)
			if requestsJSON(args) {
				return writeParseError(message, args, stdout, stderr)
			}
			writeDiagnostic(stderr, args, "error: %s\n\n", message)
			if err := writeUsage(stderr, usage.topic); err != nil {
				return 6
			}
			return 2
		}
		writeDiagnostic(stderr, args, "error: %s\n", err.Error())
		return 6
	}

	if executor == nil {
		executor = unwiredExecutor{}
	}
	result, err := executor.Execute(ctx, invocation)
	if err != nil {
		return writeExecutionError(invocation, err, args, stdout, stderr)
	}
	result.Schema = commandResultSchema
	result.OK = true
	result.Command = invocation.Command
	if invocation.Global.Format == "json" {
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			writeDiagnostic(stderr, args, "error: encode command result: %v\n", err)
			return 6
		}
		return 0
	}
	if result.Summary != "" {
		if _, err := fmt.Fprintln(stdout, result.Summary); err != nil {
			writeDiagnostic(stderr, args, "error: write command result: %v\n", err)
			return 6
		}
	} else {
		if _, err := fmt.Fprintf(stdout, "%s completed\n", invocation.Command); err != nil {
			writeDiagnostic(stderr, args, "error: write command result: %v\n", err)
			return 6
		}
	}
	names := make([]string, 0, len(result.Outputs))
	for name := range result.Outputs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := result.Outputs[name]
		if _, err := fmt.Fprintf(stdout, "%s: %s\n", name, path); err != nil {
			writeDiagnostic(stderr, args, "error: write command result: %v\n", err)
			return 6
		}
	}
	return 0
}

func writeExecutionError(invocation Invocation, err error, args []string, stdout, stderr io.Writer) int {
	exitCode := 6
	code := "internal_error"
	if errors.Is(err, errExecutorNotWired) {
		code = "engine_not_wired"
	}
	message := redactCLIError(err.Error(), args)
	if invocation.Global.Format == "json" {
		payload := struct {
			Schema  string  `json:"schema"`
			OK      bool    `json:"ok"`
			Command Command `json:"command"`
			Error   struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}{
			Schema:  commandResultSchema,
			OK:      false,
			Command: invocation.Command,
		}
		payload.Error.Code = code
		payload.Error.Message = message
		if encodeErr := json.NewEncoder(stdout).Encode(payload); encodeErr != nil {
			writeDiagnostic(stderr, args, "error: encode command error: %v\n", encodeErr)
		}
		return exitCode
	}
	writeDiagnostic(stderr, args, "error: %s\n", message)
	return exitCode
}

const redactedCLIValue = "<redacted>"

// redactCLIError keeps command-line values out of diagnostics. In particular,
// unexpected positionals can be seed phrases, while participant identifiers
// and private-key paths can expose operator-specific ceremony details. Error
// messages remain useful, but values supplied by the caller are never echoed.
func redactCLIError(message string, args []string) string {
	safeCommandArguments := identifyCLICommandArguments(args)
	candidates := make(map[string]struct{})
	for index, arg := range args {
		if _, safe := safeCommandArguments[index]; safe {
			continue
		}
		if name, value, found := strings.Cut(arg, "="); found && strings.HasPrefix(name, "-") {
			addCLIErrorCandidate(candidates, value)
			addCLIErrorCandidate(candidates, name)
			addCLIErrorCandidate(candidates, "-"+strings.TrimLeft(name, "-"))
			continue
		}
		addCLIErrorCandidate(candidates, arg)
		if strings.HasPrefix(arg, "-") {
			addCLIErrorCandidate(candidates, "-"+strings.TrimLeft(arg, "-"))
		}
	}

	ordered := make([]string, 0, len(candidates))
	for candidate := range candidates {
		ordered = append(ordered, candidate)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return len(ordered[i]) > len(ordered[j])
	})
	for _, candidate := range ordered {
		message = redactCandidate(message, candidate)
	}
	return message
}

// shortCandidateLength is the length below which redaction switches from
// substring replacement to whole-token replacement. Long values are replaced
// wherever they appear: incidental collisions are vanishingly rare and a
// secret embedded in a longer string must still be caught. Short values are
// replaced only as complete tokens: a one-to-three character argument such as
// a participant count would otherwise blank matching digits and letters inside
// unrelated words, degrading the diagnostic exactly when it is needed. A short
// value that IS echoed verbatim — validateID permits one-character key ids —
// still appears as its own token and is still redacted, which is the leak that
// forced the revert of the plain length-floor approach.
const shortCandidateLength = 4

func redactCandidate(message, candidate string) string {
	if len(candidate) >= shortCandidateLength {
		return strings.ReplaceAll(message, candidate, redactedCLIValue)
	}
	var builder strings.Builder
	remaining := message
	for {
		index := strings.Index(remaining, candidate)
		if index < 0 {
			builder.WriteString(remaining)
			return builder.String()
		}
		before := remaining[:index]
		after := remaining[index+len(candidate):]
		if isTokenBoundary(before, true) && isTokenBoundary(after, false) {
			builder.WriteString(before)
			builder.WriteString(redactedCLIValue)
			remaining = after
			continue
		}
		builder.WriteString(remaining[:index+len(candidate)])
		remaining = after
	}
}

// isTokenBoundary reports whether the text adjacent to a candidate ends (or
// starts) a token: empty, or a byte that cannot continue an identifier or
// number. Letters and digits continue a token; everything else separates.
func isTokenBoundary(adjacent string, atEnd bool) bool {
	if adjacent == "" {
		return true
	}
	var b byte
	if atEnd {
		b = adjacent[len(adjacent)-1]
	} else {
		b = adjacent[0]
	}
	isAlphanumeric := b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
	return !isAlphanumeric
}

func identifyCLICommandArguments(args []string) map[int]struct{} {
	safe := make(map[int]struct{})
	index := 0
	for index < len(args) {
		switch {
		case args[index] == "--format":
			index += 2
		case strings.HasPrefix(args[index], "--format="):
			index++
		case args[index] == "--quiet" || args[index] == "--help":
			index++
		case strings.HasPrefix(args[index], "-"):
			index++
		default:
			goto command
		}
	}
	return safe

command:
	topLevel := map[string]struct{}{
		"audit": {}, "decision": {}, "finalize": {}, "help": {}, "init": {},
		"ops": {}, "phase1": {}, "phase2": {}, "release": {},
	}
	if _, ok := topLevel[args[index]]; !ok {
		return safe
	}
	safe[index] = struct{}{}

	subcommands := map[string]map[string]struct{}{
		"phase1": {
			"attest-erasure": {}, "beacon": {}, "close": {},
			"contribute": {}, "help": {}, "seal": {}, "verify": {},
		},
		"phase2": {
			"attest-erasure": {}, "beacon": {}, "close": {},
			"contribute": {}, "help": {}, "init": {}, "verify": {},
		},
		"decision": {"help": {}, "prepare": {}, "sign": {}, "verify": {}},
		"ops":      {"export-signing": {}, "help": {}, "import-signature": {}, "verify": {}},
		"release":  {"help": {}, "sign": {}, "verify": {}},
	}
	allowed, hasSubcommands := subcommands[args[index]]
	if hasSubcommands && index+1 < len(args) {
		if _, ok := allowed[args[index+1]]; ok {
			safe[index+1] = struct{}{}
		}
	}
	return safe
}

func addCLIErrorCandidate(candidates map[string]struct{}, value string) {
	if value == "" || value == "-" || value == "--" {
		return
	}
	candidates[value] = struct{}{}
}

// writeDiagnostic is the only stderr outlet. It redacts the formatted message
// against argv by construction, so a new diagnostic call site cannot leak a
// command-line value by forgetting to call redactCLIError first. Call sites
// that already redacted are unaffected: redaction is idempotent.
func writeDiagnostic(w io.Writer, cliArgs []string, format string, args ...any) {
	_, _ = fmt.Fprint(w, redactCLIError(fmt.Sprintf(format, args...), cliArgs))
}

func requestsJSON(args []string) bool {
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--format" && i+1 < len(args):
			return args[i+1] == "json"
		case args[i] == "--format=json":
			return true
		case len(args[i]) == 0 || args[i][0] != '-':
			return false
		}
	}
	return false
}

func writeParseError(message string, args []string, stdout, stderr io.Writer) int {
	payload := struct {
		Schema string `json:"schema"`
		OK     bool   `json:"ok"`
		Error  struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{
		Schema: commandResultSchema,
		OK:     false,
	}
	payload.Error.Code = "usage_error"
	payload.Error.Message = message
	if err := json.NewEncoder(stdout).Encode(payload); err != nil {
		writeDiagnostic(stderr, args, "error: encode usage error: %v\n", err)
		return 6
	}
	return 2
}
