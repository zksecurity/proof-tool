package main

import (
	"bytes"
	"strings"
	"testing"

	gnarklogger "github.com/consensys/gnark/logger"
	"github.com/rs/zerolog"
)

func TestConfigureLibraryLoggingKeepsDiagnosticsOffStdout(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	gnarklogger.Set(zerolog.New(&stdout))
	t.Cleanup(gnarklogger.Disable)

	configureLibraryLogging(&stderr)
	diagnosticLogger := gnarklogger.Logger()
	diagnosticLogger.Debug().Msg("gnark diagnostic")

	if stdout.Len() != 0 {
		t.Fatalf("gnark wrote %q to stdout", stdout.String())
	}
	if !strings.Contains(stderr.String(), "gnark diagnostic") {
		t.Fatalf("gnark diagnostic missing from stderr: %q", stderr.String())
	}
}
